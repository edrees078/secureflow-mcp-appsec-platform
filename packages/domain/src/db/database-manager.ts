import pg from 'pg';
import { PrismaPg } from '@prisma/adapter-pg';
import { SecureFlowError } from '@secureflow/shared';
import { PrismaClient, type Prisma } from '../generated/prisma/client.js';
import { createRepositories, type RepositoryContainer } from './repositories/index.js';

const { Pool } = pg;

export interface DatabaseConfig {
  /**
   * PostgreSQL connection string.
   * Format: postgresql://[user[:password]@][host][:port][/database][?param=value]
   */
  connectionString: string;
  /**
   * Maximum number of connections in the pool. Defaults to 10.
   */
  maxConnections?: number;
  /**
   * Number of milliseconds a client must sit idle in the pool and not be checked out
   * before it is disconnected. Defaults to 30000 (30 seconds).
   */
  idleTimeoutMillis?: number;
  /**
   * Number of milliseconds to wait before timing out when connecting a new client.
   * Defaults to 5000 (5 seconds).
   */
  connectionTimeoutMillis?: number;
  /**
   * Maximum number of milliseconds any query statement may execute before timing out.
   * Defaults to 10000 (10 seconds).
   */
  statementTimeoutMillis?: number;
  /**
   * SSL connection configuration.
   */
  ssl?: boolean | pg.ConnectionConfig['ssl'];
  /**
   * Target PostgreSQL schema. Defaults to 'public'.
   */
  schema?: string;
}

export interface DatabaseIdentity {
  database: string;
  host: string;
  port: number;
  version: string;
  majorVersion: number;
  authenticatedUser: string;
}

/**
 * Utility to redact credentials from a connection string for safe diagnostic logging.
 */
export function redactDatabaseUrl(connectionUrl: string): string {
  try {
    const url = new URL(connectionUrl);
    if (url.password) {
      url.password = '****';
    }
    return url.toString();
  } catch {
    return 'postgresql://[REDACTED_INVALID_URL]';
  }
}

/**
 * DatabaseManager
 *
 * Manages the PostgreSQL connection pool (pg.Pool), Prisma 7 driver adapter (PrismaPg),
 * and PrismaClient instance lifecycle.
 *
 * Guarantees:
 * - Deterministic lifecycle management (no process-wide mutable singletons).
 * - Safe credential handling (passwords are redacted from all diagnostics).
 * - Idempotent graceful shutdown without double-closing the connection pool.
 * - Transaction execution with transaction-scoped repository container.
 */
export class DatabaseManager {
  private readonly config: DatabaseConfig;
  private readonly pool: pg.Pool;
  private readonly prisma: PrismaClient;
  private isClosed = false;
  private isShuttingDown = false;

  public readonly redactedUrl: string;
  public readonly targetDatabase: string;
  public readonly targetHost: string;
  public readonly targetPort: number;
  public readonly targetSchema: string;

  constructor(config: DatabaseConfig) {
    if (!config.connectionString || typeof config.connectionString !== 'string') {
      throw new SecureFlowError(
        'DatabaseManager initialization failed: connectionString is required',
        'DATABASE_CONFIG_ERROR',
        500,
      );
    }

    let parsedUrl: URL;
    try {
      parsedUrl = new URL(config.connectionString);
    } catch {
      throw new SecureFlowError(
        'DatabaseManager initialization failed: connectionString is not a valid URL',
        'DATABASE_CONFIG_ERROR',
        500,
      );
    }

    if (parsedUrl.protocol !== 'postgresql:' && parsedUrl.protocol !== 'postgres:') {
      throw new SecureFlowError(
        `DatabaseManager initialization failed: invalid protocol '${parsedUrl.protocol}'. Expected 'postgresql:' or 'postgres:'`,
        'DATABASE_CONFIG_ERROR',
        500,
      );
    }

    this.config = {
      maxConnections: 10,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 5000,
      statementTimeoutMillis: 10000,
      schema: 'public',
      ...config,
    };

    this.redactedUrl = redactDatabaseUrl(config.connectionString);
    this.targetDatabase = parsedUrl.pathname.replace(/^\//, '') || 'postgres';
    this.targetHost = parsedUrl.hostname || '127.0.0.1';
    this.targetPort = parsedUrl.port ? Number.parseInt(parsedUrl.port, 10) : 5432;
    this.targetSchema = this.config.schema ?? 'public';

    // 1. Initialize dedicated connection pool
    this.pool = new Pool({
      connectionString: this.config.connectionString,
      max: this.config.maxConnections,
      idleTimeoutMillis: this.config.idleTimeoutMillis,
      connectionTimeoutMillis: this.config.connectionTimeoutMillis,
      statement_timeout: this.config.statementTimeoutMillis,
      ssl: this.config.ssl,
    });

    // Suppress unhandled pool errors during idle disconnection
    this.pool.on('error', () => {
      // Handled via connection health diagnostics
    });

    // 2. Initialize Prisma 7 driver adapter
    // disposeExternalPool: false ensures PrismaClient.$disconnect() does NOT call pool.end(),
    // allowing DatabaseManager to deterministically control pool shutdown.
    const adapter = new PrismaPg(this.pool, {
      schema: this.targetSchema,
      disposeExternalPool: false,
    });

    // 3. Initialize PrismaClient with adapter
    this.prisma = new PrismaClient({ adapter });
  }

  private assertActive(): void {
    if (this.isClosed || this.isShuttingDown) {
      throw new SecureFlowError(
        `DatabaseManager targeting '${this.targetDatabase}' has been shut down and cannot accept queries`,
        'DATABASE_CONNECTION_CLOSED',
        500,
      );
    }
  }

  /**
   * Returns the underlying PrismaClient instance.
   */
  public getPrismaClient(): PrismaClient {
    this.assertActive();
    return this.prisma;
  }

  /**
   * Returns the underlying pg.Pool instance.
   */
  public getPool(): pg.Pool {
    this.assertActive();
    return this.pool;
  }

  /**
   * Returns a standard repository container bound to the root PrismaClient.
   */
  public getRepositories(): RepositoryContainer {
    this.assertActive();
    return createRepositories(this.prisma);
  }

  /**
   * Verifies database connectivity, authenticated user, and PostgreSQL version.
   */
  public async verifyConnectivity(): Promise<DatabaseIdentity> {
    this.assertActive();
    const client = await this.pool.connect();
    try {
      const res = await client.query<{
        current_db: string;
        current_user: string;
        server_addr: string | null;
        server_port: number | null;
        full_version: string;
      }>(`
        SELECT
          current_database() AS current_db,
          current_user AS current_user,
          inet_server_addr()::text AS server_addr,
          inet_server_port() AS server_port,
          version() AS full_version;
      `);

      const row = res.rows[0];
      if (!row) {
        throw new SecureFlowError('Failed to retrieve database identity row', 'DATABASE_IDENTITY_ERROR', 500);
      }

      const versionMatch = /PostgreSQL (\d+)\.?\d*/i.exec(row.full_version);
      const majorVersion = versionMatch && versionMatch[1] ? Number.parseInt(versionMatch[1], 10) : 0;

      return {
        database: row.current_db,
        authenticatedUser: row.current_user,
        host: row.server_addr ?? this.targetHost,
        port: row.server_port ?? this.targetPort,
        version: row.full_version,
        majorVersion,
      };
    } finally {
      client.release();
    }
  }

  /**
   * Executes a callback within a managed database transaction.
   *
   * Guarantees:
   * - Creates a transaction-scoped RepositoryContainer bound exclusively to the transaction client.
   * - Automatically rolls back changes if an error is thrown in the callback.
   * - Prevents usage of the transaction client after callback completion.
   */
  public async runTransaction<T>(
    fn: (repos: RepositoryContainer, tx: Prisma.TransactionClient) => Promise<T>,
    options?: {
      maxWait?: number;
      timeout?: number;
      isolationLevel?: Prisma.TransactionIsolationLevel;
    },
  ): Promise<T> {
    this.assertActive();
    return this.prisma.$transaction(async (tx) => {
      const txRepos = createRepositories(tx);
      return await fn(txRepos, tx);
    }, options);
  }

  /**
   * Gracefully shuts down the database client and connection pool.
   * Idempotent: safe to invoke multiple times.
   */
  public async shutdown(): Promise<void> {
    if (this.isClosed) {
      return;
    }
    this.isShuttingDown = true;
    try {
      await this.prisma.$disconnect();
    } catch {
      // Ignore disconnect errors during teardown
    }
    try {
      await this.pool.end();
    } catch {
      // Ignore pool end errors during teardown
    } finally {
      this.isClosed = true;
      this.isShuttingDown = false;
    }
  }
}
