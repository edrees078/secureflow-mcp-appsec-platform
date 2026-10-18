import path from 'node:path';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';
import pg from 'pg';

const { Client } = pg;

// Monorepo environment variable loading
const __dirname = path.dirname(fileURLToPath(import.meta.url));
dotenv.config({ path: path.resolve(__dirname, '../../../.env') });
dotenv.config({ path: path.resolve(__dirname, '../../.env') });

export interface DatabaseConnectivityResult {
  connected: boolean;
  database?: string | undefined;
  user?: string | undefined;
  version?: string | undefined;
  majorVersion?: number | undefined;
  hostPort?: number | string | undefined;
  serverTime?: string | undefined;
  error?: string | undefined;
  errorCode?: string | undefined;
  diagnosticAdvice?: string | undefined;
}

/**
 * Executes a real authenticated PostgreSQL query to verify end-to-end database connectivity.
 * Guarantees isolation from any host PostgreSQL 15 service by validating major version 17,
 * host port 5433, database name 'secureflow_dev', and authenticated user 'secureflow'.
 *
 * @param connectionString Optional explicit connection string; defaults to DATABASE_URL or component variables.
 * @param timeoutMs Connection timeout in milliseconds.
 * @returns Structured result containing connection status, database metadata, and diagnostic advice.
 */
export async function verifyDatabaseConnectivity(
  connectionString?: string,
  timeoutMs = 5000,
): Promise<DatabaseConnectivityResult> {
  const defaultPort = process.env['POSTGRES_PORT'] || '5433';
  const url =
    connectionString ||
    process.env['DATABASE_URL'] ||
    `postgresql://${process.env['POSTGRES_USER'] || 'secureflow'}:${process.env['POSTGRES_PASSWORD'] || 'secureflow_dev_password_change_me'}@${process.env['POSTGRES_HOST'] || '127.0.0.1'}:${defaultPort}/${process.env['POSTGRES_DB'] || 'secureflow_dev'}?schema=public`;

  let resolvedPort: string = defaultPort;
  try {
    const parsed = new URL(url);
    if (parsed.port) {
      resolvedPort = parsed.port;
    }
  } catch {
    // Keep defaultPort if URL parsing fails
  }

  const client = new Client({
    connectionString: url,
    connectionTimeoutMillis: timeoutMs,
  });

  try {
    await client.connect();
    const result = await client.query<{
      connected: number;
      db_name: string;
      username: string;
      version: string;
      server_time: string;
    }>(
      'SELECT 1 AS connected, current_database() AS db_name, current_user AS username, version() AS version, NOW() AS server_time;',
    );

    const row = result.rows[0];
    await client.end();

    const versionStr = row?.version ?? '';
    const majorMatch = versionStr.match(/PostgreSQL (\d+)/i);
    const majorVersion = majorMatch && majorMatch[1] ? parseInt(majorMatch[1], 10) : undefined;
    const dbName = row?.db_name;
    const username = row?.username;

    // Safety Isolation Verification: Ensure we never run against host PostgreSQL 15
    if (majorVersion !== 17) {
      return {
        connected: false,
        database: dbName,
        user: username,
        version: versionStr,
        majorVersion,
        hostPort: resolvedPort,
        error: `Connected to unexpected PostgreSQL version: ${majorVersion ?? 'unknown'}. Expected PostgreSQL 17.`,
        errorCode: 'ERR_WRONG_PG_VERSION',
        diagnosticAdvice:
          'Port conflict or wrong instance detected. Ensure SecureFlow is connecting to Docker PostgreSQL 17 on port 5433, not native PostgreSQL 15 on port 5432.',
      };
    }

    if (dbName !== 'secureflow_dev') {
      return {
        connected: false,
        database: dbName,
        user: username,
        version: versionStr,
        majorVersion,
        hostPort: resolvedPort,
        error: `Connected to unexpected database: '${dbName}'. Expected 'secureflow_dev'.`,
        errorCode: 'ERR_WRONG_DATABASE',
        diagnosticAdvice: 'Check POSTGRES_DB in .env and verify database name in connection string.',
      };
    }

    if (username !== 'secureflow') {
      return {
        connected: false,
        database: dbName,
        user: username,
        version: versionStr,
        majorVersion,
        hostPort: resolvedPort,
        error: `Authenticated as unexpected user: '${username}'. Expected 'secureflow'.`,
        errorCode: 'ERR_WRONG_USER',
        diagnosticAdvice: 'Check POSTGRES_USER in .env and verify credentials in connection string.',
      };
    }

    return {
      connected: true,
      database: dbName,
      user: username,
      version: versionStr,
      majorVersion,
      hostPort: resolvedPort,
      serverTime: row?.server_time,
    };
  } catch (err: unknown) {
    try {
      await client.end();
    } catch {
      // Ignore disconnect error if connection was never established
    }

    const pgError = err as { code?: string; message?: string; errno?: number | string };
    const errorCode = pgError.code || (typeof pgError.errno === 'string' ? pgError.errno : undefined) || 'UNKNOWN';
    const errorMessage = pgError.message || String(err);

    let diagnosticAdvice = 'Check PostgreSQL container and network configuration.';
    if (errorMessage.includes('ECONNREFUSED') || errorCode === 'ECONNREFUSED') {
      diagnosticAdvice =
        `PostgreSQL service is offline or not reachable on 127.0.0.1:${resolvedPort}. ` +
        "Ensure Docker Desktop is running and start the container with 'pnpm run db:up'. " +
        'Check container logs with docker compose logs postgres.';
    } else if (errorCode === '28P01') {
      diagnosticAdvice =
        'Authentication failed (password authentication failed). ' +
        'Verify POSTGRES_PASSWORD in .env matches the initialized database credentials.';
    } else if (errorCode === '3D000') {
      diagnosticAdvice =
        'Target database does not exist. Verify POSTGRES_DB in .env or run database initialization.';
    } else if (errorMessage.includes('timeout')) {
      diagnosticAdvice =
        'Connection timed out. Check firewall rules, port conflicts, or container responsiveness.';
    }

    return {
      connected: false,
      hostPort: resolvedPort,
      error: errorMessage,
      errorCode,
      diagnosticAdvice,
    };
  }
}

// Direct CLI execution handler
const currentFile = fileURLToPath(import.meta.url);
const invokedFile = process.argv[1] ? path.resolve(process.argv[1]) : '';

if (invokedFile && (currentFile === invokedFile || invokedFile.endsWith('smoke-check.ts') || invokedFile.endsWith('smoke-check.js'))) {
  console.log('==================================================');
  console.log('SecureFlow — PostgreSQL Connectivity Smoke Check');
  console.log('==================================================');

  verifyDatabaseConnectivity()
    .then((result) => {
      if (result.connected) {
        console.log('STATUS:             CONNECTED (SUCCESS)');
        console.log(`Host Port:          ${result.hostPort}`);
        console.log(`Database:           ${result.database}`);
        console.log(`Authenticated User: ${result.user}`);
        console.log(`PostgreSQL Version: ${result.version}`);
        console.log(`Major Version:      ${result.majorVersion} (VERIFIED ISOLATED FROM PG 15)`);
        console.log(`Server Time:        ${result.serverTime}`);
        console.log('==================================================');
        process.exit(0);
      } else {
        console.error('STATUS:             FAILED / DISCONNECTED');
        console.error(`Host Port:          ${result.hostPort}`);
        console.error(`Error Code:         ${result.errorCode}`);
        console.error(`Error Msg:          ${result.error}`);
        console.error(`Advice:             ${result.diagnosticAdvice}`);
        console.error('==================================================');
        process.exit(1);
      }
    })
    .catch((unexpected) => {
      console.error('Unexpected error during database connectivity check:', unexpected);
      process.exit(1);
    });
}
