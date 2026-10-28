import { DatabaseManager, type DatabaseConfig } from '../db/database-manager.js';
import { ProjectService } from './project-service.js';
import { AuditService } from './audit-service.js';
import { FindingService } from './finding-service.js';
import type { IProjectService, IAuditService, IFindingService } from './types.js';
import { SecureFlowError } from '@secureflow/shared';

export interface DomainServicesConfig {
  connectionString: string;
  maxConnections?: number | undefined;
  idleTimeoutMillis?: number | undefined;
  connectionTimeoutMillis?: number | undefined;
  statementTimeoutMillis?: number | undefined;
  schema?: string | undefined;
}

export interface DomainServices {
  readonly projectService: IProjectService;
  readonly auditService: IAuditService;
  readonly findingService: IFindingService;
  readonly close: () => Promise<void>;
}

/**
 * Trusted production composition root for SecureFlow domain services.
 * Instantiates the internal DatabaseManager and binds all domain services
 * without exposing raw Prisma clients, connection pools, or unrestricted repositories.
 *
 * DatabaseManager Ownership Contract:
 * - When initialized with `DomainServicesConfig`, this factory constructs and owns
 *   the underlying `DatabaseManager`. Calling `close()` will shut down the connection pool.
 * - When initialized with an existing `DatabaseManager`, the caller retains ownership.
 *   Calling `close()` is a no-op to prevent silently shutting down an externally managed or shared instance.
 */
export function createDomainServices(
  config: DomainServicesConfig | DatabaseManager,
): DomainServices {
  if (!config) {
    throw new SecureFlowError(
      'createDomainServices failed: config or DatabaseManager required',
      'SERVICE_INITIALIZATION_ERROR',
      500,
    );
  }

  const isOwned = !(config instanceof DatabaseManager);
  const dbManager = isOwned
    ? new DatabaseManager(config as DatabaseConfig)
    : config;

  return {
    projectService: new ProjectService(dbManager),
    auditService: new AuditService(dbManager),
    findingService: new FindingService({ db: dbManager }),
    close: async () => {
      if (isOwned) {
        await dbManager.shutdown();
      }
    },
  };
}
