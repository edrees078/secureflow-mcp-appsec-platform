import {
  QueryAuditEventsInputSchema,
  type QueryAuditEventsInput,
} from '@secureflow/schemas';
import {
  ForbiddenError,
  SecureFlowError,
  UnauthorizedError,
} from '@secureflow/shared';

import type { ActorContext } from '../policy/actor-context.js';
import { AuditPolicy } from '../policy/audit-policy.js';
import type {
  AuditEventEntity,
  PaginatedResult,
  RepositoryContainer,
} from '../db/repositories/types.js';
import { DatabaseManager } from '../db/database-manager.js';
import type { IAuditService } from './types.js';
import { handleDatabaseConcurrencyError } from './concurrency-handler.js';

/**
 * Service initialization parameter: either trusted DatabaseManager or explicitly provided test repositories.
 */
export type AuditServiceInit =
  | DatabaseManager
  | { readonly repositories: RepositoryContainer };

/**
 * Audit Log Domain Service.
 *
 * Implements IAuditService governing immutable audit trail inspection.
 * Restricted strictly to organization-wide Admin reviewers (per FR-020, FR-022, NEG-12).
 *
 * Guarantees:
 * 1. ActorContext as Mandatory First Parameter.
 * 2. Administrative Authorization Policy Enforcement (AuditPolicy.authorize).
 * 3. Authoritative Account & Role Freshness: Re-checks caller status in database.
 * 4. Runtime DTO Validation via QueryAuditEventsInputSchema.
 * 5. Strict Date Range Invariants: Rejects reversed date ranges (from > to) with HTTP 400.
 * 6. Strict Append-Only Immutability: No update or delete operations exist.
 * 7. Information Disclosure Defense: Non-admin callers receive 403 Forbidden without leaking metadata.
 */
export class AuditService implements IAuditService {
  private readonly db: DatabaseManager | undefined;
  private readonly directRepos: RepositoryContainer | undefined;

  public constructor(init: AuditServiceInit) {
    if (!init) {
      throw new SecureFlowError(
        'AuditService initialization failed: valid DatabaseManager or test repository container required',
        'SERVICE_INITIALIZATION_ERROR',
        500,
      );
    }

    if (init instanceof DatabaseManager) {
      this.db = init;
      this.directRepos = undefined;
    } else if (
      typeof init === 'object' &&
      'repositories' in init &&
      init.repositories &&
      typeof init.repositories === 'object' &&
      init.repositories.auditRepo &&
      init.repositories.userRepo
    ) {
      this.directRepos = init.repositories;
      this.db = undefined;
    } else {
      throw new SecureFlowError(
        'AuditService initialization failed: invalid or contradictory dependencies provided',
        'SERVICE_INITIALIZATION_ERROR',
        500,
      );
    }
  }

  private getRepos(): RepositoryContainer {
    if (this.directRepos) {
      return this.directRepos;
    }
    if (this.db) {
      return this.db.getRepositories();
    }
    throw new SecureFlowError(
      'AuditService database connection not configured',
      'DATABASE_CONFIG_ERROR',
      500,
    );
  }

  public async queryAuditLogs(
    actor: ActorContext,
    filter: QueryAuditEventsInput,
  ): Promise<PaginatedResult<AuditEventEntity>> {
    // 1. Policy-based authorization (AuditPolicy enforces Admin role, rejects non-admin with 403)
    // Authorization check PRECEDES query parsing so malformed inputs do not leak to unauthorized callers
    AuditPolicy.authorize(actor, 'view_org');

    const repos = this.getRepos();

    // 2. Authoritative database freshness revalidation
    const user = await repos.userRepo.findById(actor.id);
    if (!user) {
      throw new UnauthorizedError('Actor account not found');
    }
    if (!user.isActive) {
      throw new ForbiddenError('User account is deactivated');
    }
    if (user.globalRole !== 'ADMIN') {
      throw new ForbiddenError('Audit event inspection requires organization-wide Admin role');
    }

    // 3. Strict runtime DTO validation
    const parsed = QueryAuditEventsInputSchema.parse(filter);

    // 4. Date range parsing & ordering validation
    const fromTimestamp = parsed.fromTimestamp
      ? new Date(parsed.fromTimestamp)
      : undefined;
    const toTimestamp = parsed.toTimestamp
      ? new Date(parsed.toTimestamp)
      : undefined;

    if (fromTimestamp && toTimestamp && fromTimestamp > toTimestamp) {
      throw new SecureFlowError(
        'Invalid date range: fromTimestamp cannot be after toTimestamp',
        'INVALID_DATE_RANGE',
        400,
      );
    }

    try {
      // 5. Query append-only audit repository
      return await repos.auditRepo.query({
        eventCategory: parsed.eventCategory,
        eventType: parsed.eventType,
        resourceId: parsed.resourceId,
        resourceType: parsed.resourceType,
        actorId: parsed.actorId,
        fromTimestamp,
        toTimestamp,
        page: parsed.page,
        limit: parsed.limit,
      });
    } catch (err: unknown) {
      handleDatabaseConcurrencyError(err);
    }
  }
}
