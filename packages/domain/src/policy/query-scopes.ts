import type { ActorContext } from './actor-context.js';
import type {
  FindingQueryScope,
  ProjectQueryScope,
} from '../db/repositories/types.js';

export interface ScopeDerivationOptions {
  /**
   * Whether to include inactive (archived) projects.
   * Only honored for global Admin callers.
   */
  readonly includeInactiveProjects?: boolean | undefined;
  /**
   * Whether to include soft-deleted findings (OLI-12).
   * Strictly honored for global Admin callers only.
   */
  readonly includeDeletedFindings?: boolean | undefined;
}

/**
 * Derives a ProjectQueryScope from the authenticated ActorContext.
 *
 * Security Invariants:
 * - Inactive actors fail-closed with empty accessibleProjectIds (0 records).
 * - Only global Admin callers receive unrestricted: true.
 * - Non-admins (Analyst, Developer) receive strictly the project IDs where they have active membership.
 * - includeInactive is honored only for global Admin.
 */
export function deriveProjectQueryScope(
  actor: ActorContext | null | undefined,
  options?: ScopeDerivationOptions,
): ProjectQueryScope {
  if (!actor || !actor.isActive) {
    return { accessibleProjectIds: [] };
  }

  if (actor.isAdmin()) {
    return {
      unrestricted: true,
      includeInactive: options?.includeInactiveProjects ?? false,
    };
  }

  const accessibleProjectIds = actor.getProjectIds();
  return {
    accessibleProjectIds,
    unrestricted: false,
    includeInactive: false,
  };
}

/**
 * Derives a FindingQueryScope from the authenticated ActorContext.
 *
 * Security Invariants:
 * - Inactive actors fail-closed with empty accessibleProjectIds (0 records).
 * - Only global Admin callers receive unrestricted: true.
 * - Invariant OLI-12: includeDeleted: true is strictly restricted to global Admin callers.
 *   Even if an Analyst or Developer passes includeDeletedFindings: true, it is ignored and set to false.
 * - Analysts can query only findings belonging to their authorized projects.
 * - Developers are strictly constrained to findings assigned to them (assignedToUserId: actor.id)
 *   within their authorized projects.
 * - If accessibleProjectIds is empty, query returns 0 records at the database level.
 */
export function deriveFindingQueryScope(
  actor: ActorContext | null | undefined,
  options?: ScopeDerivationOptions,
): FindingQueryScope {
  if (!actor || !actor.isActive) {
    return { accessibleProjectIds: [] };
  }

  if (actor.isAdmin()) {
    return {
      unrestricted: true,
      includeDeleted: options?.includeDeletedFindings === true,
    };
  }

  const accessibleProjectIds = actor.getProjectIds();

  if (actor.isAnalyst()) {
    return {
      accessibleProjectIds,
      unrestricted: false,
      includeDeleted: false,
    };
  }

  if (actor.isDeveloper()) {
    return {
      accessibleProjectIds,
      assignedToUserId: actor.id,
      unrestricted: false,
      includeDeleted: false,
    };
  }

  // Deny by default for any unknown role state
  return { accessibleProjectIds: [] };
}
