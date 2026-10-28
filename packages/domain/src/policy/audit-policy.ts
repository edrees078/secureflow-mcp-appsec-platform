import { ForbiddenError, UnauthorizedError } from '@secureflow/shared';
import type { ActorContext } from './actor-context.js';
import type { AuditAction, AuthzDecision } from './types.js';

/**
 * Authorization Policy for Audit Event Resources.
 * Enforces permissions per docs/04-authorization-matrix.md Section 2.4.
 */
export class AuditPolicy {
  public static can(
    actor: ActorContext | null | undefined,
    action: AuditAction,
  ): AuthzDecision {
    // 1. Unauthenticated request denial (NEG-05: 401 Unauthorized)
    if (!actor) {
      return {
        allowed: false,
        httpStatus: 401,
        errorCode: 'UNAUTHORIZED',
        reason: 'Authentication required',
      };
    }

    // 2. Inactive account denial by default (403 Forbidden)
    if (!actor.isActive) {
      return {
        allowed: false,
        httpStatus: 403,
        errorCode: 'ACCOUNT_INACTIVE',
        reason: 'User account is deactivated',
      };
    }

    switch (action) {
      case 'view_project':
      case 'view_org': {
        // NEG-12: Only global Admin may view audit logs
        if (actor.isAdmin()) {
          return { allowed: true };
        }
        return {
          allowed: false,
          httpStatus: 403,
          errorCode: 'FORBIDDEN',
          reason: 'Audit event inspection requires organization-wide Admin role',
        };
      }

      default:
        return {
          allowed: false,
          httpStatus: 403,
          errorCode: 'FORBIDDEN',
          reason: `Unknown or unpermitted audit action '${action}'`,
        };
    }
  }

  public static authorize(
    actor: ActorContext | null | undefined,
    action: AuditAction,
  ): void {
    const decision = AuditPolicy.can(actor, action);
    if (!decision.allowed) {
      if (decision.httpStatus === 401) {
        throw new UnauthorizedError(decision.reason ?? 'Authentication required');
      }
      throw new ForbiddenError(decision.reason ?? 'Access forbidden');
    }
  }
}
