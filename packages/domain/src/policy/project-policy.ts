import { EntityNotFoundError, ForbiddenError, UnauthorizedError } from '@secureflow/shared';
import type { ActorContext } from './actor-context.js';
import type { AuthzDecision, ProjectAction } from './types.js';

/**
 * Authorization Policy for Project Resources.
 * Enforces permissions per docs/04-authorization-matrix.md Section 2.1.
 */
export class ProjectPolicy {
  public static can(
    actor: ActorContext | null | undefined,
    action: ProjectAction,
    target?: { id: string } | null,
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
      case 'create':
      case 'update':
      case 'archive':
      case 'add_member':
      case 'remove_member':
      case 'list_all': {
        // Admin governance operations (NEG-06, NEG-07)
        if (actor.isAdmin()) {
          return { allowed: true };
        }
        return {
          allowed: false,
          httpStatus: 403,
          errorCode: 'FORBIDDEN',
          reason: `Action '${action}' requires organization-wide Admin role`,
        };
      }

      case 'list_own': {
        // All active users can query their own permitted projects
        return { allowed: true };
      }

      case 'view':
      case 'view_members': {
        if (actor.isAdmin()) {
          return { allowed: true };
        }
        if (!target?.id) {
          return {
            allowed: false,
            httpStatus: 404,
            errorCode: 'RESOURCE_NOT_FOUND',
            reason: 'Project not found',
          };
        }
        if (actor.isMemberOf(target.id)) {
          return { allowed: true };
        }
        // Invariant: Non-members receive 404 existence hiding, not 403
        return {
          allowed: false,
          httpStatus: 404,
          errorCode: 'RESOURCE_NOT_FOUND',
          reason: 'Project not found or caller lacks authorized membership',
        };
      }

      default:
        return {
          allowed: false,
          httpStatus: 403,
          errorCode: 'FORBIDDEN',
          reason: `Unknown or unpermitted project action '${action}'`,
        };
    }
  }

  public static authorize(
    actor: ActorContext | null | undefined,
    action: ProjectAction,
    target?: { id: string } | null,
  ): void {
    const decision = ProjectPolicy.can(actor, action, target);
    if (!decision.allowed) {
      if (decision.httpStatus === 401) {
        throw new UnauthorizedError(decision.reason ?? 'Authentication required');
      }
      if (decision.httpStatus === 404) {
        throw new EntityNotFoundError('Project not found');
      }
      throw new ForbiddenError(decision.reason ?? 'Access forbidden');
    }
  }
}
