import { EntityNotFoundError, ForbiddenError, UnauthorizedError } from '@secureflow/shared';
import type { ActorContext } from './actor-context.js';
import type { AuthzDecision, TaskAction, TaskAuthzContext } from './types.js';

/**
 * Authorization Policy for Remediation Task Resources.
 * Enforces permissions per docs/04-authorization-matrix.md Section 2.3.
 */
export class TaskPolicy {
  public static can(
    actor: ActorContext | null | undefined,
    action: TaskAction,
    context: TaskAuthzContext,
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

    const { projectId, task } = context;

    switch (action) {
      // -----------------------------------------------------------------------
      // Task Creation
      // -----------------------------------------------------------------------
      case 'create': {
        if (actor.isAdmin()) {
          return {
            allowed: false,
            httpStatus: 403,
            errorCode: 'FORBIDDEN',
            reason: 'Administrative role cannot create remediation tasks',
          };
        }

        if (actor.isDeveloper()) {
          return {
            allowed: false,
            httpStatus: 403,
            errorCode: 'FORBIDDEN',
            reason: 'Developer role cannot create remediation tasks',
          };
        }

        if (!actor.isMemberOf(projectId)) {
          return {
            allowed: false,
            httpStatus: 404,
            errorCode: 'RESOURCE_NOT_FOUND',
            reason: 'Project not found or caller lacks authorized membership',
          };
        }

        if (!actor.hasProjectRole(projectId, 'ANALYST')) {
          return {
            allowed: false,
            httpStatus: 403,
            errorCode: 'FORBIDDEN',
            reason: 'Caller lacks Analyst role in project',
          };
        }

        return { allowed: true };
      }

      // -----------------------------------------------------------------------
      // Task Viewing
      // -----------------------------------------------------------------------
      case 'view': {
        if (!task?.id) {
          return {
            allowed: false,
            httpStatus: 404,
            errorCode: 'RESOURCE_NOT_FOUND',
            reason: 'Remediation task not found',
          };
        }

        if (actor.isAdmin()) {
          return { allowed: true };
        }

        if (!actor.isMemberOf(projectId)) {
          return {
            allowed: false,
            httpStatus: 404,
            errorCode: 'RESOURCE_NOT_FOUND',
            reason: 'Remediation task not found',
          };
        }

        if (actor.isAnalyst()) {
          return { allowed: true };
        }

        if (actor.isDeveloper()) {
          if (task.assignedToId === actor.id) {
            return { allowed: true };
          }
          // Existence hiding: unassigned task returns 404 Not Found to developer
          return {
            allowed: false,
            httpStatus: 404,
            errorCode: 'RESOURCE_NOT_FOUND',
            reason: 'Remediation task not found',
          };
        }

        return {
          allowed: false,
          httpStatus: 404,
          errorCode: 'RESOURCE_NOT_FOUND',
          reason: 'Remediation task not found',
        };
      }

      // -----------------------------------------------------------------------
      // Task Progress & Submission (Developer only)
      // -----------------------------------------------------------------------
      case 'update_notes':
      case 'submit': {
        if (actor.isAdmin() || actor.isAnalyst()) {
          return {
            allowed: false,
            httpStatus: 403,
            errorCode: 'FORBIDDEN',
            reason: `Action '${action}' is restricted to assigned Developers`,
          };
        }

        if (!task?.id || !actor.isMemberOf(projectId)) {
          return {
            allowed: false,
            httpStatus: 404,
            errorCode: 'RESOURCE_NOT_FOUND',
            reason: 'Remediation task not found',
          };
        }

        // Invariant OLI-3: Developer must be the assigned remediator
        if (task.assignedToId !== actor.id) {
          return {
            allowed: false,
            httpStatus: 403,
            errorCode: 'FORBIDDEN',
            reason: 'Developer is not the designated assignee for this task',
          };
        }

        return { allowed: true };
      }

      // -----------------------------------------------------------------------
      // Task Verification / Rejection (Analyst only)
      // -----------------------------------------------------------------------
      case 'verify':
      case 'reject': {
        if (actor.isAdmin() || actor.isDeveloper()) {
          return {
            allowed: false,
            httpStatus: 403,
            errorCode: 'FORBIDDEN',
            reason: `Action '${action}' is restricted to project Security Analysts`,
          };
        }

        if (!task?.id || !actor.isMemberOf(projectId)) {
          return {
            allowed: false,
            httpStatus: 404,
            errorCode: 'RESOURCE_NOT_FOUND',
            reason: 'Remediation task not found',
          };
        }

        if (!actor.hasProjectRole(projectId, 'ANALYST')) {
          return {
            allowed: false,
            httpStatus: 403,
            errorCode: 'FORBIDDEN',
            reason: 'Caller lacks Analyst role in project',
          };
        }

        return { allowed: true };
      }

      default:
        return {
          allowed: false,
          httpStatus: 403,
          errorCode: 'FORBIDDEN',
          reason: `Unknown or unpermitted task action '${action}'`,
        };
    }
  }

  public static authorize(
    actor: ActorContext | null | undefined,
    action: TaskAction,
    context: TaskAuthzContext,
  ): void {
    const decision = TaskPolicy.can(actor, action, context);
    if (!decision.allowed) {
      if (decision.httpStatus === 401) {
        throw new UnauthorizedError(decision.reason ?? 'Authentication required');
      }
      if (decision.httpStatus === 404) {
        throw new EntityNotFoundError('Remediation task not found');
      }
      throw new ForbiddenError(decision.reason ?? 'Access forbidden');
    }
  }
}
