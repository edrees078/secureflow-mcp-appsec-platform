import { EntityNotFoundError, ForbiddenError, UnauthorizedError } from '@secureflow/shared';
import type { ActorContext } from './actor-context.js';
import type { AuthzDecision, FindingAction, FindingAuthzContext } from './types.js';

/**
 * Authorization Policy for Finding Resources.
 * Enforces permissions per docs/04-authorization-matrix.md Section 2.2 and Section 3 (OLI-1 to OLI-12).
 */
export class FindingPolicy {
  public static can(
    actor: ActorContext | null | undefined,
    action: FindingAction,
    context: FindingAuthzContext,
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

    const projectId = context.finding?.projectId ?? context.projectId;
    const findingId = context.finding?.id;

    switch (action) {
      // -----------------------------------------------------------------------
      // Finding Creation
      // -----------------------------------------------------------------------
      case 'create': {
        // NEG-13: Admin cannot create operational findings (F-13)
        if (actor.isAdmin()) {
          return {
            allowed: false,
            httpStatus: 403,
            errorCode: 'FORBIDDEN',
            reason: 'Administrative role cannot create operational security findings (Analyst-scoped action)',
          };
        }

        // NEG-04: Developer cannot create findings
        if (actor.isDeveloper()) {
          return {
            allowed: false,
            httpStatus: 403,
            errorCode: 'FORBIDDEN',
            reason: 'Developer role cannot create security findings',
          };
        }

        if (!projectId) {
          return {
            allowed: false,
            httpStatus: 404,
            errorCode: 'RESOURCE_NOT_FOUND',
            reason: 'Project not found',
          };
        }

        // Analyst must be a member of the project with ANALYST role
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
            reason: 'Caller lacks Analyst role in target project',
          };
        }

        return { allowed: true };
      }

      // -----------------------------------------------------------------------
      // Finding Viewing
      // -----------------------------------------------------------------------
      case 'view': {
        if (!findingId || !projectId) {
          return {
            allowed: false,
            httpStatus: 404,
            errorCode: 'RESOURCE_NOT_FOUND',
            reason: 'Finding not found',
          };
        }

        // Invariant OLI-12: Soft-deleted finding is hidden from all non-admin callers
        if (context.finding?.isDeleted) {
          if (actor.isAdmin()) {
            return { allowed: true };
          }
          return {
            allowed: false,
            httpStatus: 404,
            errorCode: 'RESOURCE_NOT_FOUND',
            reason: 'Finding not found',
          };
        }

        // Admin has organization-wide read access
        if (actor.isAdmin()) {
          return { allowed: true };
        }

        // OLI-1 & NEG-03: User must have active project membership
        if (!actor.isMemberOf(projectId)) {
          return {
            allowed: false,
            httpStatus: 404,
            errorCode: 'RESOURCE_NOT_FOUND',
            reason: 'Finding not found',
          };
        }

        // Analysts see all findings in their projects
        if (actor.isAnalyst()) {
          return { allowed: true };
        }

        // OLI-2 & NEG-01: Developer may only read findings assigned to them
        if (actor.isDeveloper()) {
          if (context.finding?.assignedToId === actor.id) {
            return { allowed: true };
          }
          // Existence hiding: unassigned finding returns 404 Not Found to developer
          return {
            allowed: false,
            httpStatus: 404,
            errorCode: 'RESOURCE_NOT_FOUND',
            reason: 'Finding not found',
          };
        }

        return {
          allowed: false,
          httpStatus: 404,
          errorCode: 'RESOURCE_NOT_FOUND',
          reason: 'Finding not found',
        };
      }

      // -----------------------------------------------------------------------
      // Finding List
      // -----------------------------------------------------------------------
      case 'list': {
        // Handled by query scope builder (fail-closed if no authorized projects)
        return { allowed: true };
      }

      // -----------------------------------------------------------------------
      // Analyst Operational Actions (Triage, Metadata, Assignment, Close, Soft-Delete)
      // -----------------------------------------------------------------------
      case 'update_metadata':
      case 'triage':
      case 'assign':
      case 'close':
      case 'reopen':
      case 'soft_delete': {
        if (actor.isAdmin()) {
          return {
            allowed: false,
            httpStatus: 403,
            errorCode: 'FORBIDDEN',
            reason: `Action '${action}' is reserved for project Security Analysts`,
          };
        }

        if (actor.isDeveloper()) {
          return {
            allowed: false,
            httpStatus: 403,
            errorCode: 'FORBIDDEN',
            reason: `Developer cannot execute '${action}' on finding`,
          };
        }

        if (!projectId || !actor.isMemberOf(projectId)) {
          return {
            allowed: false,
            httpStatus: 404,
            errorCode: 'RESOURCE_NOT_FOUND',
            reason: 'Finding not found',
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
      // Remediation Submission (Developer only)
      // -----------------------------------------------------------------------
      case 'submit_remediation': {
        if (actor.isAdmin() || actor.isAnalyst()) {
          return {
            allowed: false,
            httpStatus: 403,
            errorCode: 'FORBIDDEN',
            reason: 'Remediation submission is an action reserved for assigned Developers',
          };
        }

        if (!projectId || !actor.isMemberOf(projectId)) {
          return {
            allowed: false,
            httpStatus: 404,
            errorCode: 'RESOURCE_NOT_FOUND',
            reason: 'Finding not found',
          };
        }

        // OLI-6 & NEG-08: Developer must be the designated assignee
        if (context.finding?.assignedToId !== actor.id) {
          return {
            allowed: false,
            httpStatus: 403,
            errorCode: 'FORBIDDEN',
            reason: 'Developer is not the designated assignee for this finding',
          };
        }

        return { allowed: true };
      }

      // -----------------------------------------------------------------------
      // Finding Verification & Separation of Duties (Analyst only)
      // -----------------------------------------------------------------------
      case 'verify': {
        // NEG-02 & NEG-11: Developer cannot verify findings
        if (actor.isDeveloper()) {
          return {
            allowed: false,
            httpStatus: 403,
            errorCode: 'FORBIDDEN',
            reason: 'Developer cannot verify findings',
          };
        }

        if (actor.isAdmin()) {
          return {
            allowed: false,
            httpStatus: 403,
            errorCode: 'FORBIDDEN',
            reason: 'Verification is an operational Analyst role; Admin cannot verify findings',
          };
        }

        if (!projectId || !actor.isMemberOf(projectId)) {
          return {
            allowed: false,
            httpStatus: 404,
            errorCode: 'RESOURCE_NOT_FOUND',
            reason: 'Finding not found',
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

        // OLI-7: Separation of Duties Check (Fail-Closed)
        // Verification REQUIRES reliable remediation submitter evidence.
        // If remediationSubmitterId is missing, undefined, null, or unrecorded,
        // verification cannot proceed because separation of duties cannot be verified.
        if (!context.remediationSubmitterId) {
          return {
            allowed: false,
            httpStatus: 403,
            errorCode: 'SEPARATION_OF_DUTIES_VIOLATION',
            reason: 'Verification rejected: reliable remediation submitter evidence is missing or unavailable (fail-closed SoD enforcement OLI-7)',
          };
        }

        // Analyst who submitted remediation cannot verify the same finding
        if (context.remediationSubmitterId === actor.id) {
          return {
            allowed: false,
            httpStatus: 403,
            errorCode: 'SEPARATION_OF_DUTIES_VIOLATION',
            reason: 'Analyst who submitted remediation cannot verify the same finding (separation of duties violation OLI-7)',
          };
        }

        return { allowed: true };
      }

      // -----------------------------------------------------------------------
      // Admin Exceptional Actions
      // -----------------------------------------------------------------------
      case 'force_close':
      case 'force_reopen': {
        if (actor.isAdmin()) {
          return { allowed: true };
        }
        return {
          allowed: false,
          httpStatus: 403,
          errorCode: 'FORBIDDEN',
          reason: `Exceptional action '${action}' requires global Admin authority`,
        };
      }

      default:
        return {
          allowed: false,
          httpStatus: 403,
          errorCode: 'FORBIDDEN',
          reason: `Unknown or unpermitted finding action '${action}'`,
        };
    }
  }

  public static authorize(
    actor: ActorContext | null | undefined,
    action: FindingAction,
    context: FindingAuthzContext,
  ): void {
    const decision = FindingPolicy.can(actor, action, context);
    if (!decision.allowed) {
      if (decision.httpStatus === 401) {
        throw new UnauthorizedError(decision.reason ?? 'Authentication required');
      }
      if (decision.httpStatus === 404) {
        throw new EntityNotFoundError('Finding not found');
      }
      throw new ForbiddenError(decision.reason ?? 'Access forbidden');
    }
  }
}
