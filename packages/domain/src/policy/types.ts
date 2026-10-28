/**
 * Authorization Decision Result Contract.
 */
export interface AuthzDecision {
  readonly allowed: boolean;
  readonly reason?: string;
  readonly httpStatus?: 401 | 403 | 404;
  readonly errorCode?: string;
}

/**
 * Project-Level Operational Actions.
 */
export type ProjectAction =
  | 'create'
  | 'list_all'
  | 'list_own'
  | 'view'
  | 'update'
  | 'archive'
  | 'add_member'
  | 'remove_member'
  | 'view_members';

/**
 * Finding-Level Operational Actions.
 */
export type FindingAction =
  | 'create'
  | 'list'
  | 'view'
  | 'update_metadata'
  | 'triage'
  | 'assign'
  | 'submit_remediation'
  | 'verify'
  | 'close'
  | 'reopen'
  | 'force_close'
  | 'force_reopen'
  | 'soft_delete';

/**
 * Remediation Task Operational Actions.
 */
export type TaskAction =
  | 'create'
  | 'view'
  | 'update_notes'
  | 'submit'
  | 'verify'
  | 'reject';

/**
 * Audit Log Operational Actions.
 */
export type AuditAction =
  | 'view_project'
  | 'view_org';

/**
 * Resource Context for Finding Policy Evaluations.
 */
export interface FindingAuthzContext {
  readonly finding?: {
    readonly id: string;
    readonly projectId: string;
    readonly assignedToId?: string | null;
    readonly isDeleted?: boolean;
  } | null;
  readonly projectId?: string;
  /**
   * User ID of the actor who submitted remediation for this finding.
   * Required for Separation of Duties (SoD) verification (OLI-7).
   */
  readonly remediationSubmitterId?: string | null;
}

/**
 * Resource Context for Task Policy Evaluations.
 */
export interface TaskAuthzContext {
  readonly task?: {
    readonly id: string;
    readonly findingId: string;
    readonly assignedToId: string;
  } | null;
  readonly projectId: string;
}
