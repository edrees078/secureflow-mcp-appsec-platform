/**
 * SecureFlow Domain Service Contracts & Interfaces.
 *
 * Defines type-safe service interfaces and DTO contracts governing all domain operations.
 *
 * Architecture & Security Principles (Gates 3A-3D):
 * 1. ActorContext as First Parameter:
 *    Every public domain service method accepts `actor: ActorContext` as its mandatory first argument.
 *    Object-level authorization policies (Gate 3C) and query scopes are evaluated directly within the service.
 *    No unauthenticated or actorless service method exists.
 * 2. Optimistic Concurrency Control (OCC):
 *    All finding mutations accept `expectedVersion: number`. The service enforces atomic compare-and-increment
 *    via repository `updateAtomic`, returning 409 Conflict on version mismatch.
 * 3. Strict DTO Validation:
 *    Service operations accept canonical DTOs validated against schemas from `@secureflow/schemas`.
 *    Runtime validation for exceptional admin actions (ForceCloseFindingInputSchema, ForceReopenFindingInputSchema)
 *    strictly mandates non-empty business justifications.
 * 4. Separation of Concerns & Clean Architecture:
 *    Service interfaces and dependency-injection contracts decouple business logic from concrete
 *    database drivers (Prisma ORM, pg adapter) and transport protocols (REST API, MCP).
 */

import type {
  CreateFindingInput,
  TriageFindingInput,
  AssignFindingInput,
  SubmitRemediationInput,
  VerifyFindingInput,
  CloseFindingInput,
  ForceCloseFindingInput,
  ForceReopenFindingInput,
  UpdateFindingMetadataInput,
  SoftDeleteFindingInput,
  CreateProjectInput,
  UpdateProjectInput,
  AddProjectMemberInput,
  UpdateTaskNotesInput,
  QueryAuditEventsInput,
  FindingSeverity,
  FindingCategory,
  FindingStatus,
} from '@secureflow/schemas';

import type { ActorContext } from '../policy/actor-context.js';
import type {
  ProjectEntity,
  ProjectMemberEntity,
  FindingEntity,
  RemediationTaskEntity,
  AuditEventEntity,
  PaginatedResult,
  RepositoryContainer,
} from '../db/repositories/types.js';

// Re-export exceptional admin action DTOs from schemas for service callers
export type {
  ForceCloseFindingInput,
  ForceReopenFindingInput,
};

// ============================================================================
// Service Query & Mutation Filter Contracts
// ============================================================================

export interface ListFindingsFilterInput {
  readonly projectId?: string;
  readonly status?: FindingStatus;
  readonly severity?: FindingSeverity;
  readonly category?: FindingCategory;
  readonly assignedToId?: string;
  readonly search?: string;
  readonly page?: number;
  readonly limit?: number;
}

export interface ListProjectsFilterInput {
  readonly search?: string;
  readonly page?: number;
  readonly limit?: number;
  readonly includeInactive?: boolean;
}

// ============================================================================
// Service Dependency Injection Contracts
// ============================================================================

/**
 * Controlled dependency-injection interface for domain services.
 * Injects repository interfaces without exposing Prisma clients or concrete classes.
 */
export interface ServiceDependencies {
  readonly repositories: RepositoryContainer;
}

// ============================================================================
// Domain Service Interfaces
// ============================================================================

/**
 * Project Management Domain Service Interface.
 * Governs project lifecycle, metadata updates, archiving, and member administration.
 */
export interface IProjectService {
  createProject(actor: ActorContext, input: CreateProjectInput): Promise<ProjectEntity>;
  updateProject(actor: ActorContext, projectId: string, input: UpdateProjectInput): Promise<ProjectEntity>;
  archiveProject(actor: ActorContext, projectId: string): Promise<ProjectEntity>;
  getProject(actor: ActorContext, projectId: string): Promise<ProjectEntity>;
  listProjects(actor: ActorContext, filter?: ListProjectsFilterInput): Promise<PaginatedResult<ProjectEntity>>;
  addMember(actor: ActorContext, projectId: string, input: AddProjectMemberInput): Promise<ProjectMemberEntity>;
  removeMember(actor: ActorContext, projectId: string, userId: string): Promise<boolean>;
  listMembers(actor: ActorContext, projectId: string): Promise<ProjectMemberEntity[]>;
}

/**
 * Finding Management Domain Service Interface.
 * Governs full finding lifecycle, state machine transitions, OCC mutations, and SoD verification.
 * Every operation mandates an authenticated ActorContext; zero actorless methods are permitted.
 */
export interface IFindingService {
  createFinding(actor: ActorContext, input: CreateFindingInput): Promise<FindingEntity>;
  getFinding(actor: ActorContext, findingId: string): Promise<FindingEntity>;
  listFindings(actor: ActorContext, filter?: ListFindingsFilterInput): Promise<PaginatedResult<FindingEntity>>;
  triageFinding(actor: ActorContext, findingId: string, input: TriageFindingInput): Promise<FindingEntity>;
  assignFinding(actor: ActorContext, findingId: string, input: AssignFindingInput): Promise<FindingEntity>;
  submitRemediation(actor: ActorContext, findingId: string, input: SubmitRemediationInput): Promise<FindingEntity>;
  verifyFinding(actor: ActorContext, findingId: string, input: VerifyFindingInput): Promise<FindingEntity>;
  confirmVerification(actor: ActorContext, findingId: string, input: Omit<VerifyFindingInput, 'outcome'>): Promise<FindingEntity>;
  rejectVerification(actor: ActorContext, findingId: string, input: Omit<VerifyFindingInput, 'outcome'>): Promise<FindingEntity>;
  closeFinding(actor: ActorContext, findingId: string, input: CloseFindingInput): Promise<FindingEntity>;
  forceCloseFinding(actor: ActorContext, findingId: string, input: ForceCloseFindingInput): Promise<FindingEntity>;
  forceReopenFinding(actor: ActorContext, findingId: string, input: ForceReopenFindingInput): Promise<FindingEntity>;
  updateFindingMetadata(actor: ActorContext, findingId: string, input: UpdateFindingMetadataInput): Promise<FindingEntity>;
  softDeleteFinding(actor: ActorContext, findingId: string, input: SoftDeleteFindingInput): Promise<FindingEntity>;
}

/**
 * Remediation Task Management Domain Service Interface.
 * Governs task progress notes updates and developer task queries.
 */
export interface ITaskService {
  getTask(actor: ActorContext, taskId: string): Promise<RemediationTaskEntity>;
  getTaskByFindingId(actor: ActorContext, findingId: string): Promise<RemediationTaskEntity | null>;
  updateTaskNotes(actor: ActorContext, taskId: string, input: UpdateTaskNotesInput): Promise<RemediationTaskEntity>;
}

/**
 * Audit Log Domain Service Interface.
 * Governs immutable audit trail queries for Admin security reviewers.
 */
export interface IAuditService {
  queryAuditLogs(actor: ActorContext, filter: QueryAuditEventsInput): Promise<PaginatedResult<AuditEventEntity>>;
}
