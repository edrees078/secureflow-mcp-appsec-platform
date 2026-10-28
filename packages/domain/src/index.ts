/**
 * SecureFlow Domain Layer Entry Point.
 *
 * Public surface of @secureflow/domain exposing approved business services,
 * object-level authorization policies, read-only domain entity types,
 * and typed repository interfaces for dependency injection.
 *
 * Security Boundary:
 * - DatabaseManager, PrismaClient, driver adapters, and concrete repositories remain strictly internal.
 * - Raw repository factories (createRepositories) are not exposed publicly.
 * - Internal privileged query scopes (ProjectQueryScope, FindingQueryScope) are protected and not exported.
 * - Authorization policies provide declarative object-level security enforcement (Gate 3C).
 */

// Business Services & Trusted Composition Root (Gate 3D)
export {
  FindingService,
  ProjectService,
  AuditService,
  createDomainServices,
  generateProjectSlug,
} from './services/index.js';
export type {
  IProjectService,
  IFindingService,
  ITaskService,
  IAuditService,
  DomainServices,
  DomainServicesConfig,
  ProjectServiceInit,
  AuditServiceInit,
  ListFindingsFilterInput,
  ListProjectsFilterInput,
  ForceCloseFindingInput,
  ForceReopenFindingInput,
} from './services/index.js';

// Object-Level Authorization Policies & Actor Context (Gate 3C)
export {
  ActorContext,
  type ActorContextParams,
  type ProjectMembership,
  ProjectPolicy,
  FindingPolicy,
  TaskPolicy,
  AuditPolicy,
  type AuthzDecision,
  type ProjectAction,
  type FindingAction,
  type TaskAction,
  type AuditAction,
  type FindingAuthzContext,
  type TaskAuthzContext,
} from './policy/index.js';

// Domain Entities (Read-only projections)
export type {
  ProjectEntity,
  ProjectMemberEntity,
  FindingEntity,
  FindingEventEntity,
  RemediationTaskEntity,
  AuditEventEntity,
  AuthoritativeUserEntity,
  PaginatedResult,
} from './db/repositories/types.js';

// Repository Interfaces (Read-only contracts)
export type {
  IProjectRepository,
  IFindingRepository,
  ITaskRepository,
  IAuditRepository,
  IUserRepository,
  UserAuthEntity,
} from './db/repositories/types.js';

// Typed Mutation Input Data Contracts (Strict DTOs - no raw Prisma input types)
export type {
  CreateProjectRepoData,
  UpdateProjectRepoData,
  AddProjectMemberRepoData,
  CreateFindingRepoData,
  UpdateFindingRepoData,
  CreateFindingEventRepoData,
  CreateTaskRepoData,
  CreateAuditEventRepoData,
} from './db/repositories/types.js';
