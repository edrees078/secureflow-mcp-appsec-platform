/**
 * SecureFlow Domain Layer Entry Point.
 *
 * Public surface of @secureflow/domain exposing approved business services,
 * read-only domain entity types, and typed repository interfaces for dependency injection.
 *
 * Security Boundary:
 * - DatabaseManager, PrismaClient, driver adapters, and concrete repositories remain strictly internal.
 * - Raw repository factories (createRepositories) are not exposed publicly.
 * - Internal privileged query scopes (ProjectQueryScope, FindingQueryScope) are protected and not exported.
 */

// Business Services (Gate 3D will expand these)
export { FindingService, type CreateFindingDto } from './services/index.js';

// Domain Entities (Read-only projections)
export type {
  ProjectEntity,
  ProjectMemberEntity,
  FindingEntity,
  FindingEventEntity,
  RemediationTaskEntity,
  AuditEventEntity,
  PaginatedResult,
} from './db/repositories/types.js';

// Repository Interfaces (for Dependency Injection and testing)
export type {
  IProjectRepository,
  IFindingRepository,
  ITaskRepository,
  IAuditRepository,
  RepositoryContainer,
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

/**
 * Controlled Service Initialization Contract for Dependency Injection (Gate 3D).
 * Preserves a clean pathway for injecting repository containers and mock dependencies
 * into future domain services without exposing concrete database drivers or clients.
 */
export interface DomainServiceDependencies {
  readonly repositories: import('./db/repositories/types.js').RepositoryContainer;
}
