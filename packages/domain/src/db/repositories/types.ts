import type {
  AuditEventCategory,
  FindingCategory,
  FindingEventType,
  FindingSeverity,
  FindingStatus,
  ProjectRole,
  RemediationTaskStatus,
} from '@secureflow/schemas';
import type { Prisma } from '../../generated/prisma/client.js';

/**
 * Common database client abstraction matching both PrismaClient and Prisma TransactionClient.
 */
export type PrismaDbClient = {
  project: Prisma.ProjectDelegate;
  projectMember: Prisma.ProjectMemberDelegate;
  finding: Prisma.FindingDelegate;
  findingEvent: Prisma.FindingEventDelegate;
  remediationTask: Prisma.RemediationTaskDelegate;
  auditEvent: Prisma.AuditEventDelegate;
};

// ============================================================================
// Domain Entities (Read-only projections)
// ============================================================================

export interface ProjectEntity {
  id: string;
  name: string;
  slug: string;
  description: string | null;
  isActive: boolean;
  createdById: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface ProjectMemberEntity {
  id: string;
  projectId: string;
  userId: string;
  role: ProjectRole;
  addedById: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface FindingEntity {
  id: string;
  projectId: string;
  title: string;
  description: string;
  severity: FindingSeverity;
  category: FindingCategory;
  cvssScore: number | null;
  status: FindingStatus;
  createdById: string;
  assignedToId: string | null;
  dueDate: Date | null;
  isDeleted: boolean;
  version: number;
  createdAt: Date;
  updatedAt: Date;
}

export interface FindingEventEntity {
  id: string;
  findingId: string;
  actorId: string;
  eventType: FindingEventType;
  previousStatus: string | null;
  newStatus: string | null;
  metadata: Record<string, unknown> | null;
  createdAt: Date;
}

export interface RemediationTaskEntity {
  id: string;
  findingId: string;
  assignedToId: string;
  assignedById: string;
  description: string;
  notes: string | null;
  status: RemediationTaskStatus;
  dueDate: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface AuditEventEntity {
  id: string;
  actorId: string | null;
  eventCategory: AuditEventCategory;
  eventType: string;
  resourceId: string | null;
  resourceType: string | null;
  beforeState: Record<string, unknown> | null;
  afterState: Record<string, unknown> | null;
  ipAddress: string | null;
  userAgent: string | null;
  createdAt: Date;
}

// ============================================================================
// Pagination & Query Scoping
// ============================================================================

export interface PaginatedResult<T> {
  items: T[];
  total: number;
  page: number;
  limit: number;
  totalPages: number;
}

/**
 * Internal Project Query Scope.
 * Governs project-level visibility. Must be constructed strictly by trusted domain policies
 * (Gate 3C) and never accepted raw from untrusted transport-layer inputs.
 */
export interface ProjectQueryScope {
  /**
   * Explicit list of project IDs the authenticated actor is a member of.
   * If empty or undefined and unrestricted is false, query returns zero results.
   */
  accessibleProjectIds?: string[];
  /**
   * If true, enables unconstrained project queries (organization-wide Admin access).
   * Must be set strictly by authoritative domain policies, never from untrusted client input.
   */
  unrestricted?: boolean;
  /**
   * Whether to include inactive (archived) projects. Defaults to false.
   */
  includeInactive?: boolean;
}

export interface ProjectFilter {
  scope: ProjectQueryScope;
  search?: string;
  page?: number;
  limit?: number;
}

/**
 * Internal Finding Query Scope.
 * Governs finding-level visibility and filtering. Must be constructed strictly by trusted
 * domain policies (Gate 3C) and never accepted raw from untrusted transport-layer inputs.
 */
export interface FindingQueryScope {
  /**
   * Projects the authenticated caller has access to.
   * If empty or undefined and unrestricted is false, query returns zero results.
   */
  accessibleProjectIds?: string[];
  /**
   * Filter findings assigned to this specific user (e.g. for Developer persona).
   * Must be constrained to accessible projects when evaluated.
   */
  assignedToUserId?: string;
  /**
   * If true, enables unconstrained finding queries (organization-wide Admin access).
   * Must be set strictly by authoritative domain policies, never from untrusted client input.
   */
  unrestricted?: boolean;
  /**
   * Invariant OLI-12: Soft-deleted findings are excluded from all queries unless the caller
   * is an Admin with explicit permission to view deleted records. Defaults to false.
   */
  includeDeleted?: boolean;
}

export interface FindingFilter {
  scope: FindingQueryScope;
  projectId?: string;
  status?: FindingStatus;
  severity?: FindingSeverity;
  category?: FindingCategory;
  assignedToId?: string;
  search?: string;
  page?: number;
  limit?: number;
}

export interface AuditEventFilter {
  eventCategory?: AuditEventCategory;
  eventType?: string;
  resourceId?: string;
  resourceType?: string;
  actorId?: string;
  fromTimestamp?: Date;
  toTimestamp?: Date;
  page?: number;
  limit?: number;
}

// ============================================================================
// Repository Input Data Interfaces (Typed DTOs - No arbitrary Prisma objects)
// ============================================================================

export interface CreateProjectRepoData {
  name: string;
  slug: string;
  description?: string | null;
  createdById: string;
}

export interface UpdateProjectRepoData {
  name?: string;
  description?: string | null;
  isActive?: boolean;
}

export interface AddProjectMemberRepoData {
  userId: string;
  role: ProjectRole;
  addedById: string;
}

export interface CreateFindingRepoData {
  projectId: string;
  title: string;
  description: string;
  severity: FindingSeverity;
  category: FindingCategory;
  cvssScore?: number | null;
  createdById: string;
  assignedToId?: string | null;
  dueDate?: Date | null;
}

export interface UpdateFindingRepoData {
  expectedVersion: number;
  title?: string;
  description?: string;
  severity?: FindingSeverity;
  category?: FindingCategory;
  cvssScore?: number | null;
  status?: FindingStatus;
  assignedToId?: string | null;
  dueDate?: Date | null;
  isDeleted?: boolean;
}

export interface CreateFindingEventRepoData {
  findingId: string;
  actorId: string;
  eventType: FindingEventType;
  previousStatus?: string | null;
  newStatus?: string | null;
  metadata?: Record<string, unknown> | null;
}

export interface CreateTaskRepoData {
  findingId: string;
  assignedToId: string;
  assignedById: string;
  description: string;
  dueDate?: Date | null;
}

export interface CreateAuditEventRepoData {
  actorId?: string | null;
  eventCategory: AuditEventCategory;
  eventType: string;
  resourceId?: string | null;
  resourceType?: string | null;
  beforeState?: Record<string, unknown> | null;
  afterState?: Record<string, unknown> | null;
  ipAddress?: string | null;
  userAgent?: string | null;
}

// ============================================================================
// Repository Interfaces
// ============================================================================

export interface IProjectRepository {
  findById(id: string, scope?: ProjectQueryScope): Promise<ProjectEntity | null>;
  findBySlug(slug: string, scope?: ProjectQueryScope): Promise<ProjectEntity | null>;
  findMany(filter: ProjectFilter): Promise<PaginatedResult<ProjectEntity>>;
  create(data: CreateProjectRepoData): Promise<ProjectEntity>;
  update(id: string, data: UpdateProjectRepoData): Promise<ProjectEntity>;
  addMember(projectId: string, data: AddProjectMemberRepoData): Promise<ProjectMemberEntity>;
  removeMember(projectId: string, userId: string): Promise<boolean>;
  getMembers(projectId: string): Promise<ProjectMemberEntity[]>;
  isMember(projectId: string, userId: string): Promise<boolean>;
}

export interface IFindingRepository {
  findById(id: string, scope?: FindingQueryScope): Promise<FindingEntity | null>;
  findMany(filter: FindingFilter): Promise<PaginatedResult<FindingEntity>>;
  create(data: CreateFindingRepoData): Promise<FindingEntity>;
  updateAtomic(id: string, data: UpdateFindingRepoData): Promise<FindingEntity>;
  softDelete(id: string, expectedVersion: number): Promise<FindingEntity>;
  addEvent(data: CreateFindingEventRepoData): Promise<FindingEventEntity>;
  getEvents(findingId: string): Promise<FindingEventEntity[]>;
}

export interface ITaskRepository {
  findById(id: string): Promise<RemediationTaskEntity | null>;
  findByFindingId(findingId: string): Promise<RemediationTaskEntity[]>;
  findActiveByFindingId(findingId: string): Promise<RemediationTaskEntity | null>;
  create(data: CreateTaskRepoData): Promise<RemediationTaskEntity>;
  updateNotes(id: string, notes: string | null): Promise<RemediationTaskEntity>;
  updateStatus(
    id: string,
    status: RemediationTaskStatus,
    notes?: string | null,
  ): Promise<RemediationTaskEntity>;
}

/**
 * Append-only Audit Repository Contract.
 *
 * Invariant: Audit records are strictly immutable at the application layer.
 * No update, modify, or delete methods are exposed by this interface or implementation.
 *
 * Note: This is an application-level immutability guarantee. Database-level permissions
 * (e.g. REVOKE UPDATE, DELETE ON audit_events), row-level security, and cryptographic tamper resistance
 * remain separate infrastructure and authorization concerns.
 */
export interface IAuditRepository {
  append(data: CreateAuditEventRepoData): Promise<AuditEventEntity>;
  query(filter: AuditEventFilter): Promise<PaginatedResult<AuditEventEntity>>;
}

/**
 * Container bundling all domain repositories for a given database client or transaction.
 */
export interface RepositoryContainer {
  projectRepo: IProjectRepository;
  findingRepo: IFindingRepository;
  taskRepo: ITaskRepository;
  auditRepo: IAuditRepository;
}
