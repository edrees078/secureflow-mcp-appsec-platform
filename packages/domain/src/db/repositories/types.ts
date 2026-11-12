import type {
  AuditEventCategory,
  FindingCategory,
  FindingEventType,
  FindingSeverity,
  FindingStatus,
  GlobalRole,
  ProjectRole,
  RemediationTaskStatus,
} from '@secureflow/schemas';
import type { Prisma } from '../../generated/prisma/client.js';

/**
 * Common database client abstraction matching both PrismaClient and Prisma TransactionClient.
 */
export type PrismaDbClient = {
  user: Prisma.UserDelegate;
  userSession?: Prisma.UserSessionDelegate;
  oidcTransaction?: Prisma.OidcTransactionDelegate;
  project: Prisma.ProjectDelegate;
  projectMember: Prisma.ProjectMemberDelegate;
  finding: Prisma.FindingDelegate;
  findingEvent: Prisma.FindingEventDelegate;
  remediationTask: Prisma.RemediationTaskDelegate;
  auditEvent: Prisma.AuditEventDelegate;
  $queryRaw: <T = unknown>(query: TemplateStringsArray | Prisma.Sql, ...values: unknown[]) => Promise<T>;
  $executeRaw: (query: TemplateStringsArray | Prisma.Sql, ...values: unknown[]) => Promise<number>;
};

export interface UserAuthEntity {
  id: string;
  isActive: boolean;
  globalRole: GlobalRole;
}

export interface UserProfileEntity {
  id: string;
  sub: string;
  email: string;
  displayName: string;
  globalRole: GlobalRole;
  isActive: boolean;
  createdAt: Date;
  updatedAt: Date;
}

export interface UserSessionEntity {
  id: string;
  userId: string;
  tokenHash: string;
  csrfToken: string;
  oidcSid: string | null;
  ipAddress: string | null;
  userAgent: string | null;
  createdAt: Date;
  lastActivityAt: Date;
  idleExpiresAt: Date;
  expiresAt: Date;
  revokedAt: Date | null;
  revocationReason: string | null;
}

export interface OidcTransactionEntity {
  id: string;
  txnTokenHash: string;
  stateHash: string;
  nonce: string;
  codeVerifier: string;
  returnTo: string;
  createdAt: Date;
  expiresAt: Date;
  consumedAt: Date | null;
}

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
  search?: string | undefined;
  page?: number | undefined;
  limit?: number | undefined;
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
  accessibleProjectIds?: string[] | undefined;
  /**
   * Filter findings assigned to this specific user (e.g. for Developer persona).
   * Must be constrained to accessible projects when evaluated.
   */
  assignedToUserId?: string | undefined;
  /**
   * If true, enables unconstrained finding queries (organization-wide Admin access).
   * Must be set strictly by authoritative domain policies, never from untrusted client input.
   */
  unrestricted?: boolean | undefined;
  /**
   * Invariant OLI-12: Soft-deleted findings are excluded from all queries unless the caller
   * is an Admin with explicit permission to view deleted records. Defaults to false.
   */
  includeDeleted?: boolean | undefined;
}

export interface FindingFilter {
  scope: FindingQueryScope;
  projectId?: string | undefined;
  status?: FindingStatus | undefined;
  severity?: FindingSeverity | undefined;
  category?: FindingCategory | undefined;
  assignedToId?: string | undefined;
  search?: string | undefined;
  page?: number | undefined;
  limit?: number | undefined;
}

export interface AuditEventFilter {
  eventCategory?: AuditEventCategory | undefined;
  eventType?: string | undefined;
  resourceId?: string | undefined;
  resourceType?: string | undefined;
  actorId?: string | undefined;
  fromTimestamp?: Date | undefined;
  toTimestamp?: Date | undefined;
  page?: number | undefined;
  limit?: number | undefined;
}

// ============================================================================
// Repository Input Data Interfaces (Typed DTOs - No arbitrary Prisma objects)
// ============================================================================

export interface CreateProjectRepoData {
  name: string;
  slug: string;
  description?: string | null | undefined;
  createdById: string;
}

export interface UpdateProjectRepoData {
  name?: string | undefined;
  description?: string | null | undefined;
  isActive?: boolean | undefined;
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

export interface CreateUserRepoData {
  sub: string;
  email: string;
  displayName: string;
  globalRole: GlobalRole;
  isActive?: boolean;
}

export interface CreateUserSessionRepoData {
  userId: string;
  tokenHash: string;
  csrfToken?: string;
  oidcSid?: string | null;
  ipAddress?: string | null;
  userAgent?: string | null;
  lastActivityAt: Date;
  idleExpiresAt: Date;
  expiresAt: Date;
}

export interface CreateOidcTransactionRepoData {
  txnTokenHash: string;
  stateHash: string;
  nonce: string;
  codeVerifier: string;
  returnTo: string;
  expiresAt: Date;
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

  // --- Sub-Gate 3D.2 Lock Enhancements ---
  lockProject(id: string, mode?: 'SHARE' | 'UPDATE'): Promise<ProjectEntity | null>;
  lockMember(projectId: string, userId: string, mode?: 'SHARE' | 'UPDATE'): Promise<ProjectMemberEntity | null>;
  lockMembers(projectId: string, userIds: string[], mode?: 'SHARE' | 'UPDATE'): Promise<ProjectMemberEntity[]>;
  getMemberRole(projectId: string, userId: string): Promise<ProjectRole | null>;
}

export interface AuthoritativeUserEntity {
  id: string;
  isActive: boolean;
  globalRole: GlobalRole;
  memberships: Array<{
    projectId: string;
    role: ProjectRole;
  }>;
}

export interface IUserRepository {
  findById(id: string): Promise<UserAuthEntity | null>;
  findAuthoritativeUser(id: string): Promise<AuthoritativeUserEntity | null>;
  lockUser(id: string, mode?: 'SHARE' | 'UPDATE'): Promise<UserAuthEntity | null>;
  lockUsers(userIds: string[], mode?: 'SHARE' | 'UPDATE'): Promise<Map<string, UserAuthEntity>>;
  deactivateUser(id: string): Promise<UserAuthEntity>;
  updateGlobalRole(id: string, role: GlobalRole): Promise<UserAuthEntity>;

  // --- Sub-Gate 4B.1 Authentication & Bootstrap Extensions ---
  findBySub?(sub: string): Promise<UserProfileEntity | null>;
  findByEmail?(email: string): Promise<UserProfileEntity | null>;
  findProfileById?(id: string): Promise<UserProfileEntity | null>;
  lockUserBySub?(sub: string, mode?: 'SHARE' | 'UPDATE'): Promise<UserProfileEntity | null>;
  lockUserByEmail?(email: string, mode?: 'SHARE' | 'UPDATE'): Promise<UserProfileEntity | null>;
  createUser?(data: CreateUserRepoData): Promise<UserProfileEntity>;
  updateDisplayName?(id: string, displayName: string): Promise<UserProfileEntity>;
  acquireBootstrapAdvisoryLock?(): Promise<void>;
  acquireIdentityProvisioningLocks?(sub: string, normalizedEmail: string): Promise<void>;
  countActiveAdmins?(): Promise<number>;
}

export interface ISessionRepository {
  create(data: CreateUserSessionRepoData): Promise<UserSessionEntity>;
  findByTokenHash(tokenHash: string): Promise<UserSessionEntity | null>;
  findById(id: string): Promise<UserSessionEntity | null>;
  listActiveByUserId(userId: string, now?: Date): Promise<UserSessionEntity[]>;
  touchActivity(id: string, lastActivityAt: Date, idleExpiresAt: Date): Promise<UserSessionEntity>;
  revokeById(id: string, reason: string, revokedAt?: Date): Promise<boolean>;
  revokeByTokenHash(tokenHash: string, reason: string, revokedAt?: Date): Promise<UserSessionEntity | null>;
  revokeAllActiveForUser(userId: string, reason: string, revokedAt?: Date): Promise<number>;
  revokeActiveByOidcSid(oidcSid: string, reason: string, revokedAt?: Date): Promise<number>;
}

export interface IOidcTransactionRepository {
  create(data: CreateOidcTransactionRepoData): Promise<OidcTransactionEntity>;
  findByTokenHash(txnTokenHash: string): Promise<OidcTransactionEntity | null>;
  consumeAtomically(txnTokenHash: string, now?: Date): Promise<OidcTransactionEntity | null>;
  deleteExpired(before: Date): Promise<number>;
}

export interface IFindingRepository {
  findById(id: string, scope?: FindingQueryScope): Promise<FindingEntity | null>;
  findMany(filter: FindingFilter): Promise<PaginatedResult<FindingEntity>>;
  create(data: CreateFindingRepoData): Promise<FindingEntity>;
  updateAtomic(id: string, data: UpdateFindingRepoData): Promise<FindingEntity>;
  softDelete(id: string, expectedVersion: number): Promise<FindingEntity>;
  addEvent(data: CreateFindingEventRepoData): Promise<FindingEventEntity>;
  getEvents(findingId: string): Promise<FindingEventEntity[]>;
  lockFinding(id: string, mode?: 'SHARE' | 'UPDATE'): Promise<FindingEntity | null>;
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
  lockTask(id: string, mode?: 'SHARE' | 'UPDATE'): Promise<RemediationTaskEntity | null>;
  lockActiveTaskByFindingId(findingId: string, mode?: 'SHARE' | 'UPDATE'): Promise<RemediationTaskEntity | null>;
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
  userRepo: IUserRepository;
  sessionRepo?: ISessionRepository;
  oidcTransactionRepo?: IOidcTransactionRepository;
}
