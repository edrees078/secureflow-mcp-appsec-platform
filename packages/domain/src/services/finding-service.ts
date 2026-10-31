import {
  CreateFindingInputSchema,
  TriageFindingInputSchema,
  AssignFindingInputSchema,
  SubmitRemediationInputSchema,
  VerifyFindingInputSchema,
  CloseFindingInputSchema,
  ForceCloseFindingInputSchema,
  ForceReopenFindingInputSchema,
  SoftDeleteFindingInputSchema,
  UpdateFindingMetadataInputSchema,
  ListFindingsFilterInputSchema,
  type CreateFindingInput,
  type TriageFindingInput,
  type AssignFindingInput,
  type SubmitRemediationInput,
  type VerifyFindingInput,
  type CloseFindingInput,
  type ForceCloseFindingInput,
  type ForceReopenFindingInput,
  type UpdateFindingMetadataInput,
  type SoftDeleteFindingInput,
  type ListFindingsFilterInput,
} from '@secureflow/schemas';
import {
  ConcurrencyConflictError,
  EntityNotFoundError,
  ForbiddenError,
  InvalidStateTransitionError,
  SecureFlowError,
} from '@secureflow/shared';

import { ActorContext } from '../policy/actor-context.js';
import { FindingPolicy } from '../policy/finding-policy.js';
import { TaskPolicy } from '../policy/task-policy.js';
import { deriveFindingQueryScope } from '../policy/query-scopes.js';
import type {
  FindingEntity,
  PaginatedResult,
  RepositoryContainer,
  UpdateFindingRepoData,
} from '../db/repositories/types.js';
import { DatabaseManager } from '../db/database-manager.js';
import type {
  IFindingService,
} from './types.js';
import { handleDatabaseConcurrencyError } from './concurrency-handler.js';
import { isAuthorizedTestPersistence } from './persistence-token.js';

export type FindingServiceInit = DatabaseManager | undefined;

/**
 * Finding Domain Service.
 *
 * Implements IFindingService mediating all business operations on findings.
 * Every method mandates an authenticated ActorContext as its first parameter.
 *
 * Sub-Gate 3D.3 Implementation Scope:
 * 1. createFinding (Analyst-scoped, Level 0 -> Level 1 -> Level 2 locking, atomic FindingEvent + AuditEvent)
 * 2. getFinding (Authoritative DB check, existence hiding 404)
 * 3. listFindings (Database-filtered query scopes, runtime ListFindingsFilterInputSchema validation, persona isolation)
 * 4. updateFindingMetadata (Analyst-scoped, preliminary safe lookup -> Level 0 -> 1 -> 2 -> 3 locking, OCC compare-and-increment, audit diff)
 * 5. triageFinding (OPEN -> TRIAGED, preliminary safe lookup -> Level 0 -> 1 -> 2 -> 3 locking, OCC compare-and-increment, atomic audit)
 *
 * Canonical Database Row Lock Hierarchy:
 * Level 0 (users) -> Level 1 (projects) -> Level 2 (project_members) -> Level 3 (findings) -> Level 4 (remediation_tasks)
 *
 * All other methods remain explicit NOT_IMPLEMENTED (501) stubs for future sub-gates.
 */
export class FindingService implements IFindingService {
  private readonly db: DatabaseManager | undefined;
  private readonly directRepos: RepositoryContainer | undefined;

  public constructor(db?: DatabaseManager);
  public constructor(testInit: unknown);
  public constructor(init?: unknown) {
    if (!init) {
      this.db = undefined;
      this.directRepos = undefined;
      return;
    }

    if (init instanceof DatabaseManager) {
      this.db = init;
      this.directRepos = undefined;
    } else if (isAuthorizedTestPersistence(init)) {
      if (
        !init.repositories.findingRepo ||
        !init.repositories.projectRepo ||
        !init.repositories.userRepo ||
        !init.repositories.auditRepo
      ) {
        throw new SecureFlowError(
          'FindingService initialization failed: incomplete repository container',
          'SERVICE_INITIALIZATION_ERROR',
          500,
        );
      }
      this.directRepos = init.repositories;
      this.db = undefined;
    } else {
      throw new SecureFlowError(
        'Direct repository injection is prohibited outside @secureflow/domain/testing',
        'UNAUTHORIZED_PERSISTENCE_INJECTION',
        500,
      );
    }
  }

  private getRepos(): RepositoryContainer {
    if (this.directRepos) {
      return this.directRepos;
    }
    if (this.db) {
      return this.db.getRepositories();
    }
    throw new SecureFlowError(
      '[NOT_IMPLEMENTED] FindingService requires DatabaseManager or test repositories',
      'NOT_IMPLEMENTED',
      501,
    );
  }

  private async executeTransaction<T>(
    operation: (repos: RepositoryContainer) => Promise<T>,
  ): Promise<T> {
    if (this.directRepos) {
      return await operation(this.directRepos);
    }
    if (this.db) {
      return await this.db.runTransaction(operation);
    }
    throw new SecureFlowError(
      '[NOT_IMPLEMENTED] FindingService requires DatabaseManager or test repositories',
      'NOT_IMPLEMENTED',
      501,
    );
  }

  private async getAuthoritativeActor(
    actor: ActorContext,
    userRepo: RepositoryContainer['userRepo'],
  ): Promise<ActorContext> {
    const authUser = await userRepo.findAuthoritativeUser(actor.id);
    if (!authUser || !authUser.isActive) {
      throw new ForbiddenError('User account is deactivated or does not exist');
    }
    return new ActorContext({
      id: authUser.id,
      globalRole: authUser.globalRole,
      isActive: authUser.isActive,
      memberships: authUser.memberships,
    });
  }

  // ==========================================================================
  // Authorized IFindingService Operations (Sub-Gate 3D.3)
  // ==========================================================================

  public async createFinding(
    actor: ActorContext,
    input: CreateFindingInput,
  ): Promise<FindingEntity> {
    if (!this.db && !this.directRepos) {
      throw new SecureFlowError(
        '[NOT_IMPLEMENTED] FindingService uninitialized or operation not implemented',
        'NOT_IMPLEMENTED',
        501,
      );
    }

    const parsed = CreateFindingInputSchema.parse(input);

    try {
      return await this.executeTransaction(async (repos) => {
        // 1. Authoritative identity and role revalidation
        const freshActor = await this.getAuthoritativeActor(actor, repos.userRepo);

        // 2. Pre-transaction object-level authorization (Analyst-only per NEG-13 and NEG-04)
        FindingPolicy.authorize(freshActor, 'create', { projectId: parsed.projectId });

        // 3. Level 0: Deterministic row lock on actor
        const userMap = await repos.userRepo.lockUsers([actor.id], 'SHARE');
        const user = userMap.get(actor.id);
        if (!user || !user.isActive) {
          throw new ForbiddenError('Actor account is deactivated');
        }

        // 4. Level 1: Row lock on target project (must exist)
        const lockedProject = await repos.projectRepo.lockProject(parsed.projectId, 'SHARE');
        if (!lockedProject) {
          throw new EntityNotFoundError('Project not found');
        }

        // 5. Level 2: Row lock on membership
        const lockedMember = await repos.projectRepo.lockMember(parsed.projectId, actor.id, 'SHARE');
        if (!lockedMember) {
          throw new EntityNotFoundError('Project not found');
        }
        if (lockedMember.role !== 'ANALYST') {
          throw new ForbiddenError('Caller lacks Analyst role in project');
        }

        // Project active status checked AFTER membership verification (existence hiding for archived foreign projects)
        if (!lockedProject.isActive) {
          throw new ForbiddenError('Project is archived and cannot receive new findings');
        }

        // 6. Persist finding in OPEN status with version 1
        const finding = await repos.findingRepo.create({
          projectId: parsed.projectId,
          title: parsed.title,
          description: parsed.description,
          severity: parsed.severity,
          category: parsed.category,
          cvssScore: parsed.cvssScore !== undefined && parsed.cvssScore !== null ? parsed.cvssScore : null,
          createdById: actor.id,
          assignedToId: null,
          dueDate: parsed.dueDate ? new Date(parsed.dueDate) : null,
        });

        // 7. Atomic lifecycle event creation (CREATED)
        await repos.findingRepo.addEvent({
          findingId: finding.id,
          actorId: actor.id,
          eventType: 'CREATED',
          previousStatus: null,
          newStatus: 'OPEN',
          metadata: {
            title: finding.title,
            severity: finding.severity,
            category: finding.category,
            cvssScore: finding.cvssScore,
          },
        });

        // 8. Atomic application audit event (finding.created)
        await repos.auditRepo.append({
          actorId: actor.id,
          eventCategory: 'FINDING',
          eventType: 'finding.created',
          resourceId: finding.id,
          resourceType: 'finding',
          beforeState: null,
          afterState: {
            id: finding.id,
            projectId: finding.projectId,
            title: finding.title,
            severity: finding.severity,
            category: finding.category,
            status: finding.status,
            version: finding.version,
          },
        });

        return finding;
      });
    } catch (err) {
      handleDatabaseConcurrencyError(err);
    }
  }

  public async getFinding(actor: ActorContext, findingId: string): Promise<FindingEntity> {
    if (!this.db && !this.directRepos) {
      throw new SecureFlowError(
        '[NOT_IMPLEMENTED] FindingService uninitialized or operation not implemented',
        'NOT_IMPLEMENTED',
        501,
      );
    }

    try {
      const repos = this.getRepos();
      const freshActor = await this.getAuthoritativeActor(actor, repos.userRepo);
      const scope = deriveFindingQueryScope(freshActor);

      const finding = await repos.findingRepo.findById(findingId, scope);
      if (!finding) {
        throw new EntityNotFoundError('Finding not found');
      }

      // Defense-in-depth authorization check enforcing existence hiding
      FindingPolicy.authorize(freshActor, 'view', {
        finding,
        projectId: finding.projectId,
      });

      return finding;
    } catch (err) {
      handleDatabaseConcurrencyError(err);
    }
  }

  public async listFindings(
    actor: ActorContext,
    filter?: ListFindingsFilterInput,
  ): Promise<PaginatedResult<FindingEntity>> {
    if (!this.db && !this.directRepos) {
      throw new SecureFlowError(
        '[NOT_IMPLEMENTED] FindingService uninitialized or operation not implemented',
        'NOT_IMPLEMENTED',
        501,
      );
    }

    const parsedFilter = filter !== undefined ? ListFindingsFilterInputSchema.parse(filter) : undefined;

    try {
      const repos = this.getRepos();
      const freshActor = await this.getAuthoritativeActor(actor, repos.userRepo);
      const scope = deriveFindingQueryScope(freshActor, {
        includeDeletedFindings: parsedFilter?.includeDeleted,
      });

      return await repos.findingRepo.findMany({
        scope,
        projectId: parsedFilter?.projectId,
        status: parsedFilter?.status,
        severity: parsedFilter?.severity,
        category: parsedFilter?.category,
        assignedToId: parsedFilter?.assignedToId,
        search: parsedFilter?.search,
        page: parsedFilter?.page ?? 1,
        limit: parsedFilter?.limit ?? 25,
      });
    } catch (err) {
      handleDatabaseConcurrencyError(err);
    }
  }

  public async updateFindingMetadata(
    actor: ActorContext,
    findingId: string,
    input: UpdateFindingMetadataInput,
  ): Promise<FindingEntity> {
    if (!this.db && !this.directRepos) {
      throw new SecureFlowError(
        '[NOT_IMPLEMENTED] FindingService uninitialized or operation not implemented',
        'NOT_IMPLEMENTED',
        501,
      );
    }

    const parsed = UpdateFindingMetadataInputSchema.parse(input);

    try {
      return await this.executeTransaction(async (repos) => {
        // Preliminary safe lookup to determine targetProjectId before locking.
        // If finding does not exist or is soft-deleted, fail closed with 404 (existence hiding).
        const candidate = await repos.findingRepo.findById(findingId, { unrestricted: true });
        if (!candidate || candidate.isDeleted) {
          throw new EntityNotFoundError('Finding not found');
        }
        const targetProjectId = candidate.projectId;

        // Level 0: Deterministic row lock on actor
        const userMap = await repos.userRepo.lockUsers([actor.id], 'SHARE');
        const user = userMap.get(actor.id);
        if (!user || !user.isActive) {
          throw new ForbiddenError('Actor account is deactivated');
        }

        // Level 1: Row lock on target project (must exist)
        const lockedProject = await repos.projectRepo.lockProject(targetProjectId, 'SHARE');
        if (!lockedProject) {
          throw new EntityNotFoundError('Finding not found');
        }

        // Level 2: Row lock on project membership (establishing the exact linearization point)
        let freshActor: ActorContext;
        if (user.globalRole === 'ADMIN') {
          const lockedMember = await repos.projectRepo.lockMember(targetProjectId, actor.id, 'SHARE');
          freshActor = new ActorContext({
            id: user.id,
            globalRole: user.globalRole,
            isActive: user.isActive,
            memberships: lockedMember ? [{ projectId: targetProjectId, role: lockedMember.role }] : [],
          });
        } else {
          const lockedMember = await repos.projectRepo.lockMember(targetProjectId, actor.id, 'SHARE');
          if (!lockedMember) {
            // Existence hiding: non-members receive 404
            throw new EntityNotFoundError('Finding not found');
          }
          freshActor = new ActorContext({
            id: user.id,
            globalRole: user.globalRole,
            isActive: user.isActive,
            memberships: [{ projectId: targetProjectId, role: lockedMember.role }],
          });
        }

        // Project active status checked AFTER membership verification (existence hiding for archived foreign projects)
        if (!lockedProject.isActive) {
          throw new ForbiddenError('Project is archived and cannot be modified');
        }

        // Level 3: Row lock on finding for update
        const lockedFinding = await repos.findingRepo.lockFinding(findingId, 'UPDATE');
        if (!lockedFinding || lockedFinding.isDeleted) {
          throw new EntityNotFoundError('Finding not found');
        }

        // Re-validate finding under lock: verify finding still belongs to targetProjectId
        if (lockedFinding.projectId !== targetProjectId) {
          throw new EntityNotFoundError('Finding not found');
        }

        // Enforce FindingPolicy update_metadata permission under lock
        FindingPolicy.authorize(freshActor, 'update_metadata', {
          finding: lockedFinding,
          projectId: lockedFinding.projectId,
        });

        // Atomic OCC compare-and-increment
        const updateData: UpdateFindingRepoData = {
          expectedVersion: parsed.expectedVersion,
        };
        if (parsed.title !== undefined) updateData.title = parsed.title;
        if (parsed.description !== undefined) updateData.description = parsed.description;
        if (parsed.severity !== undefined) updateData.severity = parsed.severity;
        if (parsed.category !== undefined) updateData.category = parsed.category;
        if (parsed.cvssScore !== undefined) updateData.cvssScore = parsed.cvssScore;
        if (parsed.dueDate !== undefined) updateData.dueDate = parsed.dueDate ? new Date(parsed.dueDate) : null;

        const updated = await repos.findingRepo.updateAtomic(findingId, updateData);

        // Add FindingEvent (UPDATED)
        await repos.findingRepo.addEvent({
          findingId: updated.id,
          actorId: actor.id,
          eventType: 'UPDATED',
          previousStatus: lockedFinding.status,
          newStatus: updated.status,
          metadata: {
            changes: {
              title: parsed.title !== undefined ? { before: lockedFinding.title, after: updated.title } : undefined,
              severity: parsed.severity !== undefined ? { before: lockedFinding.severity, after: updated.severity } : undefined,
              category: parsed.category !== undefined ? { before: lockedFinding.category, after: updated.category } : undefined,
              cvssScore: parsed.cvssScore !== undefined ? { before: lockedFinding.cvssScore, after: updated.cvssScore } : undefined,
            },
          },
        });

        // Append AuditEvent (finding.metadata_updated)
        await repos.auditRepo.append({
          actorId: actor.id,
          eventCategory: 'FINDING',
          eventType: 'finding.metadata_updated',
          resourceId: updated.id,
          resourceType: 'finding',
          beforeState: {
            version: lockedFinding.version,
            title: lockedFinding.title,
            severity: lockedFinding.severity,
            category: lockedFinding.category,
            cvssScore: lockedFinding.cvssScore,
          },
          afterState: {
            version: updated.version,
            title: updated.title,
            severity: updated.severity,
            category: updated.category,
            cvssScore: updated.cvssScore,
          },
        });

        return updated;
      });
    } catch (err) {
      handleDatabaseConcurrencyError(err);
    }
  }

  public async triageFinding(
    actor: ActorContext,
    findingId: string,
    input: TriageFindingInput,
  ): Promise<FindingEntity> {
    if (!this.db && !this.directRepos) {
      throw new SecureFlowError(
        '[NOT_IMPLEMENTED] FindingService uninitialized or operation not implemented',
        'NOT_IMPLEMENTED',
        501,
      );
    }

    const parsed = TriageFindingInputSchema.parse(input);

    try {
      return await this.executeTransaction(async (repos) => {
        // Preliminary safe lookup to determine targetProjectId before locking.
        // If finding does not exist or is soft-deleted, fail closed with 404 (existence hiding).
        const candidate = await repos.findingRepo.findById(findingId, { unrestricted: true });
        if (!candidate || candidate.isDeleted) {
          throw new EntityNotFoundError('Finding not found');
        }
        const targetProjectId = candidate.projectId;

        // Level 0: Deterministic row lock on actor
        const userMap = await repos.userRepo.lockUsers([actor.id], 'SHARE');
        const user = userMap.get(actor.id);
        if (!user || !user.isActive) {
          throw new ForbiddenError('Actor account is deactivated');
        }

        // Level 1: Row lock on target project (must exist)
        const lockedProject = await repos.projectRepo.lockProject(targetProjectId, 'SHARE');
        if (!lockedProject) {
          throw new EntityNotFoundError('Finding not found');
        }

        // Level 2: Row lock on project membership (establishing the exact linearization point)
        let freshActor: ActorContext;
        if (user.globalRole === 'ADMIN') {
          const lockedMember = await repos.projectRepo.lockMember(targetProjectId, actor.id, 'SHARE');
          freshActor = new ActorContext({
            id: user.id,
            globalRole: user.globalRole,
            isActive: user.isActive,
            memberships: lockedMember ? [{ projectId: targetProjectId, role: lockedMember.role }] : [],
          });
        } else {
          const lockedMember = await repos.projectRepo.lockMember(targetProjectId, actor.id, 'SHARE');
          if (!lockedMember) {
            // Existence hiding: non-members receive 404
            throw new EntityNotFoundError('Finding not found');
          }
          freshActor = new ActorContext({
            id: user.id,
            globalRole: user.globalRole,
            isActive: user.isActive,
            memberships: [{ projectId: targetProjectId, role: lockedMember.role }],
          });
        }

        // Project active status checked AFTER membership verification (existence hiding for archived foreign projects)
        if (!lockedProject.isActive) {
          throw new ForbiddenError('Project is archived and cannot be modified');
        }

        // Level 3: Row lock on finding for update
        const lockedFinding = await repos.findingRepo.lockFinding(findingId, 'UPDATE');
        if (!lockedFinding || lockedFinding.isDeleted) {
          throw new EntityNotFoundError('Finding not found');
        }

        // Re-validate finding under lock: verify finding still belongs to targetProjectId
        if (lockedFinding.projectId !== targetProjectId) {
          throw new EntityNotFoundError('Finding not found');
        }

        // Enforce FindingPolicy triage permission under lock
        FindingPolicy.authorize(freshActor, 'triage', {
          finding: lockedFinding,
          projectId: lockedFinding.projectId,
        });

        // Optimistic Concurrency Control (OCC) version check under Level 3 lock
        if (lockedFinding.version !== parsed.expectedVersion) {
          throw new ConcurrencyConflictError(
            `Optimistic concurrency conflict on Finding '${findingId}'. Expected version ${parsed.expectedVersion}, but found version ${lockedFinding.version}.`,
            lockedFinding.version,
            parsed.expectedVersion,
          );
        }

        // Lifecycle state machine invariant: only OPEN findings can transition to TRIAGED
        if (lockedFinding.status !== 'OPEN') {
          throw new InvalidStateTransitionError(
            `Cannot triage finding '${findingId}': current status is '${lockedFinding.status}', expected 'OPEN'`,
            lockedFinding.status,
            'TRIAGED',
          );
        }

        // Atomic OCC compare-and-increment to TRIAGED
        const updateData: UpdateFindingRepoData = {
          expectedVersion: parsed.expectedVersion,
          status: 'TRIAGED',
        };
        if (parsed.severity !== undefined) updateData.severity = parsed.severity;
        if (parsed.category !== undefined) updateData.category = parsed.category;
        if (parsed.cvssScore !== undefined) updateData.cvssScore = parsed.cvssScore;
        if (parsed.dueDate !== undefined) updateData.dueDate = parsed.dueDate ? new Date(parsed.dueDate) : null;

        const updated = await repos.findingRepo.updateAtomic(findingId, updateData);

        // Add FindingEvent (STATUS_CHANGED: OPEN -> TRIAGED)
        await repos.findingRepo.addEvent({
          findingId: updated.id,
          actorId: actor.id,
          eventType: 'STATUS_CHANGED',
          previousStatus: 'OPEN',
          newStatus: 'TRIAGED',
          metadata: {
            severity: parsed.severity ?? lockedFinding.severity,
            category: parsed.category ?? lockedFinding.category,
            cvssScore: parsed.cvssScore !== undefined ? parsed.cvssScore : lockedFinding.cvssScore,
          },
        });

        // Append AuditEvent (finding.triaged)
        await repos.auditRepo.append({
          actorId: actor.id,
          eventCategory: 'FINDING',
          eventType: 'finding.triaged',
          resourceId: updated.id,
          resourceType: 'finding',
          beforeState: {
            status: 'OPEN',
            version: lockedFinding.version,
          },
          afterState: {
            status: 'TRIAGED',
            version: updated.version,
          },
        });

        return updated;
      });
    } catch (err) {
      handleDatabaseConcurrencyError(err);
    }
  }

  // ==========================================================================
  // Future Gate 3D Stubs (Scheduled for Sub-Gates 3D.4 through 3D.6)
  // ==========================================================================

  public async assignFinding(
    actor: ActorContext,
    findingId: string,
    input: AssignFindingInput,
  ): Promise<FindingEntity> {
    if (!this.db && !this.directRepos) {
      throw new SecureFlowError(
        '[NOT_IMPLEMENTED] FindingService uninitialized or operation not implemented',
        'NOT_IMPLEMENTED',
        501,
      );
    }

    const parsed = AssignFindingInputSchema.parse(input);

    try {
      return await this.executeTransaction(async (repos) => {
        // Safe preliminary lookup
        const candidate = await repos.findingRepo.findById(findingId, { unrestricted: true });
        if (!candidate || candidate.isDeleted) {
          throw new EntityNotFoundError('Finding not found');
        }
        const targetProjectId = candidate.projectId;

        // Level 0: Deterministic row locks on actor and target assignee in ascending lexical order
        const userIds = Array.from(new Set([actor.id, parsed.assignedToId])).sort();
        const userMap = await repos.userRepo.lockUsers(userIds, 'SHARE');
        const actorUser = userMap.get(actor.id);
        if (!actorUser || !actorUser.isActive) {
          throw new ForbiddenError('Actor account is deactivated');
        }
        const assigneeUser = userMap.get(parsed.assignedToId);
        if (!assigneeUser || !assigneeUser.isActive) {
          throw new ForbiddenError('Assignee account is deactivated or does not exist');
        }

        // Level 1: Row lock on target project
        const lockedProject = await repos.projectRepo.lockProject(targetProjectId, 'SHARE');
        if (!lockedProject) {
          throw new EntityNotFoundError('Finding not found');
        }

        // Level 2: Row locks on project memberships (establishing exact linearization point)
        let freshActor: ActorContext;
        if (actorUser.globalRole === 'ADMIN') {
          const lockedMember = await repos.projectRepo.lockMember(targetProjectId, actor.id, 'SHARE');
          freshActor = new ActorContext({
            id: actorUser.id,
            globalRole: actorUser.globalRole,
            isActive: actorUser.isActive,
            memberships: lockedMember ? [{ projectId: targetProjectId, role: lockedMember.role }] : [],
          });
        } else {
          const lockedActorMember = await repos.projectRepo.lockMember(targetProjectId, actor.id, 'SHARE');
          if (!lockedActorMember) {
            // Existence hiding: unauthorized caller receives generic 404
            throw new EntityNotFoundError('Finding not found');
          }
          freshActor = new ActorContext({
            id: actorUser.id,
            globalRole: actorUser.globalRole,
            isActive: actorUser.isActive,
            memberships: [{ projectId: targetProjectId, role: lockedActorMember.role }],
          });
        }

        // Project active status checked strictly AFTER membership verification
        // Existence hiding: non-members have already been rejected with 404 above; only authorized members receive 403
        if (!lockedProject.isActive) {
          throw new ForbiddenError('Project is archived and cannot be modified');
        }

        // Verify target assignee is an active Developer member of target project
        const lockedAssigneeMember = await repos.projectRepo.lockMember(targetProjectId, parsed.assignedToId, 'SHARE');
        if (!lockedAssigneeMember) {
          throw new ForbiddenError('Target developer is not a member of the project');
        }
        if (lockedAssigneeMember.role !== 'DEVELOPER') {
          throw new ForbiddenError('Target assignee must have DEVELOPER role in the project');
        }

        // Level 3: Row lock on finding
        const lockedFinding = await repos.findingRepo.lockFinding(findingId, 'UPDATE');
        if (!lockedFinding || lockedFinding.isDeleted || lockedFinding.projectId !== targetProjectId) {
          throw new EntityNotFoundError('Finding not found');
        }

        // Policy check for assign action (Analyst-scoped)
        FindingPolicy.authorize(freshActor, 'assign', {
          finding: lockedFinding,
          projectId: lockedFinding.projectId,
        });

        // Optimistic Concurrency Control (OCC) version check under Level 3 lock
        if (lockedFinding.version !== parsed.expectedVersion) {
          throw new ConcurrencyConflictError(
            `Optimistic concurrency conflict on Finding '${findingId}'. Expected version ${parsed.expectedVersion}, but found version ${lockedFinding.version}.`,
            lockedFinding.version,
            parsed.expectedVersion,
          );
        }

        // Lifecycle invariant: Finding status must be TRIAGED or REOPENED
        if (lockedFinding.status !== 'TRIAGED' && lockedFinding.status !== 'REOPENED') {
          throw new InvalidStateTransitionError(
            `Cannot assign finding '${findingId}': current status is '${lockedFinding.status}', expected 'TRIAGED' or 'REOPENED'`,
            lockedFinding.status,
            'IN_PROGRESS',
          );
        }

        // Check for existing active remediation task (partial unique index invariant)
        const activeTask = await repos.taskRepo.findActiveByFindingId(findingId);
        if (activeTask) {
          throw new InvalidStateTransitionError(
            `Cannot assign finding '${findingId}': finding already has an active remediation task '${activeTask.id}'`,
            lockedFinding.status,
            'IN_PROGRESS',
          );
        }

        // Atomic OCC compare-and-increment on Finding
        const updatedFinding = await repos.findingRepo.updateAtomic(findingId, {
          expectedVersion: parsed.expectedVersion,
          status: 'IN_PROGRESS',
          assignedToId: parsed.assignedToId,
          dueDate: parsed.dueDate !== undefined ? (parsed.dueDate ? new Date(parsed.dueDate) : null) : lockedFinding.dueDate,
        });

        // Create RemediationTask in PENDING status
        const newTask = await repos.taskRepo.create({
          findingId,
          assignedToId: parsed.assignedToId,
          assignedById: actor.id,
          description: parsed.taskDescription,
          dueDate: parsed.dueDate ? new Date(parsed.dueDate) : (lockedFinding.dueDate ?? null),
        });

        // Add FindingEvent (ASSIGNED)
        await repos.findingRepo.addEvent({
          findingId: updatedFinding.id,
          actorId: actor.id,
          eventType: 'ASSIGNED',
          previousStatus: lockedFinding.status,
          newStatus: 'IN_PROGRESS',
          metadata: {
            assignedToId: parsed.assignedToId,
            taskId: newTask.id,
            taskDescription: parsed.taskDescription,
          },
        });

        // Append AuditEvents
        await repos.auditRepo.append({
          actorId: actor.id,
          eventCategory: 'FINDING',
          eventType: 'finding.assigned',
          resourceId: updatedFinding.id,
          resourceType: 'finding',
          beforeState: {
            status: lockedFinding.status,
            assignedToId: lockedFinding.assignedToId,
            version: lockedFinding.version,
          },
          afterState: {
            status: 'IN_PROGRESS',
            assignedToId: updatedFinding.assignedToId,
            version: updatedFinding.version,
            taskId: newTask.id,
          },
        });

        await repos.auditRepo.append({
          actorId: actor.id,
          eventCategory: 'TASK',
          eventType: 'task.created',
          resourceId: newTask.id,
          resourceType: 'remediation_task',
          beforeState: null,
          afterState: {
            id: newTask.id,
            findingId: newTask.findingId,
            assignedToId: newTask.assignedToId,
            assignedById: newTask.assignedById,
            status: newTask.status,
          },
        });

        return updatedFinding;
      });
    } catch (err) {
      handleDatabaseConcurrencyError(err);
    }
  }

  public async submitRemediation(
    actor: ActorContext,
    findingId: string,
    input: SubmitRemediationInput,
  ): Promise<FindingEntity> {
    if (!this.db && !this.directRepos) {
      throw new SecureFlowError(
        '[NOT_IMPLEMENTED] FindingService uninitialized or operation not implemented',
        'NOT_IMPLEMENTED',
        501,
      );
    }

    const parsed = SubmitRemediationInputSchema.parse(input);

    try {
      return await this.executeTransaction(async (repos) => {
        // Safe preliminary lookup
        const candidate = await repos.findingRepo.findById(findingId, { unrestricted: true });
        if (!candidate || candidate.isDeleted) {
          throw new EntityNotFoundError('Finding not found');
        }
        const targetProjectId = candidate.projectId;

        // Level 0: Deterministic row lock on actor
        const userMap = await repos.userRepo.lockUsers([actor.id], 'SHARE');
        const user = userMap.get(actor.id);
        if (!user || !user.isActive) {
          throw new ForbiddenError('Actor account is deactivated');
        }

        // Level 1: Row lock on target project
        const lockedProject = await repos.projectRepo.lockProject(targetProjectId, 'SHARE');
        if (!lockedProject) {
          throw new EntityNotFoundError('Finding not found');
        }

        // Level 2: Row lock on project membership (establishing exact linearization point)
        let freshActor: ActorContext;
        if (user.globalRole === 'ADMIN') {
          const lockedMember = await repos.projectRepo.lockMember(targetProjectId, actor.id, 'SHARE');
          freshActor = new ActorContext({
            id: user.id,
            globalRole: user.globalRole,
            isActive: user.isActive,
            memberships: lockedMember ? [{ projectId: targetProjectId, role: lockedMember.role }] : [],
          });
        } else {
          const lockedMember = await repos.projectRepo.lockMember(targetProjectId, actor.id, 'SHARE');
          if (!lockedMember) {
            // Existence hiding: non-members receive generic 404
            throw new EntityNotFoundError('Finding not found');
          }
          freshActor = new ActorContext({
            id: user.id,
            globalRole: user.globalRole,
            isActive: user.isActive,
            memberships: [{ projectId: targetProjectId, role: lockedMember.role }],
          });
        }

        // Project active status checked strictly AFTER membership verification
        // Existence hiding: non-members have already been rejected with 404 above; only authorized members receive 403
        if (!lockedProject.isActive) {
          throw new ForbiddenError('Project is archived and cannot be modified');
        }

        // Level 3: Row lock on finding
        const lockedFinding = await repos.findingRepo.lockFinding(findingId, 'UPDATE');
        if (!lockedFinding || lockedFinding.isDeleted || lockedFinding.projectId !== targetProjectId) {
          throw new EntityNotFoundError('Finding not found');
        }

        // Level 4: Row lock on active task
        const lockedTask = await repos.taskRepo.lockActiveTaskByFindingId(findingId, 'UPDATE');
        if (!lockedTask) {
          throw new EntityNotFoundError('Active remediation task not found for finding');
        }

        // Enforce policies:
        // FindingPolicy: caller must be assigned Developer
        FindingPolicy.authorize(freshActor, 'submit_remediation', {
          finding: lockedFinding,
          projectId: lockedFinding.projectId,
        });

        // TaskPolicy: caller must be assigned Developer
        TaskPolicy.authorize(freshActor, 'submit', {
          projectId: targetProjectId,
          task: lockedTask,
        });

        // Optimistic Concurrency Control (OCC) version check under Level 3 lock
        if (lockedFinding.version !== parsed.expectedVersion) {
          throw new ConcurrencyConflictError(
            `Optimistic concurrency conflict on Finding '${findingId}'. Expected version ${parsed.expectedVersion}, but found version ${lockedFinding.version}.`,
            lockedFinding.version,
            parsed.expectedVersion,
          );
        }

        // Lifecycle state machine invariants
        if (lockedFinding.status !== 'IN_PROGRESS') {
          throw new InvalidStateTransitionError(
            `Cannot submit remediation for finding '${findingId}': current status is '${lockedFinding.status}', expected 'IN_PROGRESS'`,
            lockedFinding.status,
            'READY_FOR_REVIEW',
          );
        }

        if (lockedTask.status !== 'PENDING' && lockedTask.status !== 'IN_PROGRESS') {
          throw new InvalidStateTransitionError(
            `Cannot submit remediation for task '${lockedTask.id}': current status is '${lockedTask.status}', expected 'PENDING' or 'IN_PROGRESS'`,
            lockedTask.status,
            'SUBMITTED',
          );
        }

        // Atomic OCC compare-and-increment on Finding
        const updatedFinding = await repos.findingRepo.updateAtomic(findingId, {
          expectedVersion: parsed.expectedVersion,
          status: 'READY_FOR_REVIEW',
        });

        // Transition task to SUBMITTED
        const updatedTask = await repos.taskRepo.updateStatus(
          lockedTask.id,
          'SUBMITTED',
          parsed.notes !== undefined ? parsed.notes : lockedTask.notes,
        );

        // Add FindingEvent (STATUS_CHANGED: IN_PROGRESS -> READY_FOR_REVIEW)
        // CRITICAL: Must record submitterId for Separation of Duties (OLI-7)
        await repos.findingRepo.addEvent({
          findingId: updatedFinding.id,
          actorId: actor.id,
          eventType: 'STATUS_CHANGED',
          previousStatus: 'IN_PROGRESS',
          newStatus: 'READY_FOR_REVIEW',
          metadata: {
            submitterId: actor.id,
            taskId: lockedTask.id,
            notes: parsed.notes ?? null,
          },
        });

        // Append AuditEvents
        await repos.auditRepo.append({
          actorId: actor.id,
          eventCategory: 'FINDING',
          eventType: 'finding.remediation_submitted',
          resourceId: updatedFinding.id,
          resourceType: 'finding',
          beforeState: {
            status: 'IN_PROGRESS',
            version: lockedFinding.version,
          },
          afterState: {
            status: 'READY_FOR_REVIEW',
            version: updatedFinding.version,
            submitterId: actor.id,
          },
        });

        await repos.auditRepo.append({
          actorId: actor.id,
          eventCategory: 'TASK',
          eventType: 'task.submitted',
          resourceId: lockedTask.id,
          resourceType: 'remediation_task',
          beforeState: {
            status: lockedTask.status,
            notes: lockedTask.notes,
          },
          afterState: {
            status: 'SUBMITTED',
            notes: updatedTask.notes,
          },
        });

        return updatedFinding;
      });
    } catch (err) {
      handleDatabaseConcurrencyError(err);
    }
  }

  public async verifyFinding(
    actor: ActorContext,
    findingId: string,
    input: VerifyFindingInput,
  ): Promise<FindingEntity> {
    if (!this.db && !this.directRepos) {
      throw new SecureFlowError(
        '[NOT_IMPLEMENTED] FindingService uninitialized or operation not implemented',
        'NOT_IMPLEMENTED',
        501,
      );
    }

    const parsed = VerifyFindingInputSchema.parse(input);

    try {
      return await this.executeTransaction(async (repos) => {
        // Safe preliminary lookup
        const candidate = await repos.findingRepo.findById(findingId, { unrestricted: true });
        if (!candidate || candidate.isDeleted) {
          throw new EntityNotFoundError('Finding not found');
        }
        const targetProjectId = candidate.projectId;

        // Level 0: Deterministic row lock on actor
        const userMap = await repos.userRepo.lockUsers([actor.id], 'SHARE');
        const user = userMap.get(actor.id);
        if (!user || !user.isActive) {
          throw new ForbiddenError('Actor account is deactivated');
        }

        // Level 1: Row lock on target project
        const lockedProject = await repos.projectRepo.lockProject(targetProjectId, 'SHARE');
        if (!lockedProject) {
          throw new EntityNotFoundError('Finding not found');
        }

        // Level 2: Row lock on project membership (establishing exact linearization point)
        let freshActor: ActorContext;
        if (user.globalRole === 'ADMIN') {
          const lockedMember = await repos.projectRepo.lockMember(targetProjectId, actor.id, 'SHARE');
          freshActor = new ActorContext({
            id: user.id,
            globalRole: user.globalRole,
            isActive: user.isActive,
            memberships: lockedMember ? [{ projectId: targetProjectId, role: lockedMember.role }] : [],
          });
        } else {
          const lockedMember = await repos.projectRepo.lockMember(targetProjectId, actor.id, 'SHARE');
          if (!lockedMember) {
            // Existence hiding: non-members receive generic 404
            throw new EntityNotFoundError('Finding not found');
          }
          freshActor = new ActorContext({
            id: user.id,
            globalRole: user.globalRole,
            isActive: user.isActive,
            memberships: [{ projectId: targetProjectId, role: lockedMember.role }],
          });
        }

        // Project active status checked strictly AFTER membership verification
        // Existence hiding: non-members have already been rejected with 404 above; only authorized members receive 403
        if (!lockedProject.isActive) {
          throw new ForbiddenError('Project is archived and cannot be modified');
        }

        // Level 3: Row lock on finding
        const lockedFinding = await repos.findingRepo.lockFinding(findingId, 'UPDATE');
        if (!lockedFinding || lockedFinding.isDeleted || lockedFinding.projectId !== targetProjectId) {
          throw new EntityNotFoundError('Finding not found');
        }

        // Level 4: Row lock on active task
        const lockedTask = await repos.taskRepo.lockActiveTaskByFindingId(findingId, 'UPDATE');
        if (!lockedTask) {
          throw new EntityNotFoundError('Active remediation task not found for finding');
        }

        // Optimistic Concurrency Control (OCC) version check under Level 3 lock
        if (lockedFinding.version !== parsed.expectedVersion) {
          throw new ConcurrencyConflictError(
            `Optimistic concurrency conflict on Finding '${findingId}'. Expected version ${parsed.expectedVersion}, but found version ${lockedFinding.version}.`,
            lockedFinding.version,
            parsed.expectedVersion,
          );
        }

        // Invariant checks on finding and active task state
        if (lockedFinding.status !== 'READY_FOR_REVIEW') {
          throw new InvalidStateTransitionError(
            `Cannot verify finding '${findingId}': current status is '${lockedFinding.status}', expected 'READY_FOR_REVIEW'`,
            lockedFinding.status,
            parsed.outcome,
          );
        }

        if (lockedTask.status !== 'SUBMITTED') {
          throw new InvalidStateTransitionError(
            `Cannot verify task '${lockedTask.id}': current status is '${lockedTask.status}', expected 'SUBMITTED'`,
            lockedTask.status,
            parsed.outcome === 'VERIFIED' ? 'VERIFIED' : 'REJECTED',
          );
        }

        // Separation of Duties (OLI-7) Authoritative Evidence Validation:
        // 1. Retrieve all lifecycle events for this finding
        const events = await repos.findingRepo.getEvents(findingId);

        // 2. Filter events strictly matching the current active task and approved remediation submission contract:
        //    - Belongs to the same finding
        //    - Approved eventType STATUS_CHANGED
        //    - newStatus is READY_FOR_REVIEW
        //    - metadata.taskId matches the locked active task ID (guaranteeing evidence belongs to current remediation cycle)
        const matchingSubmissionEvents = events.filter((e) => {
          if (e.findingId !== lockedFinding.id) return false;
          if (e.eventType !== 'STATUS_CHANGED') return false;
          if (e.newStatus !== 'READY_FOR_REVIEW') return false;
          const meta = e.metadata as Record<string, unknown> | null;
          if (!meta || typeof meta !== 'object') return false;
          return meta.taskId === lockedTask.id;
        });

        // 3. Deterministic sort order (handling timestamp collisions via secondary sort on event id)
        matchingSubmissionEvents.sort((a, b) => {
          const timeDiff = a.createdAt.getTime() - b.createdAt.getTime();
          if (timeDiff !== 0) return timeDiff;
          return a.id.localeCompare(b.id);
        });

        // 3. Strict Single-Submission-Event Invariant (OLI-7 fail-closed SoD enforcement):
        //    In a valid lifecycle, submitRemediation transitions the task to SUBMITTED and finding to READY_FOR_REVIEW,
        //    producing exactly 1 submission event per active task.
        //    - 0 matching events -> reject fail-closed (missing evidence)
        //    - >1 matching events -> reject fail-closed (ambiguous evidence, anomaly, or tampering)
        //    - Exactly 1 matching event -> proceed with authoritative SoD evaluation
        if (matchingSubmissionEvents.length === 0) {
          throw new ForbiddenError(
            'Verification rejected: reliable remediation submitter evidence is missing or unavailable for active task (fail-closed SoD enforcement OLI-7)',
          );
        }

        if (matchingSubmissionEvents.length > 1) {
          throw new ForbiddenError(
            'Verification rejected: ambiguous remediation submission evidence; active task has multiple submission events (fail-closed SoD enforcement OLI-7)',
          );
        }

        const latestSubmission = matchingSubmissionEvents[0]!;

        const subMeta = latestSubmission.metadata as Record<string, unknown>;
        const submitterIdFromActor = latestSubmission.actorId;
        const submitterIdFromMeta = typeof subMeta.submitterId === 'string' ? subMeta.submitterId : null;

        // 5. Inconsistent actorId and metadata.submitterId check (fail-closed OLI-7)
        if (!submitterIdFromMeta || submitterIdFromActor !== submitterIdFromMeta) {
          throw new ForbiddenError(
            'Verification rejected: contradictory remediation submitter evidence (actorId does not match metadata.submitterId)',
          );
        }

        // 6. Submitter must match the task's assigned Developer
        if (submitterIdFromActor !== lockedTask.assignedToId) {
          throw new ForbiddenError(
            'Verification rejected: submitter does not match assigned developer for active remediation task',
          );
        }

        // 7. Verifier must differ from submitter (SoD OLI-7)
        if (actor.id === submitterIdFromActor) {
          throw new ForbiddenError(
            'Analyst who submitted remediation cannot verify the same finding (separation of duties violation OLI-7)',
          );
        }

        // Authorize via FindingPolicy (enforcing OLI-7 SoD)
        FindingPolicy.authorize(freshActor, 'verify', {
          finding: lockedFinding,
          projectId: lockedFinding.projectId,
          remediationSubmitterId: submitterIdFromActor,
        });

        // Authorize via TaskPolicy (Analyst-scoped)
        TaskPolicy.authorize(freshActor, parsed.outcome === 'VERIFIED' ? 'verify' : 'reject', {
          projectId: targetProjectId,
          task: lockedTask,
        });

        // Atomic OCC compare-and-increment on Finding
        const updatedFinding = await repos.findingRepo.updateAtomic(findingId, {
          expectedVersion: parsed.expectedVersion,
          status: parsed.outcome,
        });

        // Transition task status: VERIFIED or REJECTED (both release the partial unique index)
        const updatedTask = await repos.taskRepo.updateStatus(
          lockedTask.id,
          parsed.outcome === 'VERIFIED' ? 'VERIFIED' : 'REJECTED',
          parsed.notes !== undefined ? parsed.notes : lockedTask.notes,
        );

        // Add FindingEvent
        await repos.findingRepo.addEvent({
          findingId: updatedFinding.id,
          actorId: actor.id,
          eventType: 'STATUS_CHANGED',
          previousStatus: 'READY_FOR_REVIEW',
          newStatus: parsed.outcome,
          metadata: {
            verifierId: actor.id,
            outcome: parsed.outcome,
            taskId: lockedTask.id,
            notes: parsed.notes ?? null,
          },
        });

        // Append AuditEvents
        await repos.auditRepo.append({
          actorId: actor.id,
          eventCategory: 'FINDING',
          eventType: parsed.outcome === 'VERIFIED' ? 'finding.verified' : 'finding.remediation_rejected',
          resourceId: updatedFinding.id,
          resourceType: 'finding',
          beforeState: {
            status: 'READY_FOR_REVIEW',
            version: lockedFinding.version,
          },
          afterState: {
            status: parsed.outcome,
            version: updatedFinding.version,
            verifierId: actor.id,
          },
        });

        await repos.auditRepo.append({
          actorId: actor.id,
          eventCategory: 'TASK',
          eventType: parsed.outcome === 'VERIFIED' ? 'task.verified' : 'task.rejected',
          resourceId: lockedTask.id,
          resourceType: 'remediation_task',
          beforeState: {
            status: lockedTask.status,
            notes: lockedTask.notes,
          },
          afterState: {
            status: updatedTask.status,
            notes: updatedTask.notes,
          },
        });

        return updatedFinding;
      });
    } catch (err) {
      handleDatabaseConcurrencyError(err);
    }
  }

  public async confirmVerification(
    actor: ActorContext,
    findingId: string,
    input: Omit<VerifyFindingInput, 'outcome'>,
  ): Promise<FindingEntity> {
    return this.verifyFinding(actor, findingId, { ...input, outcome: 'VERIFIED' });
  }

  public async rejectVerification(
    actor: ActorContext,
    findingId: string,
    input: Omit<VerifyFindingInput, 'outcome'>,
  ): Promise<FindingEntity> {
    return this.verifyFinding(actor, findingId, { ...input, outcome: 'REOPENED' });
  }

  public async closeFinding(
    actor: ActorContext,
    findingId: string,
    input: CloseFindingInput,
  ): Promise<FindingEntity> {
    const parsed = CloseFindingInputSchema.parse(input);
    const repos = this.getRepos();

    // 1. Preliminary safe lookup to determine target project and enforce existence hiding
    const initialFinding = await repos.findingRepo.findById(findingId, { unrestricted: true });
    if (!initialFinding || initialFinding.isDeleted) {
      throw new EntityNotFoundError('Finding not found');
    }
    const targetProjectId = initialFinding.projectId;

    // Preliminary authorization check against ActorContext snapshot (fast fail)
    const initialActor = await this.getAuthoritativeActor(actor, repos.userRepo);
    FindingPolicy.authorize(initialActor, 'close', {
      finding: initialFinding,
      projectId: targetProjectId,
    });

    try {
      return await this.executeTransaction(async (txRepos) => {
        // Level 0: Row lock on actor user
        const lockedUsers = await txRepos.userRepo.lockUsers([actor.id]);
        const user = lockedUsers.get(actor.id);
        if (!user) {
          throw new EntityNotFoundError('User not found');
        }
        if (!user.isActive) {
          throw new ForbiddenError('Actor account is deactivated');
        }

        // Level 1: Row lock on target project
        const lockedProject = await txRepos.projectRepo.lockProject(targetProjectId, 'SHARE');
        if (!lockedProject) {
          throw new EntityNotFoundError('Finding not found');
        }

        // Level 2: Row lock on project membership
        const lockedMember = await txRepos.projectRepo.lockMember(targetProjectId, actor.id, 'SHARE');
        if (!lockedMember) {
          throw new EntityNotFoundError('Finding not found');
        }

        const freshActor = new ActorContext({
          id: user.id,
          globalRole: user.globalRole,
          isActive: user.isActive,
          memberships: [{ projectId: targetProjectId, role: lockedMember.role }],
        });

        // Existence hiding for archived projects: verify membership first, then check active project status
        if (!lockedProject.isActive) {
          throw new ForbiddenError('Project is archived and cannot be modified');
        }

        // Level 3: Row lock on finding for update
        const lockedFinding = await txRepos.findingRepo.lockFinding(findingId, 'UPDATE');
        if (!lockedFinding || lockedFinding.isDeleted || lockedFinding.projectId !== targetProjectId) {
          throw new EntityNotFoundError('Finding not found');
        }

        // Authorize under lock
        FindingPolicy.authorize(freshActor, 'close', {
          finding: lockedFinding,
          projectId: targetProjectId,
        });

        // Optimistic Concurrency Control (OCC) version check under lock precedes state check
        if (lockedFinding.version !== parsed.expectedVersion) {
          throw new ConcurrencyConflictError(
            `Optimistic concurrency conflict on Finding '${findingId}'. Expected version ${parsed.expectedVersion}, but found version ${lockedFinding.version}.`,
            lockedFinding.version,
            parsed.expectedVersion,
          );
        }

        // State Machine validation: only VERIFIED findings can transition to CLOSED
        if (lockedFinding.status !== 'VERIFIED') {
          throw new InvalidStateTransitionError(
            `Cannot close finding '${findingId}': current status is '${lockedFinding.status}', expected 'VERIFIED'`,
            lockedFinding.status,
            'CLOSED',
          );
        }

        // Atomic update to CLOSED
        const updatedFinding = await txRepos.findingRepo.updateAtomic(findingId, {
          expectedVersion: parsed.expectedVersion,
          status: 'CLOSED',
        });

        // Append finding lifecycle event
        await txRepos.findingRepo.addEvent({
          findingId,
          actorId: actor.id,
          eventType: 'STATUS_CHANGED',
          previousStatus: 'VERIFIED',
          newStatus: 'CLOSED',
          metadata: parsed.notes ? { notes: parsed.notes } : null,
        });

        // Append audit event
        await txRepos.auditRepo.append({
          actorId: actor.id,
          eventCategory: 'FINDING',
          eventType: 'finding.closed',
          resourceId: findingId,
          resourceType: 'finding',
          beforeState: {
            status: lockedFinding.status,
            version: lockedFinding.version,
          },
          afterState: {
            status: updatedFinding.status,
            version: updatedFinding.version,
            ...(parsed.notes ? { notes: parsed.notes } : {}),
          },
        });

        return updatedFinding;
      });
    } catch (err) {
      handleDatabaseConcurrencyError(err);
    }
  }

  public async forceCloseFinding(
    actor: ActorContext,
    findingId: string,
    input: ForceCloseFindingInput,
  ): Promise<FindingEntity> {
    const parsed = ForceCloseFindingInputSchema.parse(input);
    const repos = this.getRepos();

    // 1. Preliminary safe lookup
    const initialFinding = await repos.findingRepo.findById(findingId, { unrestricted: true });
    if (!initialFinding || initialFinding.isDeleted) {
      throw new EntityNotFoundError('Finding not found');
    }
    const targetProjectId = initialFinding.projectId;

    // Preliminary authorization check against ActorContext snapshot (fast fail)
    const initialActor = await this.getAuthoritativeActor(actor, repos.userRepo);
    FindingPolicy.authorize(initialActor, 'force_close', {
      finding: initialFinding,
      projectId: targetProjectId,
    });

    try {
      return await this.executeTransaction(async (txRepos) => {
        // Level 0: Row lock on actor user
        const lockedUsers = await txRepos.userRepo.lockUsers([actor.id]);
        const user = lockedUsers.get(actor.id);
        if (!user) {
          throw new EntityNotFoundError('User not found');
        }
        if (!user.isActive) {
          throw new ForbiddenError('Actor account is deactivated');
        }
        if (user.globalRole !== 'ADMIN') {
          throw new ForbiddenError("Action 'force_close' requires Administrator role");
        }

        // Level 1: Row lock on target project
        const lockedProject = await txRepos.projectRepo.lockProject(targetProjectId, 'SHARE');
        if (!lockedProject) {
          throw new EntityNotFoundError('Finding not found');
        }
        if (!lockedProject.isActive) {
          throw new ForbiddenError('Project is archived and cannot be modified');
        }

        // Level 2: Omitted for Admin (global role does not require project membership)
        const freshActor = new ActorContext({
          id: user.id,
          globalRole: user.globalRole,
          isActive: user.isActive,
          memberships: [],
        });

        // Level 3: Row lock on finding for update
        const lockedFinding = await txRepos.findingRepo.lockFinding(findingId, 'UPDATE');
        if (!lockedFinding || lockedFinding.isDeleted || lockedFinding.projectId !== targetProjectId) {
          throw new EntityNotFoundError('Finding not found');
        }

        // Authorize under lock
        FindingPolicy.authorize(freshActor, 'force_close', {
          finding: lockedFinding,
          projectId: targetProjectId,
        });

        // Optimistic Concurrency Control (OCC) version check under lock precedes state check
        if (lockedFinding.version !== parsed.expectedVersion) {
          throw new ConcurrencyConflictError(
            `Optimistic concurrency conflict on Finding '${findingId}'. Expected version ${parsed.expectedVersion}, but found version ${lockedFinding.version}.`,
            lockedFinding.version,
            parsed.expectedVersion,
          );
        }

        // Exceptional Admin closure: only OPEN findings can transition to CLOSED via force_close
        if (lockedFinding.status !== 'OPEN') {
          throw new InvalidStateTransitionError(
            `Cannot force-close finding '${findingId}': current status is '${lockedFinding.status}', expected 'OPEN'`,
            lockedFinding.status,
            'CLOSED',
          );
        }

        // Atomic update to CLOSED
        const updatedFinding = await txRepos.findingRepo.updateAtomic(findingId, {
          expectedVersion: parsed.expectedVersion,
          status: 'CLOSED',
        });

        // Append finding lifecycle event with justification
        await txRepos.findingRepo.addEvent({
          findingId,
          actorId: actor.id,
          eventType: 'STATUS_CHANGED',
          previousStatus: 'OPEN',
          newStatus: 'CLOSED',
          metadata: { justification: parsed.justification },
        });

        // Append audit event with justification
        await txRepos.auditRepo.append({
          actorId: actor.id,
          eventCategory: 'FINDING',
          eventType: 'finding.force_closed',
          resourceId: findingId,
          resourceType: 'finding',
          beforeState: {
            status: lockedFinding.status,
            version: lockedFinding.version,
          },
          afterState: {
            status: updatedFinding.status,
            version: updatedFinding.version,
            justification: parsed.justification,
          },
        });

        return updatedFinding;
      });
    } catch (err) {
      handleDatabaseConcurrencyError(err);
    }
  }

  public async forceReopenFinding(
    actor: ActorContext,
    findingId: string,
    input: ForceReopenFindingInput,
  ): Promise<FindingEntity> {
    const parsed = ForceReopenFindingInputSchema.parse(input);
    const repos = this.getRepos();

    // 1. Preliminary safe lookup
    const initialFinding = await repos.findingRepo.findById(findingId, { unrestricted: true });
    if (!initialFinding || initialFinding.isDeleted) {
      throw new EntityNotFoundError('Finding not found');
    }
    const targetProjectId = initialFinding.projectId;

    // Preliminary authorization check against ActorContext snapshot (fast fail)
    const initialActor = await this.getAuthoritativeActor(actor, repos.userRepo);
    FindingPolicy.authorize(initialActor, 'force_reopen', {
      finding: initialFinding,
      projectId: targetProjectId,
    });

    try {
      return await this.executeTransaction(async (txRepos) => {
        // Level 0: Row lock on actor user
        const lockedUsers = await txRepos.userRepo.lockUsers([actor.id]);
        const user = lockedUsers.get(actor.id);
        if (!user) {
          throw new EntityNotFoundError('User not found');
        }
        if (!user.isActive) {
          throw new ForbiddenError('Actor account is deactivated');
        }
        if (user.globalRole !== 'ADMIN') {
          throw new ForbiddenError("Action 'force_reopen' requires Administrator role");
        }

        // Level 1: Row lock on target project
        const lockedProject = await txRepos.projectRepo.lockProject(targetProjectId, 'SHARE');
        if (!lockedProject) {
          throw new EntityNotFoundError('Finding not found');
        }
        if (!lockedProject.isActive) {
          throw new ForbiddenError('Project is archived and cannot be modified');
        }

        // Level 2: Omitted for Admin (global role does not require project membership)
        const freshActor = new ActorContext({
          id: user.id,
          globalRole: user.globalRole,
          isActive: user.isActive,
          memberships: [],
        });

        // Level 3: Row lock on finding for update
        const lockedFinding = await txRepos.findingRepo.lockFinding(findingId, 'UPDATE');
        if (!lockedFinding || lockedFinding.isDeleted || lockedFinding.projectId !== targetProjectId) {
          throw new EntityNotFoundError('Finding not found');
        }

        // Authorize under lock
        FindingPolicy.authorize(freshActor, 'force_reopen', {
          finding: lockedFinding,
          projectId: targetProjectId,
        });

        // Optimistic Concurrency Control (OCC) version check under lock precedes state check
        if (lockedFinding.version !== parsed.expectedVersion) {
          throw new ConcurrencyConflictError(
            `Optimistic concurrency conflict on Finding '${findingId}'. Expected version ${parsed.expectedVersion}, but found version ${lockedFinding.version}.`,
            lockedFinding.version,
            parsed.expectedVersion,
          );
        }

        // State Machine validation: only CLOSED findings can be force-reopened to REOPENED
        if (lockedFinding.status !== 'CLOSED') {
          throw new InvalidStateTransitionError(
            `Cannot force-reopen finding '${findingId}': current status is '${lockedFinding.status}', expected 'CLOSED'`,
            lockedFinding.status,
            'REOPENED',
          );
        }

        // Atomic update to REOPENED
        const updatedFinding = await txRepos.findingRepo.updateAtomic(findingId, {
          expectedVersion: parsed.expectedVersion,
          status: 'REOPENED',
        });

        // Append finding lifecycle event with justification (eventType: REOPENED)
        await txRepos.findingRepo.addEvent({
          findingId,
          actorId: actor.id,
          eventType: 'REOPENED',
          previousStatus: 'CLOSED',
          newStatus: 'REOPENED',
          metadata: { justification: parsed.justification },
        });

        // Append audit event with justification
        await txRepos.auditRepo.append({
          actorId: actor.id,
          eventCategory: 'FINDING',
          eventType: 'finding.force_reopened',
          resourceId: findingId,
          resourceType: 'finding',
          beforeState: {
            status: lockedFinding.status,
            version: lockedFinding.version,
          },
          afterState: {
            status: updatedFinding.status,
            version: updatedFinding.version,
            justification: parsed.justification,
          },
        });

        return updatedFinding;
      });
    } catch (err) {
      handleDatabaseConcurrencyError(err);
    }
  }

  public async softDeleteFinding(
    actor: ActorContext,
    findingId: string,
    input: SoftDeleteFindingInput,
  ): Promise<FindingEntity> {
    const parsed = SoftDeleteFindingInputSchema.parse(input);
    const repos = this.getRepos();

    // 1. Preliminary safe lookup
    const initialFinding = await repos.findingRepo.findById(findingId, { unrestricted: true });
    if (!initialFinding || initialFinding.isDeleted) {
      throw new EntityNotFoundError('Finding not found');
    }
    const targetProjectId = initialFinding.projectId;

    // Preliminary authorization check against ActorContext snapshot (fast fail)
    const initialActor = await this.getAuthoritativeActor(actor, repos.userRepo);
    FindingPolicy.authorize(initialActor, 'soft_delete', {
      finding: initialFinding,
      projectId: targetProjectId,
    });

    try {
      return await this.executeTransaction(async (txRepos) => {
        // Level 0: Row lock on actor user
        const lockedUsers = await txRepos.userRepo.lockUsers([actor.id]);
        const user = lockedUsers.get(actor.id);
        if (!user) {
          throw new EntityNotFoundError('User not found');
        }
        if (!user.isActive) {
          throw new ForbiddenError('Actor account is deactivated');
        }

        // Level 1: Row lock on target project
        const lockedProject = await txRepos.projectRepo.lockProject(targetProjectId, 'SHARE');
        if (!lockedProject) {
          throw new EntityNotFoundError('Finding not found');
        }

        // Level 2: Row lock on project membership
        const lockedMember = await txRepos.projectRepo.lockMember(targetProjectId, actor.id, 'SHARE');
        if (!lockedMember) {
          throw new EntityNotFoundError('Finding not found');
        }

        const freshActor = new ActorContext({
          id: user.id,
          globalRole: user.globalRole,
          isActive: user.isActive,
          memberships: [{ projectId: targetProjectId, role: lockedMember.role }],
        });

        // Existence hiding for archived projects: verify membership first, then check active project status
        if (!lockedProject.isActive) {
          throw new ForbiddenError('Project is archived and cannot be modified');
        }

        // Level 3: Row lock on finding for update
        const lockedFinding = await txRepos.findingRepo.lockFinding(findingId, 'UPDATE');
        if (!lockedFinding || lockedFinding.isDeleted || lockedFinding.projectId !== targetProjectId) {
          throw new EntityNotFoundError('Finding not found');
        }

        // Authorize under lock
        FindingPolicy.authorize(freshActor, 'soft_delete', {
          finding: lockedFinding,
          projectId: targetProjectId,
        });

        // Optimistic Concurrency Control (OCC) version check under lock
        if (lockedFinding.version !== parsed.expectedVersion) {
          throw new ConcurrencyConflictError(
            `Optimistic concurrency conflict on Finding '${findingId}'. Expected version ${parsed.expectedVersion}, but found version ${lockedFinding.version}.`,
            lockedFinding.version,
            parsed.expectedVersion,
          );
        }

        // Soft deletion sets isDeleted: true and increments version via repository softDelete
        const updatedFinding = await txRepos.findingRepo.softDelete(findingId, parsed.expectedVersion);

        // Append finding lifecycle event (eventType: DELETED)
        await txRepos.findingRepo.addEvent({
          findingId,
          actorId: actor.id,
          eventType: 'DELETED',
          previousStatus: lockedFinding.status,
          newStatus: lockedFinding.status,
          metadata: null,
        });

        // Append audit event
        await txRepos.auditRepo.append({
          actorId: actor.id,
          eventCategory: 'FINDING',
          eventType: 'finding.deleted',
          resourceId: findingId,
          resourceType: 'finding',
          beforeState: {
            isDeleted: false,
            version: lockedFinding.version,
          },
          afterState: {
            isDeleted: true,
            version: updatedFinding.version,
          },
        });

        return updatedFinding;
      });
    } catch (err) {
      handleDatabaseConcurrencyError(err);
    }
  }
}
