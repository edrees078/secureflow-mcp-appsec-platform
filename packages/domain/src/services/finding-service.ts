import {
  CreateFindingInputSchema,
  TriageFindingInputSchema,
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
  EntityNotFoundError,
  ForbiddenError,
  InvalidStateTransitionError,
  SecureFlowError,
} from '@secureflow/shared';

import { ActorContext } from '../policy/actor-context.js';
import { FindingPolicy } from '../policy/finding-policy.js';
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
  ServiceDependencies,
} from './types.js';
import { handleDatabaseConcurrencyError } from './concurrency-handler.js';

export type FindingServiceInit =
  | DatabaseManager
  | ServiceDependencies
  | undefined;

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

  public constructor(init?: FindingServiceInit) {
    if (!init) {
      this.db = undefined;
      this.directRepos = undefined;
      return;
    }

    if (init instanceof DatabaseManager) {
      this.db = init;
      this.directRepos = undefined;
    } else if (typeof init === 'object') {
      if ('db' in init && init.db instanceof DatabaseManager) {
        this.db = init.db;
        this.directRepos = undefined;
      } else if (
        'repositories' in init &&
        init.repositories &&
        typeof init.repositories === 'object' &&
        init.repositories.findingRepo &&
        init.repositories.projectRepo &&
        init.repositories.userRepo &&
        init.repositories.auditRepo
      ) {
        this.directRepos = init.repositories;
        this.db = undefined;
      } else {
        throw new SecureFlowError(
          'FindingService initialization failed: invalid or contradictory dependencies provided',
          'SERVICE_INITIALIZATION_ERROR',
          500,
        );
      }
    } else {
      throw new SecureFlowError(
        'FindingService initialization failed: valid DatabaseManager or test repository container required',
        'SERVICE_INITIALIZATION_ERROR',
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
    _actor: ActorContext,
    _findingId: string,
    _input: AssignFindingInput,
  ): Promise<FindingEntity> {
    void _actor;
    void _findingId;
    void _input;
    throw new SecureFlowError('[NOT_IMPLEMENTED] FindingService.assignFinding scheduled for Sub-Gate 3D.4', 'NOT_IMPLEMENTED', 501);
  }

  public async submitRemediation(
    _actor: ActorContext,
    _findingId: string,
    _input: SubmitRemediationInput,
  ): Promise<FindingEntity> {
    void _actor;
    void _findingId;
    void _input;
    throw new SecureFlowError('[NOT_IMPLEMENTED] FindingService.submitRemediation scheduled for Sub-Gate 3D.4', 'NOT_IMPLEMENTED', 501);
  }

  public async verifyFinding(
    _actor: ActorContext,
    _findingId: string,
    _input: VerifyFindingInput,
  ): Promise<FindingEntity> {
    void _actor;
    void _findingId;
    void _input;
    throw new SecureFlowError('[NOT_IMPLEMENTED] FindingService.verifyFinding scheduled for Sub-Gate 3D.4', 'NOT_IMPLEMENTED', 501);
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
    _actor: ActorContext,
    _findingId: string,
    _input: CloseFindingInput,
  ): Promise<FindingEntity> {
    void _actor;
    void _findingId;
    void _input;
    throw new SecureFlowError('[NOT_IMPLEMENTED] FindingService.closeFinding scheduled for Sub-Gate 3D.5', 'NOT_IMPLEMENTED', 501);
  }

  public async forceCloseFinding(
    _actor: ActorContext,
    _findingId: string,
    _input: ForceCloseFindingInput,
  ): Promise<FindingEntity> {
    void _actor;
    void _findingId;
    void _input;
    throw new SecureFlowError('[NOT_IMPLEMENTED] FindingService.forceCloseFinding scheduled for Sub-Gate 3D.5', 'NOT_IMPLEMENTED', 501);
  }

  public async forceReopenFinding(
    _actor: ActorContext,
    _findingId: string,
    _input: ForceReopenFindingInput,
  ): Promise<FindingEntity> {
    void _actor;
    void _findingId;
    void _input;
    throw new SecureFlowError('[NOT_IMPLEMENTED] FindingService.forceReopenFinding scheduled for Sub-Gate 3D.5', 'NOT_IMPLEMENTED', 501);
  }

  public async softDeleteFinding(
    _actor: ActorContext,
    _findingId: string,
    _input: SoftDeleteFindingInput,
  ): Promise<FindingEntity> {
    void _actor;
    void _findingId;
    void _input;
    throw new SecureFlowError('[NOT_IMPLEMENTED] FindingService.softDeleteFinding scheduled for Sub-Gate 3D.5', 'NOT_IMPLEMENTED', 501);
  }
}
