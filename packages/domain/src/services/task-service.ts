import {
  UpdateTaskNotesInputSchema,
  type UpdateTaskNotesInput,
} from '@secureflow/schemas';
import {
  EntityNotFoundError,
  ForbiddenError,
  SecureFlowError,
} from '@secureflow/shared';

import { ActorContext } from '../policy/actor-context.js';
import { TaskPolicy } from '../policy/task-policy.js';
import { FindingPolicy } from '../policy/finding-policy.js';
import { deriveFindingQueryScope } from '../policy/query-scopes.js';
import type {
  RemediationTaskEntity,
  RepositoryContainer,
} from '../db/repositories/types.js';
import { DatabaseManager } from '../db/database-manager.js';
import type {
  ITaskService,
} from './types.js';
import { handleDatabaseConcurrencyError } from './concurrency-handler.js';
import { isAuthorizedTestPersistence } from './persistence-token.js';

export type TaskServiceInit = DatabaseManager;

/**
 * Remediation Task Domain Service.
 *
 * Implements ITaskService mediating all business operations on remediation tasks.
 * Every method mandates an authenticated ActorContext as its first parameter.
 *
 * Sub-Gate 3D.4 Implementation Scope:
 * 1. getTask (Authoritative DB check, existence hiding 404 for unassigned developers / non-members)
 * 2. getTaskByFindingId (Role-scoped task lookup, existence hiding 404)
 * 3. updateTaskNotes (Assigned Developer only, Level 0 -> Level 1 -> Level 2 -> Level 3 -> Level 4 locking, atomic audit)
 *
 * Canonical Database Row Lock Hierarchy:
 * Level 0 (users) -> Level 1 (projects) -> Level 2 (project_members) -> Level 3 (findings) -> Level 4 (remediation_tasks)
 */
export class TaskService implements ITaskService {
  private readonly db: DatabaseManager | undefined;
  private readonly directRepos: RepositoryContainer | undefined;

  public constructor(db: DatabaseManager);
  public constructor(testInit: unknown);
  public constructor(init: unknown) {
    if (!init) {
      throw new SecureFlowError(
        'TaskService initialization failed: valid DatabaseManager or test repository container required',
        'SERVICE_INITIALIZATION_ERROR',
        500,
      );
    }

    if (init instanceof DatabaseManager) {
      this.db = init;
      this.directRepos = undefined;
    } else if (isAuthorizedTestPersistence(init)) {
      if (
        !init.repositories.taskRepo ||
        !init.repositories.findingRepo ||
        !init.repositories.projectRepo ||
        !init.repositories.userRepo ||
        !init.repositories.auditRepo
      ) {
        throw new SecureFlowError(
          'TaskService initialization failed: incomplete repository container',
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
      '[NOT_IMPLEMENTED] TaskService requires DatabaseManager or test repositories',
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
      '[NOT_IMPLEMENTED] TaskService requires DatabaseManager or test repositories',
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

  public async getTask(actor: ActorContext, taskId: string): Promise<RemediationTaskEntity> {
    if (!this.db && !this.directRepos) {
      throw new SecureFlowError(
        '[NOT_IMPLEMENTED] TaskService uninitialized or operation not implemented',
        'NOT_IMPLEMENTED',
        501,
      );
    }

    try {
      const repos = this.getRepos();
      const freshActor = await this.getAuthoritativeActor(actor, repos.userRepo);

      const task = await repos.taskRepo.findById(taskId);
      if (!task) {
        throw new EntityNotFoundError('Remediation task not found');
      }

      const finding = await repos.findingRepo.findById(task.findingId, { unrestricted: true });
      if (!finding || finding.isDeleted) {
        throw new EntityNotFoundError('Remediation task not found');
      }

      // Enforce TaskPolicy view rules:
      // Admin: allowed
      // Analyst: allowed if member of target project
      // Developer: allowed only if assigned to this specific task (existence hiding 404 otherwise)
      TaskPolicy.authorize(freshActor, 'view', {
        projectId: finding.projectId,
        task,
      });

      return task;
    } catch (err) {
      handleDatabaseConcurrencyError(err);
    }
  }

  public async getTaskByFindingId(
    actor: ActorContext,
    findingId: string,
  ): Promise<RemediationTaskEntity | null> {
    if (!this.db && !this.directRepos) {
      throw new SecureFlowError(
        '[NOT_IMPLEMENTED] TaskService uninitialized or operation not implemented',
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

      // Defense-in-depth finding view authorization check enforcing existence hiding
      FindingPolicy.authorize(freshActor, 'view', {
        finding,
        projectId: finding.projectId,
      });

      const activeTask = await repos.taskRepo.findActiveByFindingId(findingId);
      if (!activeTask) {
        return null;
      }

      // Task view authorization check enforcing existence hiding for non-assigned developers
      TaskPolicy.authorize(freshActor, 'view', {
        projectId: finding.projectId,
        task: activeTask,
      });

      return activeTask;
    } catch (err) {
      handleDatabaseConcurrencyError(err);
    }
  }

  public async updateTaskNotes(
    actor: ActorContext,
    taskId: string,
    input: UpdateTaskNotesInput,
  ): Promise<RemediationTaskEntity> {
    if (!this.db && !this.directRepos) {
      throw new SecureFlowError(
        '[NOT_IMPLEMENTED] TaskService uninitialized or operation not implemented',
        'NOT_IMPLEMENTED',
        501,
      );
    }

    const parsed = UpdateTaskNotesInputSchema.parse(input);

    try {
      return await this.executeTransaction(async (repos) => {
        // Safe preliminary lookups before locking
        const candidateTask = await repos.taskRepo.findById(taskId);
        if (!candidateTask) {
          throw new EntityNotFoundError('Remediation task not found');
        }

        const candidateFinding = await repos.findingRepo.findById(candidateTask.findingId, { unrestricted: true });
        if (!candidateFinding || candidateFinding.isDeleted) {
          throw new EntityNotFoundError('Remediation task not found');
        }
        const targetProjectId = candidateFinding.projectId;

        // Level 0: Deterministic row lock on actor
        const userMap = await repos.userRepo.lockUsers([actor.id], 'SHARE');
        const user = userMap.get(actor.id);
        if (!user || !user.isActive) {
          throw new ForbiddenError('Actor account is deactivated');
        }

        // Level 1: Row lock on target project
        const lockedProject = await repos.projectRepo.lockProject(targetProjectId, 'SHARE');
        if (!lockedProject) {
          throw new EntityNotFoundError('Remediation task not found');
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
            throw new EntityNotFoundError('Remediation task not found');
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
        const lockedFinding = await repos.findingRepo.lockFinding(candidateFinding.id, 'SHARE');
        if (!lockedFinding || lockedFinding.isDeleted || lockedFinding.projectId !== targetProjectId) {
          throw new EntityNotFoundError('Remediation task not found');
        }

        // Level 4: Row lock on task
        const lockedTask = await repos.taskRepo.lockTask(taskId, 'UPDATE');
        if (!lockedTask || lockedTask.findingId !== lockedFinding.id) {
          throw new EntityNotFoundError('Remediation task not found');
        }

        // Enforce TaskPolicy update_notes permission under lock (assigned Developer only)
        TaskPolicy.authorize(freshActor, 'update_notes', {
          projectId: targetProjectId,
          task: lockedTask,
        });

        // Update task notes
        const updatedTask = await repos.taskRepo.updateNotes(taskId, parsed.notes);

        // Atomic audit event (task.notes_updated)
        await repos.auditRepo.append({
          actorId: actor.id,
          eventCategory: 'TASK',
          eventType: 'task.notes_updated',
          resourceId: taskId,
          resourceType: 'remediation_task',
          beforeState: {
            notes: lockedTask.notes,
          },
          afterState: {
            notes: updatedTask.notes,
          },
        });

        return updatedTask;
      });
    } catch (err) {
      handleDatabaseConcurrencyError(err);
    }
  }
}
