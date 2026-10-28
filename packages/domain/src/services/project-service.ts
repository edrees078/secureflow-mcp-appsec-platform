import {
  CreateProjectInputSchema,
  UpdateProjectInputSchema,
  AddProjectMemberInputSchema,
  type CreateProjectInput,
  type UpdateProjectInput,
  type AddProjectMemberInput,
} from '@secureflow/schemas';
import {
  EntityNotFoundError,
  ForbiddenError,
  SecureFlowError,
  UnauthorizedError,
} from '@secureflow/shared';

import { ActorContext } from '../policy/actor-context.js';
import { ProjectPolicy } from '../policy/project-policy.js';
import { deriveProjectQueryScope } from '../policy/query-scopes.js';
import type {
  PaginatedResult,
  ProjectEntity,
  ProjectMemberEntity,
  RepositoryContainer,
} from '../db/repositories/types.js';
import { DatabaseManager } from '../db/database-manager.js';
import type {
  IProjectService,
  ListProjectsFilterInput,
} from './types.js';
import {
  generateProjectSlug,
  handleDatabaseConcurrencyError,
} from './concurrency-handler.js';

/**
 * Service initialization parameter: either trusted DatabaseManager or explicitly provided test repositories.
 */
export type ProjectServiceInit =
  | DatabaseManager
  | { readonly repositories: RepositoryContainer };

/**
 * Transactional Project Management Domain Service.
 *
 * Implements IProjectService governing project lifecycles, metadata updates,
 * archiving, and member administration under strict concurrency and authorization guarantees.
 *
 * Security & Concurrency Guarantees (Sub-Gate 3D.2):
 * 1. ActorContext as Mandatory First Parameter: Every public method mandates an ActorContext.
 * 2. Intra-Transaction Authorization Freshness: Authoritative state (account active status,
 *    global role, project existence) is revalidated inside PostgreSQL transactions under row lock.
 * 3. Canonical Database Row Lock Hierarchy:
 *    Level 0 (users) -> Level 1 (projects) -> Level 2 (project_members)
 * 4. Deterministic User Locking: Level 0 locks across multiple users are acquired in ascending lexical order.
 * 5. Read Authorization Freshness: Read methods re-verify active status and project memberships from PostgreSQL.
 * 6. Transactional Audit Atomicity: Every project and member mutation is atomically bundled
 *    with its corresponding append-only audit event in the same database transaction.
 * 7. Existence Hiding: Non-member reads receive HTTP 404 existence hiding rather than 403.
 */
export class ProjectService implements IProjectService {
  private readonly db: DatabaseManager | undefined;
  private readonly directRepos: RepositoryContainer | undefined;

  public constructor(init: ProjectServiceInit) {
    if (!init) {
      throw new SecureFlowError(
        'ProjectService initialization failed: valid DatabaseManager or test repository container required',
        'SERVICE_INITIALIZATION_ERROR',
        500,
      );
    }

    if (init instanceof DatabaseManager) {
      this.db = init;
      this.directRepos = undefined;
    } else if (
      typeof init === 'object' &&
      'repositories' in init &&
      init.repositories &&
      typeof init.repositories === 'object' &&
      init.repositories.projectRepo &&
      init.repositories.userRepo &&
      init.repositories.auditRepo
    ) {
      this.directRepos = init.repositories;
      this.db = undefined;
    } else {
      throw new SecureFlowError(
        'ProjectService initialization failed: invalid or contradictory dependencies provided',
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
      'ProjectService database connection not configured',
      'DATABASE_CONFIG_ERROR',
      500,
    );
  }

  private async getAuthoritativeActor(
    repos: RepositoryContainer,
    actor: ActorContext,
  ): Promise<ActorContext> {
    const user = await repos.userRepo.findAuthoritativeUser(actor.id);
    if (!user) {
      throw new UnauthorizedError('Actor account not found');
    }
    if (!user.isActive) {
      throw new ForbiddenError('User account is deactivated');
    }
    return new ActorContext({
      id: user.id,
      globalRole: user.globalRole,
      isActive: user.isActive,
      memberships: user.memberships,
    });
  }

  private async executeInTransaction<T>(
    fn: (repos: RepositoryContainer) => Promise<T>,
  ): Promise<T> {
    if (this.db) {
      try {
        return await this.db.runTransaction(async (repos) => {
          return await fn(repos);
        });
      } catch (err: unknown) {
        handleDatabaseConcurrencyError(err);
      }
    }

    if (this.directRepos) {
      try {
        return await fn(this.directRepos);
      } catch (err: unknown) {
        handleDatabaseConcurrencyError(err);
      }
    }

    throw new SecureFlowError(
      'ProjectService database connection not configured for transactions',
      'DATABASE_CONFIG_ERROR',
      500,
    );
  }

  // ==========================================================================
  // IProjectService Implementation
  // ==========================================================================

  public async createProject(
    actor: ActorContext,
    input: CreateProjectInput,
  ): Promise<ProjectEntity> {
    const parsed = CreateProjectInputSchema.parse(input);
    ProjectPolicy.authorize(actor, 'create');

    return await this.executeInTransaction(async (repos) => {
      // Level 0: Revalidate actor freshness from PostgreSQL under row lock
      const userMap = await repos.userRepo.lockUsers([actor.id], 'SHARE');
      const user = userMap.get(actor.id);
      if (!user) {
        throw new UnauthorizedError('Actor account not found');
      }
      if (!user.isActive) {
        throw new ForbiddenError('User account is deactivated');
      }
      if (user.globalRole !== 'ADMIN') {
        throw new ForbiddenError("Action 'create' requires organization-wide Admin role");
      }

      // Generate slug server-side
      const slug = generateProjectSlug(parsed.name);

      // Check slug uniqueness
      const existing = await repos.projectRepo.findBySlug(slug);
      if (existing) {
        throw new SecureFlowError(
          'Project with this slug already exists',
          'PROJECT_SLUG_CONFLICT',
          409,
        );
      }

      // Execute project creation
      const project = await repos.projectRepo.create({
        name: parsed.name,
        slug,
        description: parsed.description,
        createdById: actor.id,
      });

      // Atomic Audit Event Logging (Audit Atomicity)
      await repos.auditRepo.append({
        actorId: actor.id,
        eventCategory: 'PROJECT',
        eventType: 'project.created',
        resourceId: project.id,
        resourceType: 'Project',
        afterState: {
          id: project.id,
          name: project.name,
          slug: project.slug,
          isActive: project.isActive,
        },
      });

      return project;
    });
  }

  public async updateProject(
    actor: ActorContext,
    projectId: string,
    input: UpdateProjectInput,
  ): Promise<ProjectEntity> {
    const parsed = UpdateProjectInputSchema.parse(input);
    ProjectPolicy.authorize(actor, 'update', { id: projectId });

    return await this.executeInTransaction(async (repos) => {
      // Level 0: Revalidate actor freshness from PostgreSQL under row lock
      const userMap = await repos.userRepo.lockUsers([actor.id], 'SHARE');
      const user = userMap.get(actor.id);
      if (!user) {
        throw new UnauthorizedError('Actor account not found');
      }
      if (!user.isActive) {
        throw new ForbiddenError('User account is deactivated');
      }
      if (user.globalRole !== 'ADMIN') {
        throw new ForbiddenError("Action 'update' requires organization-wide Admin role");
      }

      // Level 1: Lock project for update
      const current = await repos.projectRepo.lockProject(projectId, 'UPDATE');
      if (!current) {
        throw new EntityNotFoundError('Project not found');
      }

      // Handle name change and slug conflict
      if (parsed.name && parsed.name !== current.name) {
        const newSlug = generateProjectSlug(parsed.name);
        const existingSlug = await repos.projectRepo.findBySlug(newSlug);
        if (existingSlug && existingSlug.id !== projectId) {
          throw new SecureFlowError(
            'Project with this slug already exists',
            'PROJECT_SLUG_CONFLICT',
            409,
          );
        }
      }

      // Execute update
      const updated = await repos.projectRepo.update(projectId, {
        name: parsed.name,
        description: parsed.description,
        isActive: parsed.isActive,
      });

      // Atomic Audit Event Logging
      await repos.auditRepo.append({
        actorId: actor.id,
        eventCategory: 'PROJECT',
        eventType: 'project.updated',
        resourceId: projectId,
        resourceType: 'Project',
        beforeState: {
          name: current.name,
          description: current.description,
          isActive: current.isActive,
        },
        afterState: {
          name: updated.name,
          description: updated.description,
          isActive: updated.isActive,
        },
      });

      return updated;
    });
  }

  public async archiveProject(
    actor: ActorContext,
    projectId: string,
  ): Promise<ProjectEntity> {
    ProjectPolicy.authorize(actor, 'archive', { id: projectId });

    return await this.executeInTransaction(async (repos) => {
      // Level 0: Revalidate actor freshness under row lock
      const userMap = await repos.userRepo.lockUsers([actor.id], 'SHARE');
      const user = userMap.get(actor.id);
      if (!user) {
        throw new UnauthorizedError('Actor account not found');
      }
      if (!user.isActive) {
        throw new ForbiddenError('User account is deactivated');
      }
      if (user.globalRole !== 'ADMIN') {
        throw new ForbiddenError("Action 'archive' requires organization-wide Admin role");
      }

      // Level 1: Lock project for update
      const current = await repos.projectRepo.lockProject(projectId, 'UPDATE');
      if (!current) {
        throw new EntityNotFoundError('Project not found');
      }

      // Execute archiving (setting isActive = false)
      const archived = await repos.projectRepo.update(projectId, { isActive: false });

      // Atomic Audit Event Logging
      await repos.auditRepo.append({
        actorId: actor.id,
        eventCategory: 'PROJECT',
        eventType: 'project.archived',
        resourceId: projectId,
        resourceType: 'Project',
        beforeState: { isActive: current.isActive },
        afterState: { isActive: false },
      });

      return archived;
    });
  }

  public async getProject(
    actor: ActorContext,
    projectId: string,
  ): Promise<ProjectEntity> {
    const repos = this.getRepos();
    const freshActor = await this.getAuthoritativeActor(repos, actor);
    ProjectPolicy.authorize(freshActor, 'view', { id: projectId });

    const scope = deriveProjectQueryScope(freshActor);
    const project = await repos.projectRepo.findById(projectId, scope);
    if (!project) {
      throw new EntityNotFoundError('Project not found');
    }
    return project;
  }

  public async listProjects(
    actor: ActorContext,
    filter?: ListProjectsFilterInput,
  ): Promise<PaginatedResult<ProjectEntity>> {
    const repos = this.getRepos();
    const freshActor = await this.getAuthoritativeActor(repos, actor);

    if (freshActor.isAdmin()) {
      ProjectPolicy.authorize(freshActor, 'list_all');
    } else {
      ProjectPolicy.authorize(freshActor, 'list_own');
    }

    const scope = deriveProjectQueryScope(freshActor, {
      includeInactiveProjects: filter?.includeInactive,
    });
    return await repos.projectRepo.findMany({
      scope,
      search: filter?.search,
      page: filter?.page,
      limit: filter?.limit,
    });
  }

  public async addMember(
    actor: ActorContext,
    projectId: string,
    input: AddProjectMemberInput,
  ): Promise<ProjectMemberEntity> {
    const parsed = AddProjectMemberInputSchema.parse(input);
    ProjectPolicy.authorize(actor, 'add_member', { id: projectId });

    return await this.executeInTransaction(async (repos) => {
      // Level 0: Deterministic user locking across [actor.id, targetUserId] in ascending order
      const userMap = await repos.userRepo.lockUsers([actor.id, parsed.userId], 'SHARE');
      const adminUser = userMap.get(actor.id);
      const targetUser = userMap.get(parsed.userId);

      if (!adminUser) {
        throw new UnauthorizedError('Actor account not found');
      }
      if (!adminUser.isActive) {
        throw new ForbiddenError('User account is deactivated');
      }
      if (adminUser.globalRole !== 'ADMIN') {
        throw new ForbiddenError("Action 'add_member' requires organization-wide Admin role");
      }

      if (!targetUser) {
        throw new EntityNotFoundError('Target user not found');
      }
      if (!targetUser.isActive) {
        throw new SecureFlowError(
          'Cannot add inactive user to project',
          'ACCOUNT_INACTIVE',
          400,
        );
      }

      // Level 1: Lock project with FOR SHARE (parent guard)
      const project = await repos.projectRepo.lockProject(projectId, 'SHARE');
      if (!project) {
        throw new EntityNotFoundError('Project not found');
      }
      if (!project.isActive) {
        throw new SecureFlowError(
          'Cannot add members to archived project',
          'PROJECT_ARCHIVED',
          400,
        );
      }

      // Level 2: Check for existing membership conflict
      const existing = await repos.projectRepo.lockMember(projectId, parsed.userId, 'SHARE');
      if (existing) {
        throw new SecureFlowError(
          'User is already a member of this project',
          'MEMBER_ALREADY_EXISTS',
          409,
        );
      }

      // Insert membership record
      const member = await repos.projectRepo.addMember(projectId, {
        userId: parsed.userId,
        role: parsed.role,
        addedById: actor.id,
      });

      // Atomic Audit Event Logging
      await repos.auditRepo.append({
        actorId: actor.id,
        eventCategory: 'MEMBER',
        eventType: 'member.added',
        resourceId: member.id,
        resourceType: 'ProjectMember',
        afterState: {
          projectId,
          userId: parsed.userId,
          role: parsed.role,
          addedById: actor.id,
        },
      });

      return member;
    });
  }

  public async removeMember(
    actor: ActorContext,
    projectId: string,
    userId: string,
  ): Promise<boolean> {
    ProjectPolicy.authorize(actor, 'remove_member', { id: projectId });

    return await this.executeInTransaction(async (repos) => {
      // Level 0: Deterministic user locking across [actor.id, targetUserId] in ascending order
      const userMap = await repos.userRepo.lockUsers([actor.id, userId], 'SHARE');
      const adminUser = userMap.get(actor.id);
      const targetUser = userMap.get(userId);

      if (!adminUser) {
        throw new UnauthorizedError('Actor account not found');
      }
      if (!adminUser.isActive) {
        throw new ForbiddenError('User account is deactivated');
      }
      if (adminUser.globalRole !== 'ADMIN') {
        throw new ForbiddenError("Action 'remove_member' requires organization-wide Admin role");
      }

      if (!targetUser) {
        throw new EntityNotFoundError('Target user not found');
      }

      // Level 1: Lock project with FOR SHARE (parent guard)
      const project = await repos.projectRepo.lockProject(projectId, 'SHARE');
      if (!project) {
        throw new EntityNotFoundError('Project not found');
      }

      // Level 2: Lock specific membership record with FOR UPDATE
      const member = await repos.projectRepo.lockMember(projectId, userId, 'UPDATE');
      if (!member) {
        throw new EntityNotFoundError('Project member not found');
      }

      // Remove membership
      await repos.projectRepo.removeMember(projectId, userId);

      // Atomic Audit Event Logging
      await repos.auditRepo.append({
        actorId: actor.id,
        eventCategory: 'MEMBER',
        eventType: 'member.removed',
        resourceId: member.id,
        resourceType: 'ProjectMember',
        beforeState: {
          projectId,
          userId,
          role: member.role,
        },
        afterState: null,
      });

      return true;
    });
  }

  public async listMembers(
    actor: ActorContext,
    projectId: string,
  ): Promise<ProjectMemberEntity[]> {
    const repos = this.getRepos();
    const freshActor = await this.getAuthoritativeActor(repos, actor);
    ProjectPolicy.authorize(freshActor, 'view_members', { id: projectId });

    const scope = deriveProjectQueryScope(freshActor);
    const project = await repos.projectRepo.findById(projectId, scope);
    if (!project) {
      throw new EntityNotFoundError('Project not found');
    }

    return await repos.projectRepo.getMembers(projectId);
  }
}
