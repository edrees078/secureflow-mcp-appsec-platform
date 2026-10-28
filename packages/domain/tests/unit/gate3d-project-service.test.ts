import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  ProjectService,
  generateProjectSlug,
  createDomainServices,
  type IProjectRepository,
  type IAuditRepository,
  type IUserRepository,
  type IFindingRepository,
  type ITaskRepository,
  type ProjectEntity,
  type ProjectMemberEntity,
  type UserAuthEntity,
} from '../../src/index.js';
import { DatabaseManager } from '../../src/db/database-manager.js';
import {
  createTestAdminActor,
  createTestAnalystActor,
  createTestDeveloperActor,
  createSyntheticActorContext,
  createTestProjectService,
  type RepositoryContainer,
} from '../../src/testing/index.js';
import {
  ForbiddenError,
  EntityNotFoundError,
} from '@secureflow/shared';

describe('Gate 3D.2 — Transactional ProjectService (Unit Tests)', () => {
  const projectId = '11111111-1111-1111-1111-111111111111';
  const targetUserId = '22222222-2222-2222-2222-222222222222';

  let mockProjectRepo: Partial<IProjectRepository>;
  let mockAuditRepo: Partial<IAuditRepository>;
  let mockUserRepo: Partial<IUserRepository>;
  let mockRepos: RepositoryContainer;
  let service: ProjectService;

  beforeEach(() => {
    mockProjectRepo = {
      create: vi.fn(),
      update: vi.fn(),
      findById: vi.fn(),
      findBySlug: vi.fn(),
      findMany: vi.fn(),
      addMember: vi.fn(),
      removeMember: vi.fn(),
      getMembers: vi.fn(),
      isMember: vi.fn(),
      lockProject: vi.fn(),
      lockMember: vi.fn(),
      lockMembers: vi.fn(),
      getMemberRole: vi.fn(),
    };

    mockAuditRepo = {
      append: vi.fn().mockResolvedValue({
        id: 'audit-1',
        actorId: 'admin-1',
        eventCategory: 'PROJECT',
        eventType: 'project.created',
        resourceId: projectId,
        resourceType: 'Project',
        beforeState: null,
        afterState: null,
        ipAddress: null,
        userAgent: null,
        createdAt: new Date(),
      }),
      query: vi.fn(),
    };

    mockUserRepo = {
      findById: vi.fn(),
      findAuthoritativeUser: vi.fn().mockImplementation((id: string) => {
        if (id === '00000000-0000-0000-0000-000000000001') {
          return Promise.resolve({
            id,
            isActive: true,
            globalRole: 'ADMIN',
            memberships: [],
          });
        }
        if (id === '00000000-0000-0000-0000-000000000002') {
          return Promise.resolve({
            id,
            isActive: true,
            globalRole: 'ANALYST',
            memberships: [{ projectId, role: 'ANALYST' }],
          });
        }
        if (id === '00000000-0000-0000-0000-000000000003') {
          return Promise.resolve({
            id,
            isActive: true,
            globalRole: 'DEVELOPER',
            memberships: [{ projectId, role: 'DEVELOPER' }],
          });
        }
        return Promise.resolve({
          id,
          isActive: true,
          globalRole: 'DEVELOPER',
          memberships: [],
        });
      }),
      lockUser: vi.fn().mockResolvedValue({
        id: '00000000-0000-0000-0000-000000000001',
        isActive: true,
        globalRole: 'ADMIN',
      } as UserAuthEntity),
      lockUsers: vi.fn().mockImplementation(async (userIds: string[], mode?: 'SHARE' | 'UPDATE') => {
        const map = new Map<string, UserAuthEntity>();
        for (const id of userIds) {
          const user = await (mockUserRepo.lockUser as ReturnType<typeof vi.fn>)(id, mode);
          if (user) {
            map.set(id, user);
          }
        }
        return map;
      }),
      deactivateUser: vi.fn(),
      updateGlobalRole: vi.fn(),
    };

    mockRepos = {
      projectRepo: mockProjectRepo as IProjectRepository,
      auditRepo: mockAuditRepo as IAuditRepository,
      userRepo: mockUserRepo as IUserRepository,
      findingRepo: {} as IFindingRepository,
      taskRepo: {} as ITaskRepository,
    };

    service = createTestProjectService(mockRepos);
  });

  describe('0. Service Initialization Contract & Dependency Boundaries', () => {
    it('rejects construction with missing or undefined dependencies', () => {
      expect(() => new ProjectService(undefined as unknown as RepositoryContainer))
        .toThrow(expect.objectContaining({
          code: 'SERVICE_INITIALIZATION_ERROR',
          statusCode: 500,
        }));
    });

    it('rejects construction with empty dependency object', () => {
      expect(() => new ProjectService({} as unknown as RepositoryContainer))
        .toThrow(expect.objectContaining({
          code: 'SERVICE_INITIALIZATION_ERROR',
          statusCode: 500,
        }));
    });

    it('rejects construction with incomplete repository container', () => {
      expect(() => new ProjectService({ repositories: {} as unknown as RepositoryContainer }))
        .toThrow(expect.objectContaining({
          code: 'SERVICE_INITIALIZATION_ERROR',
          statusCode: 500,
        }));
    });

    it('createDomainServices rejects missing or undefined config with SERVICE_INITIALIZATION_ERROR', () => {
      expect(() => createDomainServices(undefined as unknown as DatabaseManager))
        .toThrow(expect.objectContaining({
          code: 'SERVICE_INITIALIZATION_ERROR',
          statusCode: 500,
        }));
    });

    it('createDomainServices owns internally constructed DatabaseManager and shuts it down on close()', async () => {
      const shutdownSpy = vi.spyOn(DatabaseManager.prototype, 'shutdown').mockResolvedValue(undefined);
      const services = createDomainServices({
        connectionString: 'postgresql://app:dummy-token@127.0.0.1:5433/secureflow_test',
      });
      await services.close();
      expect(shutdownSpy).toHaveBeenCalledTimes(1);
      shutdownSpy.mockRestore();
    });

    it('createDomainServices preserves externally supplied DatabaseManager and does not shut it down on close()', async () => {
      const externalDb = Object.create(DatabaseManager.prototype);
      externalDb.shutdown = vi.fn().mockResolvedValue(undefined);
      externalDb.getRepositories = vi.fn().mockReturnValue(mockRepos);

      const services = createDomainServices(externalDb);
      await services.close();
      expect(externalDb.shutdown).not.toHaveBeenCalled();
    });
  });

  describe('1. Slug Generation Utility', () => {
    it('generates URL-safe lowercase slug from project names', () => {
      expect(generateProjectSlug('Core Banking Platform')).toBe('core-banking-platform');
      expect(generateProjectSlug('   Web-Portal @ Security   ')).toBe('web-portal-security');
      expect(generateProjectSlug('Multiple----Dashes   Here')).toBe('multiple-dashes-here');
      expect(generateProjectSlug('$$$###')).toBe('project');
      expect(generateProjectSlug('a'.repeat(120)).length).toBe(100);
    });
  });

  describe('2. Project Creation (createProject)', () => {
    it('Admin caller creates project and atomically writes audit log', async () => {
      const admin = createTestAdminActor();
      const mockProject: ProjectEntity = {
        id: projectId,
        name: 'Secure Cloud Platform',
        slug: 'secure-cloud-platform',
        description: 'Main production cloud infrastructure',
        isActive: true,
        createdById: admin.id,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      (mockProjectRepo.findBySlug as ReturnType<typeof vi.fn>).mockResolvedValue(null);
      (mockProjectRepo.create as ReturnType<typeof vi.fn>).mockResolvedValue(mockProject);

      const result = await service.createProject(admin, {
        name: 'Secure Cloud Platform',
        description: 'Main production cloud infrastructure',
      });

      expect(result).toEqual(mockProject);
      expect(mockUserRepo.lockUsers).toHaveBeenCalledWith([admin.id], 'SHARE');
      expect(mockProjectRepo.create).toHaveBeenCalledWith({
        name: 'Secure Cloud Platform',
        slug: 'secure-cloud-platform',
        description: 'Main production cloud infrastructure',
        createdById: admin.id,
      });
      expect(mockAuditRepo.append).toHaveBeenCalledWith(
        expect.objectContaining({
          actorId: admin.id,
          eventCategory: 'PROJECT',
          eventType: 'project.created',
          resourceId: projectId,
        }),
      );
    });

    it('Non-admin caller is rejected with 403 Forbidden', async () => {
      const analyst = createTestAnalystActor(projectId);
      await expect(service.createProject(analyst, { name: 'Unauthorized Project' }))
        .rejects.toThrow(ForbiddenError);
      expect(mockProjectRepo.create).not.toHaveBeenCalled();
    });

    it('Inactive caller is rejected with 403 ACCOUNT_INACTIVE', async () => {
      const inactiveAdmin = createSyntheticActorContext({
        id: 'admin-inactive',
        globalRole: 'ADMIN',
        isActive: false,
      });
      await expect(service.createProject(inactiveAdmin, { name: 'Inactive Admin Project' }))
        .rejects.toThrow(ForbiddenError);
    });

    it('Stale global-role: caller has in-memory ADMIN role, but PostgreSQL returns ANALYST -> rejected with 403', async () => {
      const staleAdmin = createTestAdminActor();
      (mockUserRepo.lockUser as ReturnType<typeof vi.fn>).mockResolvedValue({
        id: staleAdmin.id,
        isActive: true,
        globalRole: 'ANALYST', // Demoted in PostgreSQL
      });

      await expect(service.createProject(staleAdmin, { name: 'Stale Admin Project' }))
        .rejects.toThrow(ForbiddenError);
      expect(mockProjectRepo.create).not.toHaveBeenCalled();
    });

    it('Stale account-status: caller has in-memory isActive=true, but PostgreSQL returns isActive=false -> rejected with 403', async () => {
      const deactivatedAdmin = createTestAdminActor();
      (mockUserRepo.lockUser as ReturnType<typeof vi.fn>).mockResolvedValue({
        id: deactivatedAdmin.id,
        isActive: false, // Deactivated in PostgreSQL
        globalRole: 'ADMIN',
      });

      await expect(service.createProject(deactivatedAdmin, { name: 'Deactivated Project' }))
        .rejects.toThrow(ForbiddenError);
    });

    it('Slug collision throws HTTP 409 PROJECT_SLUG_CONFLICT', async () => {
      const admin = createTestAdminActor();
      (mockProjectRepo.findBySlug as ReturnType<typeof vi.fn>).mockResolvedValue({
        id: 'existing-id',
        name: 'Secure Cloud Platform',
        slug: 'secure-cloud-platform',
      } as ProjectEntity);

      await expect(service.createProject(admin, { name: 'Secure Cloud Platform' }))
        .rejects.toThrow(expect.objectContaining({
          code: 'PROJECT_SLUG_CONFLICT',
          statusCode: 409,
        }));
      expect(mockProjectRepo.create).not.toHaveBeenCalled();
    });

    it('Audit append failure causes error to propagate and prevent commit', async () => {
      const admin = createTestAdminActor();
      (mockProjectRepo.findBySlug as ReturnType<typeof vi.fn>).mockResolvedValue(null);
      (mockProjectRepo.create as ReturnType<typeof vi.fn>).mockResolvedValue({ id: projectId } as ProjectEntity);
      (mockAuditRepo.append as ReturnType<typeof vi.fn>).mockRejectedValue(new Error('Audit append disk failure'));

      await expect(service.createProject(admin, { name: 'Failed Audit Project' }))
        .rejects.toThrow(/Audit append disk failure/);
    });
  });

  describe('3. Project Updates & Archiving (updateProject, archiveProject)', () => {
    it('Admin caller updates project metadata and writes audit event with before and after state', async () => {
      const admin = createTestAdminActor();
      const current: ProjectEntity = {
        id: projectId,
        name: 'Old Name',
        slug: 'old-name',
        description: 'Old Description',
        isActive: true,
        createdById: admin.id,
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      const updated: ProjectEntity = {
        ...current,
        name: 'New Name',
        description: 'New Description',
      };

      (mockProjectRepo.lockProject as ReturnType<typeof vi.fn>).mockResolvedValue(current);
      (mockProjectRepo.findBySlug as ReturnType<typeof vi.fn>).mockResolvedValue(null);
      (mockProjectRepo.update as ReturnType<typeof vi.fn>).mockResolvedValue(updated);

      const result = await service.updateProject(admin, projectId, {
        name: 'New Name',
        description: 'New Description',
      });

      expect(result).toEqual(updated);
      expect(mockProjectRepo.lockProject).toHaveBeenCalledWith(projectId, 'UPDATE');
      expect(mockAuditRepo.append).toHaveBeenCalledWith(
        expect.objectContaining({
          actorId: admin.id,
          eventCategory: 'PROJECT',
          eventType: 'project.updated',
          resourceId: projectId,
          beforeState: expect.objectContaining({ name: 'Old Name' }),
          afterState: expect.objectContaining({ name: 'New Name' }),
        }),
      );
    });

    it('updateProject throws 404 EntityNotFoundError if project does not exist', async () => {
      const admin = createTestAdminActor();
      (mockProjectRepo.lockProject as ReturnType<typeof vi.fn>).mockResolvedValue(null);

      await expect(service.updateProject(admin, projectId, { name: 'Updated' }))
        .rejects.toThrow(EntityNotFoundError);
    });

    it('archiveProject sets isActive = false and writes project.archived audit event', async () => {
      const admin = createTestAdminActor();
      const current: ProjectEntity = {
        id: projectId,
        name: 'Active Project',
        slug: 'active-project',
        description: null,
        isActive: true,
        createdById: admin.id,
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      const archived: ProjectEntity = {
        ...current,
        isActive: false,
      };

      (mockProjectRepo.lockProject as ReturnType<typeof vi.fn>).mockResolvedValue(current);
      (mockProjectRepo.update as ReturnType<typeof vi.fn>).mockResolvedValue(archived);

      const result = await service.archiveProject(admin, projectId);

      expect(result.isActive).toBe(false);
      expect(mockProjectRepo.update).toHaveBeenCalledWith(projectId, { isActive: false });
      expect(mockAuditRepo.append).toHaveBeenCalledWith(
        expect.objectContaining({
          actorId: admin.id,
          eventCategory: 'PROJECT',
          eventType: 'project.archived',
          resourceId: projectId,
          beforeState: { isActive: true },
          afterState: { isActive: false },
        }),
      );
    });

    it('archiveProject rejects non-admin with 403 Forbidden', async () => {
      const analyst = createTestAnalystActor(projectId);
      await expect(service.archiveProject(analyst, projectId))
        .rejects.toThrow(ForbiddenError);
    });
  });

  describe('4. Project Queries & Existence Hiding (getProject, listProjects)', () => {
    it('Admin can view any project', async () => {
      const admin = createTestAdminActor();
      const mockProject: ProjectEntity = {
        id: projectId,
        name: 'Project Alpha',
        slug: 'project-alpha',
        description: null,
        isActive: true,
        createdById: 'admin-1',
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      (mockProjectRepo.findById as ReturnType<typeof vi.fn>).mockResolvedValue(mockProject);

      const result = await service.getProject(admin, projectId);
      expect(result).toEqual(mockProject);
    });

    it('Authorized member can view their project', async () => {
      const dev = createTestDeveloperActor(projectId);
      const mockProject: ProjectEntity = {
        id: projectId,
        name: 'Project Alpha',
        slug: 'project-alpha',
        description: null,
        isActive: true,
        createdById: 'admin-1',
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      (mockProjectRepo.findById as ReturnType<typeof vi.fn>).mockResolvedValue(mockProject);

      const result = await service.getProject(dev, projectId);
      expect(result).toEqual(mockProject);
    });

    it('Non-member receives 404 EntityNotFoundError (existence hiding, not 403)', async () => {
      const otherProjectId = '99999999-9999-9999-9999-999999999999';
      const dev = createTestDeveloperActor(otherProjectId);
      (mockUserRepo.findAuthoritativeUser as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
        id: dev.id,
        isActive: true,
        globalRole: 'DEVELOPER',
        memberships: [{ projectId: otherProjectId, role: 'DEVELOPER' }],
      });

      await expect(service.getProject(dev, projectId))
        .rejects.toThrow(EntityNotFoundError);
      expect(mockProjectRepo.findById).not.toHaveBeenCalled();
    });

    it('listProjects filters projects according to actor query scope', async () => {
      const dev = createTestDeveloperActor(projectId);
      const mockResult = {
        items: [],
        total: 0,
        page: 1,
        limit: 25,
        totalPages: 1,
      };
      (mockProjectRepo.findMany as ReturnType<typeof vi.fn>).mockResolvedValue(mockResult);

      const result = await service.listProjects(dev);
      expect(result).toEqual(mockResult);
      expect(mockProjectRepo.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          scope: expect.objectContaining({
            accessibleProjectIds: [projectId],
            unrestricted: false,
          }),
        }),
      );
    });
  });

  describe('5. Project Membership Administration (addMember, removeMember, listMembers)', () => {
    it('Admin adds member to active project and records member.added audit event', async () => {
      const admin = createTestAdminActor();
      const mockMember: ProjectMemberEntity = {
        id: 'member-1',
        projectId,
        userId: targetUserId,
        role: 'DEVELOPER',
        addedById: admin.id,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      (mockUserRepo.lockUser as ReturnType<typeof vi.fn>).mockImplementation((id: string) => {
        if (id === admin.id) return Promise.resolve({ id: admin.id, isActive: true, globalRole: 'ADMIN' });
        if (id === targetUserId) return Promise.resolve({ id: targetUserId, isActive: true, globalRole: 'DEVELOPER' });
        return Promise.resolve(null);
      });
      (mockProjectRepo.lockProject as ReturnType<typeof vi.fn>).mockResolvedValue({ id: projectId, isActive: true });
      (mockProjectRepo.lockMember as ReturnType<typeof vi.fn>).mockResolvedValue(null); // not already member
      (mockProjectRepo.addMember as ReturnType<typeof vi.fn>).mockResolvedValue(mockMember);

      const result = await service.addMember(admin, projectId, {
        userId: targetUserId,
        role: 'DEVELOPER',
      });

      expect(result).toEqual(mockMember);
      expect(mockProjectRepo.lockProject).toHaveBeenCalledWith(projectId, 'SHARE');
      expect(mockAuditRepo.append).toHaveBeenCalledWith(
        expect.objectContaining({
          actorId: admin.id,
          eventCategory: 'MEMBER',
          eventType: 'member.added',
          resourceId: 'member-1',
        }),
      );
    });

    it('addMember throws 404 if target user does not exist in database', async () => {
      const admin = createTestAdminActor();
      (mockUserRepo.lockUser as ReturnType<typeof vi.fn>).mockImplementation((id: string) => {
        if (id === admin.id) return Promise.resolve({ id: admin.id, isActive: true, globalRole: 'ADMIN' });
        return Promise.resolve(null); // target user not found
      });

      await expect(service.addMember(admin, projectId, { userId: targetUserId, role: 'DEVELOPER' }))
        .rejects.toThrow(EntityNotFoundError);
      expect(mockProjectRepo.addMember).not.toHaveBeenCalled();
    });

    it('addMember throws 400 ACCOUNT_INACTIVE if target user is deactivated', async () => {
      const admin = createTestAdminActor();
      (mockUserRepo.lockUser as ReturnType<typeof vi.fn>).mockImplementation((id: string) => {
        if (id === admin.id) return Promise.resolve({ id: admin.id, isActive: true, globalRole: 'ADMIN' });
        return Promise.resolve({ id: targetUserId, isActive: false, globalRole: 'DEVELOPER' });
      });

      await expect(service.addMember(admin, projectId, { userId: targetUserId, role: 'DEVELOPER' }))
        .rejects.toThrow(expect.objectContaining({
          code: 'ACCOUNT_INACTIVE',
          statusCode: 400,
        }));
      expect(mockProjectRepo.addMember).not.toHaveBeenCalled();
    });

    it('addMember throws 400 PROJECT_ARCHIVED if project is inactive', async () => {
      const admin = createTestAdminActor();
      (mockUserRepo.lockUser as ReturnType<typeof vi.fn>).mockResolvedValue({ id: 'user', isActive: true, globalRole: 'ADMIN' });
      (mockProjectRepo.lockProject as ReturnType<typeof vi.fn>).mockResolvedValue({ id: projectId, isActive: false });

      await expect(service.addMember(admin, projectId, { userId: targetUserId, role: 'DEVELOPER' }))
        .rejects.toThrow(expect.objectContaining({
          code: 'PROJECT_ARCHIVED',
          statusCode: 400,
        }));
      expect(mockProjectRepo.addMember).not.toHaveBeenCalled();
    });

    it('addMember throws 409 MEMBER_ALREADY_EXISTS if user is already a member', async () => {
      const admin = createTestAdminActor();
      (mockUserRepo.lockUser as ReturnType<typeof vi.fn>).mockResolvedValue({ id: 'user', isActive: true, globalRole: 'ADMIN' });
      (mockProjectRepo.lockProject as ReturnType<typeof vi.fn>).mockResolvedValue({ id: projectId, isActive: true });
      (mockProjectRepo.lockMember as ReturnType<typeof vi.fn>).mockResolvedValue({ id: 'existing-member', role: 'DEVELOPER' });

      await expect(service.addMember(admin, projectId, { userId: targetUserId, role: 'DEVELOPER' }))
        .rejects.toThrow(expect.objectContaining({
          code: 'MEMBER_ALREADY_EXISTS',
          statusCode: 409,
        }));
      expect(mockProjectRepo.addMember).not.toHaveBeenCalled();
    });

    it('removeMember locks member with FOR UPDATE, deletes row, and records member.removed audit event', async () => {
      const admin = createTestAdminActor();
      const existingMember: ProjectMemberEntity = {
        id: 'member-to-remove',
        projectId,
        userId: targetUserId,
        role: 'DEVELOPER',
        addedById: 'admin-original',
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      (mockProjectRepo.lockProject as ReturnType<typeof vi.fn>).mockResolvedValue({ id: projectId, isActive: true });
      (mockProjectRepo.lockMember as ReturnType<typeof vi.fn>).mockResolvedValue(existingMember);
      (mockProjectRepo.removeMember as ReturnType<typeof vi.fn>).mockResolvedValue(true);

      const result = await service.removeMember(admin, projectId, targetUserId);

      expect(result).toBe(true);
      expect(mockProjectRepo.lockMember).toHaveBeenCalledWith(projectId, targetUserId, 'UPDATE');
      expect(mockProjectRepo.removeMember).toHaveBeenCalledWith(projectId, targetUserId);
      expect(mockAuditRepo.append).toHaveBeenCalledWith(
        expect.objectContaining({
          actorId: admin.id,
          eventCategory: 'MEMBER',
          eventType: 'member.removed',
          resourceId: 'member-to-remove',
          beforeState: { projectId, userId: targetUserId, role: 'DEVELOPER' },
          afterState: null,
        }),
      );
    });

    it('removeMember throws 404 EntityNotFoundError if member does not exist', async () => {
      const admin = createTestAdminActor();
      (mockProjectRepo.lockProject as ReturnType<typeof vi.fn>).mockResolvedValue({ id: projectId, isActive: true });
      (mockProjectRepo.lockMember as ReturnType<typeof vi.fn>).mockResolvedValue(null);

      await expect(service.removeMember(admin, projectId, targetUserId))
        .rejects.toThrow(EntityNotFoundError);
      expect(mockProjectRepo.removeMember).not.toHaveBeenCalled();
    });

    it('listMembers gives members list to authorized member or admin; rejects non-member with 404', async () => {
      const admin = createTestAdminActor();
      (mockProjectRepo.findById as ReturnType<typeof vi.fn>).mockResolvedValue({ id: projectId });
      (mockProjectRepo.getMembers as ReturnType<typeof vi.fn>).mockResolvedValue([]);

      const result = await service.listMembers(admin, projectId);
      expect(Array.isArray(result)).toBe(true);

      // Non-member
      const nonMember = createTestDeveloperActor('other-project-id');
      (mockUserRepo.findAuthoritativeUser as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
        id: nonMember.id,
        isActive: true,
        globalRole: 'DEVELOPER',
        memberships: [{ projectId: 'other-project-id', role: 'DEVELOPER' }],
      });
      await expect(service.listMembers(nonMember, projectId))
        .rejects.toThrow(EntityNotFoundError);
    });
  });

  describe('6. Concurrency Failure Handling', () => {
    it('maps PostgreSQL deadlock error 40P01 to HTTP 409 TRANSACTION_DEADLOCK', async () => {
      const admin = createTestAdminActor();
      (mockProjectRepo.findBySlug as ReturnType<typeof vi.fn>).mockRejectedValue(
        Object.assign(new Error('deadlock detected'), { code: '40P01' }),
      );

      await expect(service.createProject(admin, { name: 'Deadlock Project' }))
        .rejects.toThrow(expect.objectContaining({
          code: 'TRANSACTION_DEADLOCK',
          statusCode: 409,
        }));
    });

    it('maps PostgreSQL serialization error 40001 to HTTP 409 SERIALIZATION_FAILURE', async () => {
      const admin = createTestAdminActor();
      (mockProjectRepo.findBySlug as ReturnType<typeof vi.fn>).mockRejectedValue(
        Object.assign(new Error('could not serialize access due to concurrent update'), { code: '40001' }),
      );

      await expect(service.createProject(admin, { name: 'Serialization Project' }))
        .rejects.toThrow(expect.objectContaining({
          code: 'SERIALIZATION_FAILURE',
          statusCode: 409,
        }));
    });

    it('maps PostgreSQL statement/lock timeout 55P03 to HTTP 504 TRANSACTION_TIMEOUT', async () => {
      const admin = createTestAdminActor();
      (mockProjectRepo.findBySlug as ReturnType<typeof vi.fn>).mockRejectedValue(
        Object.assign(new Error('canceling statement due to statement timeout'), { code: '55P03' }),
      );

      await expect(service.createProject(admin, { name: 'Timeout Project' }))
        .rejects.toThrow(expect.objectContaining({
          code: 'TRANSACTION_TIMEOUT',
          statusCode: 504,
        }));
    });
  });

  describe('7. Read Authorization Freshness & Stale Context Rejection', () => {
    it('getProject rejects deactivated user from PostgreSQL with 403 Forbidden even if ActorContext claims isActive: true', async () => {
      const activeContext = createTestDeveloperActor(projectId);
      (mockUserRepo.findAuthoritativeUser as ReturnType<typeof vi.fn>).mockResolvedValue({
        id: activeContext.id,
        isActive: false,
        globalRole: 'DEVELOPER',
        memberships: [{ projectId, role: 'DEVELOPER' }],
      });

      await expect(service.getProject(activeContext, projectId))
        .rejects.toThrow(ForbiddenError);
    });

    it('getProject rejects revoked member with 404 existence hiding even if ActorContext still contains stale membership', async () => {
      const staleDevActor = createTestDeveloperActor(projectId);
      (mockUserRepo.findAuthoritativeUser as ReturnType<typeof vi.fn>).mockResolvedValue({
        id: staleDevActor.id,
        isActive: true,
        globalRole: 'DEVELOPER',
        memberships: [],
      });

      await expect(service.getProject(staleDevActor, projectId))
        .rejects.toThrow(EntityNotFoundError);
    });

    it('listProjects restricts downgraded Admin to assigned memberships even if ActorContext claims ADMIN', async () => {
      const staleAdminActor = createTestAdminActor();
      (mockUserRepo.findAuthoritativeUser as ReturnType<typeof vi.fn>).mockResolvedValue({
        id: staleAdminActor.id,
        isActive: true,
        globalRole: 'ANALYST',
        memberships: [{ projectId, role: 'ANALYST' }],
      });

      (mockProjectRepo.findMany as ReturnType<typeof vi.fn>).mockResolvedValue({
        items: [],
        total: 0,
        page: 1,
        limit: 25,
        totalPages: 0,
      });

      await service.listProjects(staleAdminActor);

      expect(mockProjectRepo.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          scope: expect.objectContaining({
            accessibleProjectIds: [projectId],
          }),
        }),
      );
    });
  });

  describe('8. Deterministic Level 0 User Locking Order', () => {
    it('addMember passes both actorId and targetUserId to lockUsers for sorted acquisition', async () => {
      const admin = createTestAdminActor();
      (mockProjectRepo.lockProject as ReturnType<typeof vi.fn>).mockResolvedValue({ id: projectId, isActive: true });
      (mockProjectRepo.lockMember as ReturnType<typeof vi.fn>).mockResolvedValue(null);
      (mockProjectRepo.addMember as ReturnType<typeof vi.fn>).mockResolvedValue({
        id: 'member-1',
        projectId,
        userId: targetUserId,
        role: 'DEVELOPER',
      });

      await service.addMember(admin, projectId, { userId: targetUserId, role: 'DEVELOPER' });

      expect(mockUserRepo.lockUsers).toHaveBeenCalledWith([admin.id, targetUserId], 'SHARE');
    });

    it('removeMember passes both actorId and targetUserId to lockUsers for sorted acquisition', async () => {
      const admin = createTestAdminActor();
      (mockProjectRepo.lockProject as ReturnType<typeof vi.fn>).mockResolvedValue({ id: projectId, isActive: true });
      (mockProjectRepo.lockMember as ReturnType<typeof vi.fn>).mockResolvedValue({
        id: 'member-1',
        projectId,
        userId: targetUserId,
        role: 'DEVELOPER',
      });
      (mockProjectRepo.removeMember as ReturnType<typeof vi.fn>).mockResolvedValue(true);

      await service.removeMember(admin, projectId, targetUserId);

      expect(mockUserRepo.lockUsers).toHaveBeenCalledWith([admin.id, targetUserId], 'SHARE');
    });
  });
});
