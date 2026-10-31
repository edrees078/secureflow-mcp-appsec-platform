import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  FindingEntity,
  ProjectEntity,
  ProjectMemberEntity,
  RepositoryContainer,
  IFindingRepository,
  IProjectRepository,
  IAuditRepository,
  IUserRepository,
  ITaskRepository,
  UserAuthEntity,
} from '../../src/db/repositories/types.js';
import {
  createTestFindingService,
  createTestAnalystActor,
  createTestDeveloperActor,
  createTestAdminActor,
} from '../../src/testing/index.js';
import { FindingService } from '../../src/services/finding-service.js';
import {
  ConcurrencyConflictError,
  EntityNotFoundError,
  ForbiddenError,
  InvalidStateTransitionError,
} from '@secureflow/shared';

describe('Gate 3D.5 — Finding Closure, Force-Close, Force-Reopen & Soft Deletion (Unit Tests)', () => {
  const projectId = '00000000-0000-0000-0000-000000000001';
  const findingId = '11111111-1111-1111-1111-111111111111';

  const analystActor = createTestAnalystActor(projectId);
  const devActor = createTestDeveloperActor(projectId);
  const adminActor = createTestAdminActor();
  const nonMemberActor = createTestAnalystActor('00000000-0000-0000-0000-000000000099', {
    id: '00000000-0000-0000-0000-000000000099',
  });

  let mockFindingRepo: Partial<IFindingRepository>;
  let mockProjectRepo: Partial<IProjectRepository>;
  let mockAuditRepo: Partial<IAuditRepository>;
  let mockUserRepo: Partial<IUserRepository>;
  let mockTaskRepo: Partial<ITaskRepository>;
  let mockRepos: RepositoryContainer;
  let service: FindingService;

  const mockProject: ProjectEntity = {
    id: projectId,
    name: 'Platform Core',
    slug: 'platform-core',
    description: null,
    isActive: true,
    createdById: 'admin-1',
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  const defaultVerifiedFinding: FindingEntity = {
    id: findingId,
    projectId,
    title: 'SQL Injection in Auth Controller',
    description: 'Vulnerable login parameter',
    severity: 'CRITICAL',
    category: 'INJECTION',
    cvssScore: 9.8,
    status: 'VERIFIED',
    createdById: 'analyst-1',
    assignedToId: devActor.id,
    dueDate: null,
    isDeleted: false,
    version: 4,
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  const defaultOpenFinding: FindingEntity = {
    ...defaultVerifiedFinding,
    status: 'OPEN',
    assignedToId: null,
    version: 1,
  };

  const defaultClosedFinding: FindingEntity = {
    ...defaultVerifiedFinding,
    status: 'CLOSED',
    version: 5,
  };

  beforeEach(() => {
    mockFindingRepo = {
      findById: vi.fn().mockImplementation((id: string) => {
        if (id === findingId) return Promise.resolve(defaultVerifiedFinding);
        return Promise.resolve(null);
      }),
      lockFinding: vi.fn().mockImplementation((id: string) => {
        if (id === findingId) return Promise.resolve(defaultVerifiedFinding);
        return Promise.resolve(null);
      }),
      updateAtomic: vi.fn().mockImplementation((id: string, data: { expectedVersion: number; status?: FindingEntity['status']; isDeleted?: boolean }) => {
        return Promise.resolve({
          ...defaultVerifiedFinding,
          status: data.status ?? defaultVerifiedFinding.status,
          isDeleted: data.isDeleted ?? defaultVerifiedFinding.isDeleted,
          version: data.expectedVersion + 1,
        });
      }),
      softDelete: vi.fn().mockImplementation((id: string, expectedVersion: number) => {
        return Promise.resolve({
          ...defaultVerifiedFinding,
          isDeleted: true,
          version: expectedVersion + 1,
        });
      }),
      addEvent: vi.fn().mockResolvedValue({
        id: 'ev-1',
        findingId,
        actorId: analystActor.id,
        eventType: 'STATUS_CHANGED',
        createdAt: new Date(),
      }),
      getEvents: vi.fn().mockResolvedValue([]),
    };

    mockProjectRepo = {
      lockProject: vi.fn().mockResolvedValue(mockProject),
      lockMember: vi.fn().mockImplementation((projId: string, userId: string) => {
        if (projId !== projectId) return Promise.resolve(null);
        if (userId === nonMemberActor.id) return Promise.resolve(null);
        if (userId === devActor.id) {
          return Promise.resolve({
            id: 'mem-dev',
            projectId: projId,
            userId,
            role: 'DEVELOPER',
            addedById: 'admin-1',
            createdAt: new Date(),
            updatedAt: new Date(),
          } as ProjectMemberEntity);
        }
        if (userId === adminActor.id) return Promise.resolve(null);
        return Promise.resolve({
          id: 'mem-analyst',
          projectId: projId,
          userId,
          role: 'ANALYST',
          addedById: 'admin-1',
          createdAt: new Date(),
          updatedAt: new Date(),
        } as ProjectMemberEntity);
      }),
    };

    mockUserRepo = {
      findAuthoritativeUser: vi.fn().mockImplementation((id: string) => {
        if (id === devActor.id) {
          return Promise.resolve({
            id,
            isActive: true,
            globalRole: 'DEVELOPER',
            memberships: [{ projectId, role: 'DEVELOPER' }],
          });
        }
        if (id === adminActor.id) {
          return Promise.resolve({
            id,
            isActive: true,
            globalRole: 'ADMIN',
            memberships: [],
          });
        }
        if (id === nonMemberActor.id) {
          return Promise.resolve({
            id,
            isActive: true,
            globalRole: 'ANALYST',
            memberships: [],
          });
        }
        return Promise.resolve({
          id,
          isActive: true,
          globalRole: 'ANALYST',
          memberships: [{ projectId, role: 'ANALYST' }],
        });
      }),
      lockUsers: vi.fn().mockImplementation((userIds: string[]) => {
        const map = new Map<string, UserAuthEntity>();
        for (const id of userIds) {
          let globalRole: UserAuthEntity['globalRole'] = 'ANALYST';
          if (id === devActor.id) globalRole = 'DEVELOPER';
          if (id === adminActor.id) globalRole = 'ADMIN';
          map.set(id, { id, isActive: true, globalRole });
        }
        return Promise.resolve(map);
      }),
    };

    mockAuditRepo = {
      append: vi.fn().mockResolvedValue({
        id: 'audit-1',
        actorId: analystActor.id,
        eventCategory: 'FINDING',
        eventType: 'finding.closed',
        resourceId: findingId,
        resourceType: 'finding',
        createdAt: new Date(),
      }),
    };

    mockTaskRepo = {
      findActiveByFindingId: vi.fn().mockResolvedValue(null),
    };

    mockRepos = {
      findingRepo: mockFindingRepo as IFindingRepository,
      projectRepo: mockProjectRepo as IProjectRepository,
      auditRepo: mockAuditRepo as IAuditRepository,
      userRepo: mockUserRepo as IUserRepository,
      taskRepo: mockTaskRepo as ITaskRepository,
    };

    service = createTestFindingService(mockRepos);
  });

  // ==========================================================================
  // 1. Ordinary Finding Closure (closeFinding)
  // ==========================================================================
  describe('1. Ordinary Finding Closure (closeFinding)', () => {
    it('authorized Analyst successfully closes VERIFIED finding with OCC and atomic events', async () => {
      const result = await service.closeFinding(analystActor, findingId, {
        expectedVersion: 4,
        notes: 'Fix confirmed in staging environment',
      });

      expect(result.status).toBe('CLOSED');
      expect(result.version).toBe(5);

      // Verify finding lifecycle event
      expect(mockFindingRepo.addEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          findingId,
          actorId: analystActor.id,
          eventType: 'STATUS_CHANGED',
          previousStatus: 'VERIFIED',
          newStatus: 'CLOSED',
          metadata: { notes: 'Fix confirmed in staging environment' },
        }),
      );

      // Verify audit event
      expect(mockAuditRepo.append).toHaveBeenCalledWith(
        expect.objectContaining({
          actorId: analystActor.id,
          eventCategory: 'FINDING',
          eventType: 'finding.closed',
          resourceId: findingId,
          resourceType: 'finding',
          beforeState: { status: 'VERIFIED', version: 4 },
          afterState: { status: 'CLOSED', version: 5, notes: 'Fix confirmed in staging environment' },
        }),
      );
    });

    it('rejects Admin attempt to perform ordinary closeFinding with HTTP 403 Forbidden (F-13 / FindingPolicy)', async () => {
      await expect(
        service.closeFinding(adminActor, findingId, { expectedVersion: 4 }),
      ).rejects.toThrow(
        expect.objectContaining({
          statusCode: 403,
          code: 'FORBIDDEN',
        }),
      );
    });

    it('rejects Developer closure with HTTP 403 Forbidden', async () => {
      await expect(
        service.closeFinding(devActor, findingId, { expectedVersion: 4 }),
      ).rejects.toThrow(ForbiddenError);
    });

    it('rejects operational closure by global Admin with HTTP 403 Forbidden', async () => {
      await expect(
        service.closeFinding(adminActor, findingId, { expectedVersion: 4 }),
      ).rejects.toThrow(ForbiddenError);
    });

    it('rejects closure of non-VERIFIED finding with HTTP 422 InvalidStateTransitionError', async () => {
      (mockFindingRepo.findById as ReturnType<typeof vi.fn>).mockResolvedValue(defaultOpenFinding);
      (mockFindingRepo.lockFinding as ReturnType<typeof vi.fn>).mockResolvedValue(defaultOpenFinding);

      await expect(
        service.closeFinding(analystActor, findingId, { expectedVersion: 1 }),
      ).rejects.toThrow(InvalidStateTransitionError);
    });

    it('OCC conflict check precedes state validation: stale version throws HTTP 409 ConcurrencyConflictError even on invalid state', async () => {
      (mockFindingRepo.findById as ReturnType<typeof vi.fn>).mockResolvedValue(defaultOpenFinding);
      (mockFindingRepo.lockFinding as ReturnType<typeof vi.fn>).mockResolvedValue(defaultOpenFinding);

      // finding is OPEN (version 1), caller sends expectedVersion: 99
      await expect(
        service.closeFinding(analystActor, findingId, { expectedVersion: 99 }),
      ).rejects.toThrow(ConcurrencyConflictError);
    });

    it('rejects non-member Analyst with HTTP 404 EntityNotFoundError (existence hiding)', async () => {
      await expect(
        service.closeFinding(nonMemberActor, findingId, { expectedVersion: 4 }),
      ).rejects.toThrow(EntityNotFoundError);
    });

    it('rejects closure in archived project with HTTP 403 Forbidden', async () => {
      (mockProjectRepo.lockProject as ReturnType<typeof vi.fn>).mockResolvedValue({
        ...mockProject,
        isActive: false,
      });

      await expect(
        service.closeFinding(analystActor, findingId, { expectedVersion: 4 }),
      ).rejects.toThrow(ForbiddenError);
    });

    it('rejects closure if Analyst account is deactivated in database with HTTP 403 Forbidden', async () => {
      (mockUserRepo.lockUsers as ReturnType<typeof vi.fn>).mockResolvedValue(
        new Map([[analystActor.id, { id: analystActor.id, isActive: false, globalRole: 'ANALYST' }]]),
      );

      await expect(
        service.closeFinding(analystActor, findingId, { expectedVersion: 4 }),
      ).rejects.toThrow(ForbiddenError);
    });
  });

  // ==========================================================================
  // 2. Exceptional Admin Force-Close (forceCloseFinding)
  // ==========================================================================
  describe('2. Exceptional Admin Force-Close (forceCloseFinding)', () => {
    beforeEach(() => {
      (mockFindingRepo.findById as ReturnType<typeof vi.fn>).mockResolvedValue(defaultOpenFinding);
      (mockFindingRepo.lockFinding as ReturnType<typeof vi.fn>).mockResolvedValue(defaultOpenFinding);
    });

    it('authorized Admin successfully force-closes OPEN finding with mandatory justification', async () => {
      const result = await service.forceCloseFinding(adminActor, findingId, {
        expectedVersion: 1,
        justification: 'Unactionable third-party dependency false positive confirmed by vendor errata',
      });

      expect(result.status).toBe('CLOSED');
      expect(result.version).toBe(2);

      // Verify finding lifecycle event with justification
      expect(mockFindingRepo.addEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          findingId,
          actorId: adminActor.id,
          eventType: 'STATUS_CHANGED',
          previousStatus: 'OPEN',
          newStatus: 'CLOSED',
          metadata: { justification: 'Unactionable third-party dependency false positive confirmed by vendor errata' },
        }),
      );

      // Verify audit event with justification in afterState
      expect(mockAuditRepo.append).toHaveBeenCalledWith(
        expect.objectContaining({
          actorId: adminActor.id,
          eventCategory: 'FINDING',
          eventType: 'finding.force_closed',
          resourceId: findingId,
          resourceType: 'finding',
          beforeState: { status: 'OPEN', version: 1 },
          afterState: {
            status: 'CLOSED',
            version: 2,
            justification: 'Unactionable third-party dependency false positive confirmed by vendor errata',
          },
        }),
      );
    });

    it('rejects force-close by Analyst with HTTP 403 Forbidden', async () => {
      await expect(
        service.forceCloseFinding(analystActor, findingId, {
          expectedVersion: 1,
          justification: 'Analyst attempting admin action',
        }),
      ).rejects.toThrow(ForbiddenError);
    });

    it('rejects force-close by Developer with HTTP 403 Forbidden', async () => {
      await expect(
        service.forceCloseFinding(devActor, findingId, {
          expectedVersion: 1,
          justification: 'Developer attempting admin action',
        }),
      ).rejects.toThrow(ForbiddenError);
    });

    it('rejects force-close when justification is empty or whitespace-only (schema validation)', async () => {
      await expect(
        service.forceCloseFinding(adminActor, findingId, {
          expectedVersion: 1,
          justification: '',
        }),
      ).rejects.toThrow();

      await expect(
        service.forceCloseFinding(adminActor, findingId, {
          expectedVersion: 1,
          justification: '   \t\n  ',
        }),
      ).rejects.toThrow();
    });

    it('rejects force-close on non-OPEN finding with HTTP 422 InvalidStateTransitionError', async () => {
      (mockFindingRepo.findById as ReturnType<typeof vi.fn>).mockResolvedValue(defaultVerifiedFinding);
      (mockFindingRepo.lockFinding as ReturnType<typeof vi.fn>).mockResolvedValue(defaultVerifiedFinding);

      await expect(
        service.forceCloseFinding(adminActor, findingId, {
          expectedVersion: 4,
          justification: 'Valid justification on VERIFIED finding',
        }),
      ).rejects.toThrow(InvalidStateTransitionError);
    });

    it('rejects force-close on already CLOSED finding with HTTP 422 InvalidStateTransitionError', async () => {
      (mockFindingRepo.findById as ReturnType<typeof vi.fn>).mockResolvedValue(defaultClosedFinding);
      (mockFindingRepo.lockFinding as ReturnType<typeof vi.fn>).mockResolvedValue(defaultClosedFinding);

      await expect(
        service.forceCloseFinding(adminActor, findingId, {
          expectedVersion: 5,
          justification: 'Already closed finding',
        }),
      ).rejects.toThrow(InvalidStateTransitionError);
    });

    it('rejects force-close if Admin was downgraded in database before lock with HTTP 403 Forbidden', async () => {
      (mockUserRepo.lockUsers as ReturnType<typeof vi.fn>).mockResolvedValue(
        new Map([[adminActor.id, { id: adminActor.id, isActive: true, globalRole: 'DEVELOPER' }]]),
      );

      await expect(
        service.forceCloseFinding(adminActor, findingId, {
          expectedVersion: 1,
          justification: 'Valid justification',
        }),
      ).rejects.toThrow(ForbiddenError);
    });

    it('rejects force-close if Admin account is deactivated with HTTP 403 Forbidden', async () => {
      (mockUserRepo.lockUsers as ReturnType<typeof vi.fn>).mockResolvedValue(
        new Map([[adminActor.id, { id: adminActor.id, isActive: false, globalRole: 'ADMIN' }]]),
      );

      await expect(
        service.forceCloseFinding(adminActor, findingId, {
          expectedVersion: 1,
          justification: 'Valid justification',
        }),
      ).rejects.toThrow(ForbiddenError);
    });
  });

  // ==========================================================================
  // 3. Exceptional Admin Force-Reopen (forceReopenFinding)
  // ==========================================================================
  describe('3. Exceptional Admin Force-Reopen (forceReopenFinding)', () => {
    beforeEach(() => {
      (mockFindingRepo.findById as ReturnType<typeof vi.fn>).mockResolvedValue(defaultClosedFinding);
      (mockFindingRepo.lockFinding as ReturnType<typeof vi.fn>).mockResolvedValue(defaultClosedFinding);
    });

    it('authorized Admin successfully force-reopens CLOSED finding with mandatory justification', async () => {
      const result = await service.forceReopenFinding(adminActor, findingId, {
        expectedVersion: 5,
        justification: 'Regression observed in canary deployment post-closure',
      });

      expect(result.status).toBe('REOPENED');
      expect(result.version).toBe(6);

      // Verify finding lifecycle event (eventType: REOPENED)
      expect(mockFindingRepo.addEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          findingId,
          actorId: adminActor.id,
          eventType: 'REOPENED',
          previousStatus: 'CLOSED',
          newStatus: 'REOPENED',
          metadata: { justification: 'Regression observed in canary deployment post-closure' },
        }),
      );

      // Verify audit event
      expect(mockAuditRepo.append).toHaveBeenCalledWith(
        expect.objectContaining({
          actorId: adminActor.id,
          eventCategory: 'FINDING',
          eventType: 'finding.force_reopened',
          resourceId: findingId,
          resourceType: 'finding',
          beforeState: { status: 'CLOSED', version: 5 },
          afterState: {
            status: 'REOPENED',
            version: 6,
            justification: 'Regression observed in canary deployment post-closure',
          },
        }),
      );
    });

    it('rejects force-reopen by Analyst with HTTP 403 Forbidden', async () => {
      await expect(
        service.forceReopenFinding(analystActor, findingId, {
          expectedVersion: 5,
          justification: 'Analyst attempting force-reopen',
        }),
      ).rejects.toThrow(ForbiddenError);
    });

    it('rejects force-reopen by Developer with HTTP 403 Forbidden', async () => {
      await expect(
        service.forceReopenFinding(devActor, findingId, {
          expectedVersion: 5,
          justification: 'Developer attempting force-reopen',
        }),
      ).rejects.toThrow(ForbiddenError);
    });

    it('rejects force-reopen on non-CLOSED finding with HTTP 422 InvalidStateTransitionError', async () => {
      (mockFindingRepo.findById as ReturnType<typeof vi.fn>).mockResolvedValue(defaultOpenFinding);
      (mockFindingRepo.lockFinding as ReturnType<typeof vi.fn>).mockResolvedValue(defaultOpenFinding);

      await expect(
        service.forceReopenFinding(adminActor, findingId, {
          expectedVersion: 1,
          justification: 'Cannot reopen OPEN finding',
        }),
      ).rejects.toThrow(InvalidStateTransitionError);
    });

    it('OCC conflict check precedes state validation: stale version throws HTTP 409 ConcurrencyConflictError', async () => {
      await expect(
        service.forceReopenFinding(adminActor, findingId, {
          expectedVersion: 99,
          justification: 'Stale version check',
        }),
      ).rejects.toThrow(ConcurrencyConflictError);
    });
  });

  // ==========================================================================
  // 4. Soft Deletion (softDeleteFinding)
  // ==========================================================================
  describe('4. Soft Deletion (softDeleteFinding)', () => {
    it('authorized Analyst successfully soft-deletes finding with version increment and audit', async () => {
      const result = await service.softDeleteFinding(analystActor, findingId, {
        expectedVersion: 4,
      });

      expect(result.isDeleted).toBe(true);
      expect(result.version).toBe(5);

      // Verify finding lifecycle event (eventType: DELETED)
      expect(mockFindingRepo.addEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          findingId,
          actorId: analystActor.id,
          eventType: 'DELETED',
          previousStatus: 'VERIFIED',
          newStatus: 'VERIFIED',
        }),
      );

      // Verify audit event
      expect(mockAuditRepo.append).toHaveBeenCalledWith(
        expect.objectContaining({
          actorId: analystActor.id,
          eventCategory: 'FINDING',
          eventType: 'finding.deleted',
          resourceId: findingId,
          resourceType: 'finding',
          beforeState: { isDeleted: false, version: 4 },
          afterState: { isDeleted: true, version: 5 },
        }),
      );
    });

    it('rejects Developer soft deletion with HTTP 403 Forbidden', async () => {
      await expect(
        service.softDeleteFinding(devActor, findingId, { expectedVersion: 4 }),
      ).rejects.toThrow(ForbiddenError);
    });

    it('rejects Admin operational soft deletion with HTTP 403 Forbidden', async () => {
      await expect(
        service.softDeleteFinding(adminActor, findingId, { expectedVersion: 4 }),
      ).rejects.toThrow(ForbiddenError);
    });

    it('rejects soft deletion of already deleted finding with HTTP 404 EntityNotFoundError (existence hiding)', async () => {
      (mockFindingRepo.findById as ReturnType<typeof vi.fn>).mockResolvedValue({
        ...defaultVerifiedFinding,
        isDeleted: true,
      });

      await expect(
        service.softDeleteFinding(analystActor, findingId, { expectedVersion: 4 }),
      ).rejects.toThrow(EntityNotFoundError);
    });

    it('rejects soft deletion by non-member with HTTP 404 EntityNotFoundError (existence hiding)', async () => {
      await expect(
        service.softDeleteFinding(nonMemberActor, findingId, { expectedVersion: 4 }),
      ).rejects.toThrow(EntityNotFoundError);
    });

    it('rejects soft deletion with stale expectedVersion with HTTP 409 ConcurrencyConflictError', async () => {
      await expect(
        service.softDeleteFinding(analystActor, findingId, { expectedVersion: 99 }),
      ).rejects.toThrow(ConcurrencyConflictError);
    });

    it('rejects soft deletion in archived project with HTTP 403 Forbidden', async () => {
      (mockProjectRepo.lockProject as ReturnType<typeof vi.fn>).mockResolvedValue({
        ...mockProject,
        isActive: false,
      });

      await expect(
        service.softDeleteFinding(analystActor, findingId, { expectedVersion: 4 }),
      ).rejects.toThrow(ForbiddenError);
    });
  });
});
