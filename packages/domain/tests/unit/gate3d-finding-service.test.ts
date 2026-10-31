import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  FindingService,
  type IFindingRepository,
  type IProjectRepository,
  type IAuditRepository,
  type IUserRepository,
  type ITaskRepository,
  type FindingEntity,
  type ProjectEntity,
  type ProjectMemberEntity,
  type UserAuthEntity,
} from '../../src/index.js';
import {
  createTestAdminActor,
  createTestAnalystActor,
  createTestDeveloperActor,
  createTestFindingService,
  type RepositoryContainer,
} from '../../src/testing/index.js';
import {
  ConcurrencyConflictError,
  EntityNotFoundError,
  ForbiddenError,
  InvalidStateTransitionError,
} from '@secureflow/shared';

describe('Gate 3D.3 — Transactional FindingService (Unit Tests)', () => {
  const projectId = '11111111-1111-1111-1111-111111111111';
  const otherProjectId = '22222222-2222-2222-2222-222222222222';
  const findingId = '33333333-3333-3333-3333-333333333333';
  const developerUserId = '44444444-4444-4444-4444-444444444444';

  let mockFindingRepo: Partial<IFindingRepository>;
  let mockProjectRepo: Partial<IProjectRepository>;
  let mockAuditRepo: Partial<IAuditRepository>;
  let mockUserRepo: Partial<IUserRepository>;
  let mockRepos: RepositoryContainer;
  let service: FindingService;

  beforeEach(() => {
    const defaultFinding: FindingEntity = {
      id: findingId,
      projectId,
      title: 'Mock Vulnerability',
      description: 'Mock flaw',
      severity: 'HIGH',
      category: 'INJECTION',
      cvssScore: 8.0,
      status: 'OPEN',
      createdById: 'analyst-1',
      assignedToId: null,
      dueDate: null,
      isDeleted: false,
      version: 1,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    mockFindingRepo = {
      create: vi.fn(),
      findById: vi.fn().mockImplementation((id: string) => {
        return Promise.resolve({ ...defaultFinding, id });
      }),
      findMany: vi.fn(),
      updateAtomic: vi.fn(),
      softDelete: vi.fn(),
      addEvent: vi.fn(),
      getEvents: vi.fn(),
      lockFinding: vi.fn().mockImplementation((id: string) => {
        return Promise.resolve({ ...defaultFinding, id });
      }),
    };

    mockProjectRepo = {
      findById: vi.fn(),
      lockProject: vi.fn().mockResolvedValue({ id: projectId, isActive: true }),
      lockMember: vi.fn().mockResolvedValue({ id: 'm-1', projectId, userId: 'analyst-1', role: 'ANALYST' }),
      isMember: vi.fn(),
    };

    mockAuditRepo = {
      append: vi.fn().mockResolvedValue({
        id: 'audit-1',
        actorId: 'analyst-1',
        eventCategory: 'FINDING',
        eventType: 'finding.created',
        resourceId: findingId,
        resourceType: 'finding',
        createdAt: new Date(),
      }),
      query: vi.fn(),
    };

    mockUserRepo = {
      findAuthoritativeUser: vi.fn().mockImplementation((id: string) => {
        // Default to active Analyst on projectId
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
          map.set(id, {
            id,
            isActive: true,
            globalRole: 'ANALYST',
          });
        }
        return Promise.resolve(map);
      }),
      lockUser: vi.fn(),
    };

    mockRepos = {
      findingRepo: mockFindingRepo as IFindingRepository,
      projectRepo: mockProjectRepo as IProjectRepository,
      auditRepo: mockAuditRepo as IAuditRepository,
      userRepo: mockUserRepo as IUserRepository,
      taskRepo: {} as ITaskRepository,
    };

    service = createTestFindingService(mockRepos);
  });

  // ==========================================================================
  // 1. Finding Creation (createFinding)
  // ==========================================================================
  describe('1. Finding Creation (createFinding)', () => {
    it('authorized Analyst successfully creates finding with OPEN status, version 1, and atomic events', async () => {
      const analyst = createTestAnalystActor(projectId);
      const mockProject: ProjectEntity = {
        id: projectId,
        name: 'Core Platform',
        slug: 'core-platform',
        description: null,
        isActive: true,
        createdById: 'admin-1',
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      const mockMember: ProjectMemberEntity = {
        id: 'member-1',
        projectId,
        userId: analyst.id,
        role: 'ANALYST',
        addedById: 'admin-1',
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      const createdFinding: FindingEntity = {
        id: findingId,
        projectId,
        title: 'SQL Injection in Auth Controller',
        description: 'User input not sanitized in login form',
        severity: 'CRITICAL',
        category: 'INJECTION',
        cvssScore: 9.8,
        status: 'OPEN',
        createdById: analyst.id,
        assignedToId: null,
        dueDate: null,
        isDeleted: false,
        version: 1,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      (mockProjectRepo.lockProject as ReturnType<typeof vi.fn>).mockResolvedValue(mockProject);
      (mockProjectRepo.lockMember as ReturnType<typeof vi.fn>).mockResolvedValue(mockMember);
      (mockFindingRepo.create as ReturnType<typeof vi.fn>).mockResolvedValue(createdFinding);
      (mockFindingRepo.addEvent as ReturnType<typeof vi.fn>).mockResolvedValue({ id: 'event-1' });

      const result = await service.createFinding(analyst, {
        projectId,
        title: 'SQL Injection in Auth Controller',
        description: 'User input not sanitized in login form',
        severity: 'CRITICAL',
        category: 'INJECTION',
        cvssScore: 9.8,
      });

      expect(result.id).toBe(findingId);
      expect(result.status).toBe('OPEN');
      expect(result.version).toBe(1);

      // Verify row locks acquired in correct order
      expect(mockUserRepo.lockUsers).toHaveBeenCalledWith([analyst.id], 'SHARE');
      expect(mockProjectRepo.lockProject).toHaveBeenCalledWith(projectId, 'SHARE');
      expect(mockProjectRepo.lockMember).toHaveBeenCalledWith(projectId, analyst.id, 'SHARE');

      // Verify FindingEvent created with CREATED enum
      expect(mockFindingRepo.addEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          findingId,
          actorId: analyst.id,
          eventType: 'CREATED',
          newStatus: 'OPEN',
        }),
      );

      // Verify AuditEvent appended with finding.created
      expect(mockAuditRepo.append).toHaveBeenCalledWith(
        expect.objectContaining({
          eventCategory: 'FINDING',
          eventType: 'finding.created',
          resourceId: findingId,
        }),
      );
    });

    it('rejects operational finding creation by global Admin with 403 Forbidden (NEG-13)', async () => {
      const admin = createTestAdminActor();
      (mockUserRepo.findAuthoritativeUser as ReturnType<typeof vi.fn>).mockResolvedValue({
        id: admin.id,
        isActive: true,
        globalRole: 'ADMIN',
        memberships: [],
      });

      await expect(
        service.createFinding(admin, {
          projectId,
          title: 'Admin Created Finding',
          description: 'Testing operational creation denial for admin',
          severity: 'HIGH',
          category: 'AUTH',
        }),
      ).rejects.toThrow(ForbiddenError);

      expect(mockFindingRepo.create).not.toHaveBeenCalled();
    });

    it('rejects finding creation by Developer with 403 Forbidden (NEG-04)', async () => {
      const developer = createTestDeveloperActor(projectId);
      (mockUserRepo.findAuthoritativeUser as ReturnType<typeof vi.fn>).mockResolvedValue({
        id: developer.id,
        isActive: true,
        globalRole: 'DEVELOPER',
        memberships: [{ projectId, role: 'DEVELOPER' }],
      });

      await expect(
        service.createFinding(developer, {
          projectId,
          title: 'Dev Created Finding',
          description: 'Developers cannot create findings',
          severity: 'LOW',
          category: 'LOGGING',
        }),
      ).rejects.toThrow(ForbiddenError);

      expect(mockFindingRepo.create).not.toHaveBeenCalled();
    });

    it('rejects cross-project Analyst creation with 404 EntityNotFoundError (existence hiding)', async () => {
      const analyst = createTestAnalystActor(otherProjectId);
      (mockUserRepo.findAuthoritativeUser as ReturnType<typeof vi.fn>).mockResolvedValue({
        id: analyst.id,
        isActive: true,
        globalRole: 'ANALYST',
        memberships: [{ projectId: otherProjectId, role: 'ANALYST' }],
      });

      await expect(
        service.createFinding(analyst, {
          projectId,
          title: 'Cross Project Finding',
          description: 'Analyst is not a member of target project',
          severity: 'MEDIUM',
          category: 'CONFIG_EXPOSURE',
        }),
      ).rejects.toThrow(EntityNotFoundError);

      expect(mockFindingRepo.create).not.toHaveBeenCalled();
    });

    it('rejects creation when actor account is deactivated in database (HTTP 403)', async () => {
      const analyst = createTestAnalystActor(projectId);
      (mockUserRepo.findAuthoritativeUser as ReturnType<typeof vi.fn>).mockResolvedValue({
        id: analyst.id,
        isActive: false,
        globalRole: 'ANALYST',
        memberships: [{ projectId, role: 'ANALYST' }],
      });

      await expect(
        service.createFinding(analyst, {
          projectId,
          title: 'Deactivated Actor Finding',
          description: 'Should be rejected',
          severity: 'HIGH',
          category: 'CRYPTO',
        }),
      ).rejects.toThrow(ForbiddenError);

      expect(mockFindingRepo.create).not.toHaveBeenCalled();
    });

    it('rejects creation when target project is archived (HTTP 403)', async () => {
      const analyst = createTestAnalystActor(projectId);
      (mockProjectRepo.lockProject as ReturnType<typeof vi.fn>).mockResolvedValue({
        id: projectId,
        isActive: false, // Archived
      });
      (mockProjectRepo.lockMember as ReturnType<typeof vi.fn>).mockResolvedValue({
        id: 'member-1',
        projectId,
        userId: analyst.id,
        role: 'ANALYST',
      });

      await expect(
        service.createFinding(analyst, {
          projectId,
          title: 'Archived Project Finding',
          description: 'Cannot add finding to archived project',
          severity: 'HIGH',
          category: 'AUTH',
        }),
      ).rejects.toThrow(ForbiddenError);
    });
  });

  // ==========================================================================
  // 2. Finding Retrieval (getFinding)
  // ==========================================================================
  describe('2. Finding Retrieval (getFinding)', () => {
    it('authorized Analyst retrieves finding in their permitted project', async () => {
      const analyst = createTestAnalystActor(projectId);
      const mockFinding: FindingEntity = {
        id: findingId,
        projectId,
        title: 'IDOR in User Profile',
        description: 'Access control flaw',
        severity: 'HIGH',
        category: 'IDOR',
        cvssScore: 8.1,
        status: 'OPEN',
        createdById: analyst.id,
        assignedToId: null,
        dueDate: null,
        isDeleted: false,
        version: 1,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      (mockFindingRepo.findById as ReturnType<typeof vi.fn>).mockResolvedValue(mockFinding);

      const result = await service.getFinding(analyst, findingId);
      expect(result.id).toBe(findingId);
      expect(mockFindingRepo.findById).toHaveBeenCalledWith(
        findingId,
        expect.objectContaining({ accessibleProjectIds: [projectId] }),
      );
    });

    it('Developer retrieves assigned finding in permitted project', async () => {
      const developer = createTestDeveloperActor(projectId, { id: developerUserId });
      (mockUserRepo.findAuthoritativeUser as ReturnType<typeof vi.fn>).mockResolvedValue({
        id: developerUserId,
        isActive: true,
        globalRole: 'DEVELOPER',
        memberships: [{ projectId, role: 'DEVELOPER' }],
      });

      const mockFinding: FindingEntity = {
        id: findingId,
        projectId,
        title: 'Assigned XSS Finding',
        description: 'Cross-site scripting flaw',
        severity: 'MEDIUM',
        category: 'XSS',
        cvssScore: 6.1,
        status: 'IN_PROGRESS',
        createdById: 'analyst-1',
        assignedToId: developerUserId,
        dueDate: null,
        isDeleted: false,
        version: 2,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      (mockFindingRepo.findById as ReturnType<typeof vi.fn>).mockResolvedValue(mockFinding);

      const result = await service.getFinding(developer, findingId);
      expect(result.id).toBe(findingId);
      expect(mockFindingRepo.findById).toHaveBeenCalledWith(
        findingId,
        expect.objectContaining({
          accessibleProjectIds: [projectId],
          assignedToUserId: developerUserId,
        }),
      );
    });

    it('Developer is denied unassigned finding with 404 EntityNotFoundError (existence hiding)', async () => {
      const developer = createTestDeveloperActor(projectId, { id: developerUserId });
      (mockUserRepo.findAuthoritativeUser as ReturnType<typeof vi.fn>).mockResolvedValue({
        id: developerUserId,
        isActive: true,
        globalRole: 'DEVELOPER',
        memberships: [{ projectId, role: 'DEVELOPER' }],
      });

      // Repository returns null because query scope excludes unassigned finding
      (mockFindingRepo.findById as ReturnType<typeof vi.fn>).mockResolvedValue(null);

      await expect(service.getFinding(developer, findingId)).rejects.toThrow(EntityNotFoundError);
    });

    it('soft-deleted finding is hidden from non-admin with 404 EntityNotFoundError (OLI-12)', async () => {
      const analyst = createTestAnalystActor(projectId);
      (mockFindingRepo.findById as ReturnType<typeof vi.fn>).mockResolvedValue(null);

      await expect(service.getFinding(analyst, findingId)).rejects.toThrow(EntityNotFoundError);
    });

    it('global Admin can retrieve soft-deleted finding', async () => {
      const admin = createTestAdminActor();
      (mockUserRepo.findAuthoritativeUser as ReturnType<typeof vi.fn>).mockResolvedValue({
        id: admin.id,
        isActive: true,
        globalRole: 'ADMIN',
        memberships: [],
      });

      const softDeletedFinding: FindingEntity = {
        id: findingId,
        projectId,
        title: 'Soft Deleted Vulnerability',
        description: 'Deleted flaw',
        severity: 'LOW',
        category: 'OTHER',
        cvssScore: 3.0,
        status: 'CLOSED',
        createdById: 'analyst-1',
        assignedToId: null,
        dueDate: null,
        isDeleted: true,
        version: 3,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      (mockFindingRepo.findById as ReturnType<typeof vi.fn>).mockResolvedValue(softDeletedFinding);

      const result = await service.getFinding(admin, findingId);
      expect(result.isDeleted).toBe(true);
    });
  });

  // ==========================================================================
  // 3. Finding Listing & Query Scoping (listFindings)
  // ==========================================================================
  describe('3. Finding Listing & Query Scoping (listFindings)', () => {
    it('Analyst listing is scoped to member project IDs', async () => {
      const analyst = createTestAnalystActor(projectId);
      (mockFindingRepo.findMany as ReturnType<typeof vi.fn>).mockResolvedValue({
        items: [],
        total: 0,
        page: 1,
        limit: 25,
        totalPages: 0,
      });

      await service.listFindings(analyst, { page: 1, limit: 10 });

      expect(mockFindingRepo.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          scope: expect.objectContaining({
            accessibleProjectIds: [projectId],
            unrestricted: false,
            includeDeleted: false,
          }),
          page: 1,
          limit: 10,
        }),
      );
    });

    it('Developer listing is constrained to assigned findings', async () => {
      const developer = createTestDeveloperActor(projectId, { id: developerUserId });
      (mockUserRepo.findAuthoritativeUser as ReturnType<typeof vi.fn>).mockResolvedValue({
        id: developerUserId,
        isActive: true,
        globalRole: 'DEVELOPER',
        memberships: [{ projectId, role: 'DEVELOPER' }],
      });

      (mockFindingRepo.findMany as ReturnType<typeof vi.fn>).mockResolvedValue({
        items: [],
        total: 0,
        page: 1,
        limit: 25,
        totalPages: 0,
      });

      await service.listFindings(developer);

      expect(mockFindingRepo.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          scope: expect.objectContaining({
            accessibleProjectIds: [projectId],
            assignedToUserId: developerUserId,
          }),
        }),
      );
    });

    it('Admin listing receives unrestricted scope', async () => {
      const admin = createTestAdminActor();
      (mockUserRepo.findAuthoritativeUser as ReturnType<typeof vi.fn>).mockResolvedValue({
        id: admin.id,
        isActive: true,
        globalRole: 'ADMIN',
        memberships: [],
      });

      (mockFindingRepo.findMany as ReturnType<typeof vi.fn>).mockResolvedValue({
        items: [],
        total: 0,
        page: 1,
        limit: 25,
        totalPages: 0,
      });

      await service.listFindings(admin, { includeDeleted: true });

      expect(mockFindingRepo.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          scope: expect.objectContaining({
            unrestricted: true,
            includeDeleted: true,
          }),
        }),
      );
    });

    it('Non-admin caller cannot force includeDeleted: true (ignored by scope derivation)', async () => {
      const analyst = createTestAnalystActor(projectId);
      (mockFindingRepo.findMany as ReturnType<typeof vi.fn>).mockResolvedValue({
        items: [],
        total: 0,
        page: 1,
        limit: 25,
        totalPages: 0,
      });

      await service.listFindings(analyst, { includeDeleted: true });

      expect(mockFindingRepo.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          scope: expect.objectContaining({
            includeDeleted: false,
          }),
        }),
      );
    });

    it('rejects filter with unexpected properties (strict schema validation)', async () => {
      const analyst = createTestAnalystActor(projectId);
      await expect(
        service.listFindings(analyst, { page: 1, unexpectedProp: true } as unknown as import('../../src/services/types.js').ListFindingsFilterInput),
      ).rejects.toThrow();
    });

    it('rejects filter with search exceeding 200 characters', async () => {
      const analyst = createTestAnalystActor(projectId);
      await expect(
        service.listFindings(analyst, { search: 'a'.repeat(201) }),
      ).rejects.toThrow();
    });
  });

  // ==========================================================================
  // 4. Metadata Updates (updateFindingMetadata)
  // ==========================================================================
  describe('4. Metadata Updates (updateFindingMetadata)', () => {
    it('updateFindingMetadata acquires row locks in canonical hierarchy: USERS (0) -> PROJECTS (1) -> PROJECT_MEMBERS (2) -> FINDINGS (3)', async () => {
      const analyst = createTestAnalystActor(projectId);
      const callOrder: string[] = [];

      (mockUserRepo.lockUsers as ReturnType<typeof vi.fn>).mockImplementation(async (userIds: string[]) => {
        callOrder.push('USERS');
        const map = new Map<string, UserAuthEntity>();
        for (const id of userIds) {
          map.set(id, { id, isActive: true, globalRole: 'ANALYST' });
        }
        return map;
      });
      (mockProjectRepo.lockProject as ReturnType<typeof vi.fn>).mockImplementation(async () => {
        callOrder.push('PROJECTS');
        return { id: projectId, isActive: true };
      });
      (mockProjectRepo.lockMember as ReturnType<typeof vi.fn>).mockImplementation(async () => {
        callOrder.push('PROJECT_MEMBERS');
        return { id: 'm-1', projectId, userId: analyst.id, role: 'ANALYST' };
      });
      (mockFindingRepo.lockFinding as ReturnType<typeof vi.fn>).mockImplementation(async () => {
        callOrder.push('FINDINGS');
        return {
          id: findingId,
          projectId,
          title: 'Original Title',
          description: 'Original description',
          severity: 'MEDIUM',
          category: 'AUTH',
          cvssScore: 5.0,
          status: 'OPEN',
          createdById: analyst.id,
          assignedToId: null,
          dueDate: null,
          isDeleted: false,
          version: 1,
          createdAt: new Date(),
          updatedAt: new Date(),
        };
      });
      (mockFindingRepo.updateAtomic as ReturnType<typeof vi.fn>).mockResolvedValue({
        id: findingId,
        projectId,
        title: 'Updated Title',
        description: 'Original description',
        severity: 'MEDIUM',
        category: 'AUTH',
        cvssScore: 5.0,
        status: 'OPEN',
        createdById: analyst.id,
        assignedToId: null,
        dueDate: null,
        isDeleted: false,
        version: 2,
        createdAt: new Date(),
        updatedAt: new Date(),
      });

      await service.updateFindingMetadata(analyst, findingId, {
        expectedVersion: 1,
        title: 'Updated Title',
      });

      expect(callOrder).toEqual(['USERS', 'PROJECTS', 'PROJECT_MEMBERS', 'FINDINGS']);
    });

    it('preliminary lookup throws 404 EntityNotFoundError if finding missing or soft-deleted (existence hiding)', async () => {
      const analyst = createTestAnalystActor(projectId);
      (mockFindingRepo.findById as ReturnType<typeof vi.fn>).mockResolvedValue(null);

      await expect(
        service.updateFindingMetadata(analyst, findingId, {
          expectedVersion: 1,
          title: 'Updated Title',
        }),
      ).rejects.toThrow(EntityNotFoundError);

      expect(mockUserRepo.lockUsers).not.toHaveBeenCalled();
      expect(mockFindingRepo.lockFinding).not.toHaveBeenCalled();
    });

    it('authorized Analyst updates metadata with atomic OCC increment and audit log', async () => {
      const analyst = createTestAnalystActor(projectId);
      const lockedFinding: FindingEntity = {
        id: findingId,
        projectId,
        title: 'Original Title',
        description: 'Original description',
        severity: 'MEDIUM',
        category: 'AUTH',
        cvssScore: 5.0,
        status: 'OPEN',
        createdById: analyst.id,
        assignedToId: null,
        dueDate: null,
        isDeleted: false,
        version: 1,
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      const updatedFinding: FindingEntity = {
        ...lockedFinding,
        title: 'Updated Title',
        severity: 'HIGH',
        cvssScore: 7.5,
        version: 2,
      };

      (mockFindingRepo.lockFinding as ReturnType<typeof vi.fn>).mockResolvedValue(lockedFinding);
      (mockProjectRepo.lockProject as ReturnType<typeof vi.fn>).mockResolvedValue({ id: projectId, isActive: true });
      (mockProjectRepo.lockMember as ReturnType<typeof vi.fn>).mockResolvedValue({ id: 'm-1', role: 'ANALYST' });
      (mockFindingRepo.updateAtomic as ReturnType<typeof vi.fn>).mockResolvedValue(updatedFinding);
      (mockFindingRepo.addEvent as ReturnType<typeof vi.fn>).mockResolvedValue({ id: 'event-2' });

      const result = await service.updateFindingMetadata(analyst, findingId, {
        expectedVersion: 1,
        title: 'Updated Title',
        severity: 'HIGH',
        cvssScore: 7.5,
      });

      expect(result.version).toBe(2);
      expect(result.title).toBe('Updated Title');

      // Verify atomic OCC update was called with expectedVersion
      expect(mockFindingRepo.updateAtomic).toHaveBeenCalledWith(
        findingId,
        expect.objectContaining({
          expectedVersion: 1,
          title: 'Updated Title',
          severity: 'HIGH',
          cvssScore: 7.5,
        }),
      );

      // Verify FindingEvent UPDATED was generated
      expect(mockFindingRepo.addEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          findingId,
          eventType: 'UPDATED',
        }),
      );

      // Verify AuditEvent finding.metadata_updated was appended
      expect(mockAuditRepo.append).toHaveBeenCalledWith(
        expect.objectContaining({
          eventCategory: 'FINDING',
          eventType: 'finding.metadata_updated',
          resourceId: findingId,
        }),
      );
    });

    it('rejects update with stale expectedVersion with HTTP 409 ConcurrencyConflictError', async () => {
      const analyst = createTestAnalystActor(projectId);
      const lockedFinding: FindingEntity = {
        id: findingId,
        projectId,
        title: 'Original Title',
        description: 'Original description',
        severity: 'MEDIUM',
        category: 'AUTH',
        cvssScore: 5.0,
        status: 'OPEN',
        createdById: analyst.id,
        assignedToId: null,
        dueDate: null,
        isDeleted: false,
        version: 2, // Database already at version 2
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      (mockFindingRepo.lockFinding as ReturnType<typeof vi.fn>).mockResolvedValue(lockedFinding);
      (mockProjectRepo.lockProject as ReturnType<typeof vi.fn>).mockResolvedValue({ id: projectId, isActive: true });
      (mockProjectRepo.lockMember as ReturnType<typeof vi.fn>).mockResolvedValue({ id: 'm-1', role: 'ANALYST' });

      (mockFindingRepo.updateAtomic as ReturnType<typeof vi.fn>).mockRejectedValue(
        new ConcurrencyConflictError('Version mismatch', 2, 1),
      );

      await expect(
        service.updateFindingMetadata(analyst, findingId, {
          expectedVersion: 1, // Caller passed stale version 1
          title: 'New Title',
        }),
      ).rejects.toThrow(ConcurrencyConflictError);
    });

    it('rejects Developer metadata update with 403 Forbidden', async () => {
      const developer = createTestDeveloperActor(projectId, { id: developerUserId });
      (mockUserRepo.findAuthoritativeUser as ReturnType<typeof vi.fn>).mockResolvedValue({
        id: developerUserId,
        isActive: true,
        globalRole: 'DEVELOPER',
        memberships: [{ projectId, role: 'DEVELOPER' }],
      });

      const lockedFinding: FindingEntity = {
        id: findingId,
        projectId,
        title: 'Title',
        description: 'Description',
        severity: 'LOW',
        category: 'XSS',
        cvssScore: 3.0,
        status: 'OPEN',
        createdById: 'analyst-1',
        assignedToId: developerUserId,
        dueDate: null,
        isDeleted: false,
        version: 1,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      (mockFindingRepo.lockFinding as ReturnType<typeof vi.fn>).mockResolvedValue(lockedFinding);
      (mockProjectRepo.lockProject as ReturnType<typeof vi.fn>).mockResolvedValue({ id: projectId, isActive: true });
      (mockProjectRepo.lockMember as ReturnType<typeof vi.fn>).mockResolvedValue({ id: 'm-1', role: 'DEVELOPER' });

      await expect(
        service.updateFindingMetadata(developer, findingId, {
          expectedVersion: 1,
          title: 'Developer Renaming',
        }),
      ).rejects.toThrow(ForbiddenError);
    });

    it('rejects unauthorized actor targeting finding in archived project with 404 EntityNotFoundError (existence hiding)', async () => {
      const foreignAnalyst = createTestAnalystActor(otherProjectId);
      (mockUserRepo.findAuthoritativeUser as ReturnType<typeof vi.fn>).mockResolvedValue({
        id: foreignAnalyst.id,
        isActive: true,
        globalRole: 'ANALYST',
        memberships: [{ projectId: otherProjectId, role: 'ANALYST' }],
      });

      (mockProjectRepo.lockProject as ReturnType<typeof vi.fn>).mockResolvedValue({ id: projectId, isActive: false });
      // Non-member in target project
      (mockProjectRepo.lockMember as ReturnType<typeof vi.fn>).mockResolvedValue(null);

      await expect(
        service.updateFindingMetadata(foreignAnalyst, findingId, {
          expectedVersion: 1,
          title: 'Unauthorized Metadata Attempt',
        }),
      ).rejects.toThrow(EntityNotFoundError);
    });

    it('rejects authorized member targeting finding in archived project with 403 Forbidden', async () => {
      const analyst = createTestAnalystActor(projectId);
      (mockProjectRepo.lockProject as ReturnType<typeof vi.fn>).mockResolvedValue({ id: projectId, isActive: false });
      // Member in target project
      (mockProjectRepo.lockMember as ReturnType<typeof vi.fn>).mockResolvedValue({ id: 'm-1', projectId, userId: analyst.id, role: 'ANALYST' });

      await expect(
        service.updateFindingMetadata(analyst, findingId, {
          expectedVersion: 1,
          title: 'Member Metadata Attempt on Archived Project',
        }),
      ).rejects.toThrow(ForbiddenError);
    });
  });

  // ==========================================================================
  // 5. Finding Triage (triageFinding)
  // ==========================================================================
  describe('5. Finding Triage (triageFinding)', () => {
    it('triageFinding acquires row locks in canonical hierarchy: USERS (0) -> PROJECTS (1) -> PROJECT_MEMBERS (2) -> FINDINGS (3)', async () => {
      const analyst = createTestAnalystActor(projectId);
      const callOrder: string[] = [];

      (mockUserRepo.lockUsers as ReturnType<typeof vi.fn>).mockImplementation(async (userIds: string[]) => {
        callOrder.push('USERS');
        const map = new Map<string, UserAuthEntity>();
        for (const id of userIds) {
          map.set(id, { id, isActive: true, globalRole: 'ANALYST' });
        }
        return map;
      });
      (mockProjectRepo.lockProject as ReturnType<typeof vi.fn>).mockImplementation(async () => {
        callOrder.push('PROJECTS');
        return { id: projectId, isActive: true };
      });
      (mockProjectRepo.lockMember as ReturnType<typeof vi.fn>).mockImplementation(async () => {
        callOrder.push('PROJECT_MEMBERS');
        return { id: 'm-1', projectId, userId: analyst.id, role: 'ANALYST' };
      });
      (mockFindingRepo.lockFinding as ReturnType<typeof vi.fn>).mockImplementation(async () => {
        callOrder.push('FINDINGS');
        return {
          id: findingId,
          projectId,
          title: 'Original Title',
          description: 'Original description',
          severity: 'MEDIUM',
          category: 'AUTH',
          cvssScore: 5.0,
          status: 'OPEN',
          createdById: analyst.id,
          assignedToId: null,
          dueDate: null,
          isDeleted: false,
          version: 1,
          createdAt: new Date(),
          updatedAt: new Date(),
        };
      });
      (mockFindingRepo.updateAtomic as ReturnType<typeof vi.fn>).mockResolvedValue({
        id: findingId,
        projectId,
        title: 'Original Title',
        description: 'Original description',
        severity: 'MEDIUM',
        category: 'AUTH',
        cvssScore: 5.0,
        status: 'TRIAGED',
        createdById: analyst.id,
        assignedToId: null,
        dueDate: null,
        isDeleted: false,
        version: 2,
        createdAt: new Date(),
        updatedAt: new Date(),
      });

      await service.triageFinding(analyst, findingId, {
        expectedVersion: 1,
      });

      expect(callOrder).toEqual(['USERS', 'PROJECTS', 'PROJECT_MEMBERS', 'FINDINGS']);
    });

    it('authorized Analyst triages OPEN finding to TRIAGED with version increment and audit', async () => {
      const analyst = createTestAnalystActor(projectId);
      const lockedFinding: FindingEntity = {
        id: findingId,
        projectId,
        title: 'Untriaged Vulnerability',
        description: 'Needs severity review',
        severity: 'LOW',
        category: 'SSRF',
        cvssScore: 4.0,
        status: 'OPEN',
        createdById: analyst.id,
        assignedToId: null,
        dueDate: null,
        isDeleted: false,
        version: 1,
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      const triagedFinding: FindingEntity = {
        ...lockedFinding,
        severity: 'HIGH',
        cvssScore: 7.5,
        status: 'TRIAGED',
        version: 2,
      };

      (mockFindingRepo.lockFinding as ReturnType<typeof vi.fn>).mockResolvedValue(lockedFinding);
      (mockProjectRepo.lockProject as ReturnType<typeof vi.fn>).mockResolvedValue({ id: projectId, isActive: true });
      (mockProjectRepo.lockMember as ReturnType<typeof vi.fn>).mockResolvedValue({ id: 'm-1', role: 'ANALYST' });
      (mockFindingRepo.updateAtomic as ReturnType<typeof vi.fn>).mockResolvedValue(triagedFinding);
      (mockFindingRepo.addEvent as ReturnType<typeof vi.fn>).mockResolvedValue({ id: 'event-3' });

      const result = await service.triageFinding(analyst, findingId, {
        expectedVersion: 1,
        severity: 'HIGH',
        cvssScore: 7.5,
      });

      expect(result.status).toBe('TRIAGED');
      expect(result.version).toBe(2);

      // Verify atomic OCC update
      expect(mockFindingRepo.updateAtomic).toHaveBeenCalledWith(
        findingId,
        expect.objectContaining({
          expectedVersion: 1,
          status: 'TRIAGED',
          severity: 'HIGH',
          cvssScore: 7.5,
        }),
      );

      // Verify FindingEvent STATUS_CHANGED
      expect(mockFindingRepo.addEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          findingId,
          eventType: 'STATUS_CHANGED',
          previousStatus: 'OPEN',
          newStatus: 'TRIAGED',
        }),
      );

      // Verify AuditEvent finding.triaged
      expect(mockAuditRepo.append).toHaveBeenCalledWith(
        expect.objectContaining({
          eventCategory: 'FINDING',
          eventType: 'finding.triaged',
          resourceId: findingId,
        }),
      );
    });

    it('rejects triage on non-OPEN finding with InvalidStateTransitionError', async () => {
      const analyst = createTestAnalystActor(projectId);
      const lockedFinding: FindingEntity = {
        id: findingId,
        projectId,
        title: 'Already Triaged Vulnerability',
        description: 'Already in progress',
        severity: 'HIGH',
        category: 'SSRF',
        cvssScore: 7.5,
        status: 'IN_PROGRESS', // Not OPEN!
        createdById: analyst.id,
        assignedToId: developerUserId,
        dueDate: null,
        isDeleted: false,
        version: 2,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      (mockFindingRepo.lockFinding as ReturnType<typeof vi.fn>).mockResolvedValue(lockedFinding);
      (mockProjectRepo.lockProject as ReturnType<typeof vi.fn>).mockResolvedValue({ id: projectId, isActive: true });
      (mockProjectRepo.lockMember as ReturnType<typeof vi.fn>).mockResolvedValue({ id: 'm-1', role: 'ANALYST' });

      await expect(
        service.triageFinding(analyst, findingId, {
          expectedVersion: 2,
        }),
      ).rejects.toThrow(InvalidStateTransitionError);

      expect(mockFindingRepo.updateAtomic).not.toHaveBeenCalled();
    });

    it('rejects triage by Developer with 403 Forbidden', async () => {
      const developer = createTestDeveloperActor(projectId, { id: developerUserId });
      (mockUserRepo.findAuthoritativeUser as ReturnType<typeof vi.fn>).mockResolvedValue({
        id: developerUserId,
        isActive: true,
        globalRole: 'DEVELOPER',
        memberships: [{ projectId, role: 'DEVELOPER' }],
      });

      const lockedFinding: FindingEntity = {
        id: findingId,
        projectId,
        title: 'Open Finding',
        description: 'Vulnerability',
        severity: 'LOW',
        category: 'OTHER',
        cvssScore: 2.0,
        status: 'OPEN',
        createdById: 'analyst-1',
        assignedToId: null,
        dueDate: null,
        isDeleted: false,
        version: 1,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      (mockFindingRepo.lockFinding as ReturnType<typeof vi.fn>).mockResolvedValue(lockedFinding);
      (mockProjectRepo.lockProject as ReturnType<typeof vi.fn>).mockResolvedValue({ id: projectId, isActive: true });
      (mockProjectRepo.lockMember as ReturnType<typeof vi.fn>).mockResolvedValue({ id: 'm-1', role: 'DEVELOPER' });

      await expect(
        service.triageFinding(developer, findingId, {
          expectedVersion: 1,
        }),
      ).rejects.toThrow(ForbiddenError);
    });
  });

  // ==========================================================================
  // 6. Service Initialization & Concurrency Errors
  // ==========================================================================
  describe('6. Service Initialization & Concurrency Errors', () => {
    it('rejects construction with incomplete repository container (HTTP 500)', () => {
      expect(
        () => new FindingService({ repositories: {} as unknown as RepositoryContainer }),
      ).toThrow(
        expect.objectContaining({
          code: 'SERVICE_INITIALIZATION_ERROR',
          statusCode: 500,
        }),
      );
    });

    it('rejects construction with invalid dependency object (HTTP 500)', () => {
      expect(
        () => new FindingService({ invalidProp: 'arbitrary' } as unknown as import('../../src/services/finding-service.js').FindingServiceInit),
      ).toThrow(
        expect.objectContaining({
          code: 'SERVICE_INITIALIZATION_ERROR',
          statusCode: 500,
        }),
      );
    });

    it('future stubs reject with NOT_IMPLEMENTED (501) referencing target sub-gate', async () => {
      const analyst = createTestAnalystActor(projectId);
      await expect(service.verifyFinding(analyst, findingId, { expectedVersion: 1, outcome: 'VERIFIED' }))
        .rejects.toThrow(/Sub-Gate 3D\.4/);
      await expect(service.closeFinding(analyst, findingId, { expectedVersion: 1 }))
        .rejects.toThrow(/Sub-Gate 3D\.5/);
      await expect(service.forceCloseFinding(analyst, findingId, { expectedVersion: 1, justification: 'Valid FP justification' }))
        .rejects.toThrow(/Sub-Gate 3D\.5/);
      await expect(service.forceReopenFinding(analyst, findingId, { expectedVersion: 1, justification: 'Valid regression justification' }))
        .rejects.toThrow(/Sub-Gate 3D\.5/);
      await expect(service.softDeleteFinding(analyst, findingId, { expectedVersion: 1 }))
        .rejects.toThrow(/Sub-Gate 3D\.5/);
    });

    it('maps PostgreSQL deadlock error 40P01 to HTTP 409 TRANSACTION_DEADLOCK', async () => {
      const analyst = createTestAnalystActor(projectId);
      (mockProjectRepo.lockProject as ReturnType<typeof vi.fn>).mockRejectedValue(
        Object.assign(new Error('deadlock detected'), { code: '40P01' }),
      );

      await expect(
        service.createFinding(analyst, {
          projectId,
          title: 'Deadlock Test Finding',
          description: 'Testing deadlock mapping',
          severity: 'HIGH',
          category: 'INJECTION',
        }),
      ).rejects.toThrow(
        expect.objectContaining({
          code: 'TRANSACTION_DEADLOCK',
          statusCode: 409,
        }),
      );
    });

    it('maps PostgreSQL serialization error 40001 to HTTP 409 SERIALIZATION_FAILURE', async () => {
      const analyst = createTestAnalystActor(projectId);
      (mockProjectRepo.lockProject as ReturnType<typeof vi.fn>).mockRejectedValue(
        Object.assign(new Error('could not serialize access'), { code: '40001' }),
      );

      await expect(
        service.createFinding(analyst, {
          projectId,
          title: 'Serialization Test Finding',
          description: 'Testing serialization mapping',
          severity: 'HIGH',
          category: 'INJECTION',
        }),
      ).rejects.toThrow(
        expect.objectContaining({
          code: 'SERIALIZATION_FAILURE',
          statusCode: 409,
        }),
      );
    });
  });
});
