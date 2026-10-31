import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  ConcurrencyConflictError,
  EntityNotFoundError,
  ForbiddenError,
  InvalidStateTransitionError,
} from '@secureflow/shared';
import type {
  IFindingRepository,
  IProjectRepository,
  IAuditRepository,
  IUserRepository,
  ITaskRepository,
  RepositoryContainer,
  ProjectEntity,
  FindingEntity,
  RemediationTaskEntity,
  FindingEventEntity,
  UserAuthEntity,
} from '../../src/db/repositories/types.js';
import {
  createTestAdminActor,
  createTestAnalystActor,
  createTestDeveloperActor,
  createTestFindingService,
  createTestTaskService,
} from '../../src/testing/index.js';
import { FindingService } from '../../src/services/finding-service.js';
import { TaskService } from '../../src/services/task-service.js';

describe('Gate 3D.4 — TaskService & FindingService Assignment/Remediation/Verification Unit Tests', () => {
  const projectId = '11111111-1111-4111-8111-111111111111';
  const otherProjectId = '22222222-2222-4222-8222-222222222222';
  const findingId = '33333333-3333-4333-8333-333333333333';
  const taskId = '44444444-4444-4444-8444-444444444444';
  const analystId = '00000000-0000-0000-0000-000000000002';
  const dev1Id = '00000000-0000-0000-0000-000000000003';
  const dev2Id = '00000000-0000-0000-0000-000000000004';

  let mockFindingRepo: Partial<IFindingRepository>;
  let mockProjectRepo: Partial<IProjectRepository>;
  let mockTaskRepo: Partial<ITaskRepository>;
  let mockAuditRepo: Partial<IAuditRepository>;
  let mockUserRepo: Partial<IUserRepository>;
  let mockRepos: RepositoryContainer;
  let findingService: FindingService;
  let taskService: TaskService;

  beforeEach(() => {
    vi.clearAllMocks();

    mockFindingRepo = {
      findById: vi.fn(),
      findMany: vi.fn(),
      create: vi.fn(),
      updateAtomic: vi.fn(),
      softDelete: vi.fn(),
      addEvent: vi.fn().mockImplementation((d) =>
        Promise.resolve({
          id: '55555555-5555-4555-8555-555555555555',
          findingId: d.findingId,
          actorId: d.actorId,
          eventType: d.eventType,
          previousStatus: d.previousStatus ?? null,
          newStatus: d.newStatus ?? null,
          metadata: d.metadata ?? null,
          createdAt: new Date(),
        } as FindingEventEntity),
      ),
      getEvents: vi.fn().mockResolvedValue([]),
      lockFinding: vi.fn(),
    };

    mockProjectRepo = {
      findById: vi.fn(),
      lockProject: vi.fn(),
      lockMember: vi.fn(),
      lockMembers: vi.fn(),
      getMemberRole: vi.fn(),
    };

    mockTaskRepo = {
      findById: vi.fn(),
      findByFindingId: vi.fn(),
      findActiveByFindingId: vi.fn(),
      create: vi.fn(),
      updateNotes: vi.fn(),
      updateStatus: vi.fn(),
      lockTask: vi.fn(),
      lockActiveTaskByFindingId: vi.fn(),
    };

    mockAuditRepo = {
      append: vi.fn().mockResolvedValue({
        id: '66666666-6666-4666-8666-666666666666',
        actorId: analystId,
        eventCategory: 'FINDING',
        eventType: 'finding.assigned',
        resourceId: findingId,
        resourceType: 'finding',
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
      findAuthoritativeUser: vi.fn(),
      lockUser: vi.fn(),
      lockUsers: vi.fn().mockImplementation((userIds: string[]) => {
        const map = new Map<string, UserAuthEntity>();
        for (const id of userIds) {
          map.set(id, {
            id,
            isActive: true,
            globalRole: id === analystId ? 'ANALYST' : 'DEVELOPER',
          });
        }
        return Promise.resolve(map);
      }),
    };

    mockRepos = {
      findingRepo: mockFindingRepo as IFindingRepository,
      projectRepo: mockProjectRepo as IProjectRepository,
      taskRepo: mockTaskRepo as ITaskRepository,
      auditRepo: mockAuditRepo as IAuditRepository,
      userRepo: mockUserRepo as IUserRepository,
    };

    findingService = createTestFindingService(mockRepos);
    taskService = createTestTaskService(mockRepos);
  });

  // ==========================================================================
  // Section A: Transactional TaskService
  // ==========================================================================
  describe('A. Transactional TaskService', () => {
    describe('1. getTask', () => {
      it('Admin actor can view any task in any project', async () => {
        const admin = createTestAdminActor();
        const mockTask: RemediationTaskEntity = {
          id: taskId,
          findingId,
          assignedToId: dev1Id,
          assignedById: analystId,
          description: 'Fix SQL injection',
          notes: 'Working on patch',
          status: 'IN_PROGRESS',
          dueDate: null,
          createdAt: new Date(),
          updatedAt: new Date(),
        };
        const mockFinding: FindingEntity = {
          id: findingId,
          projectId,
          title: 'SQL injection',
          description: 'SQLi in auth endpoint',
          severity: 'HIGH',
          category: 'INJECTION',
          cvssScore: 8.5,
          status: 'IN_PROGRESS',
          createdById: analystId,
          assignedToId: dev1Id,
          dueDate: null,
          isDeleted: false,
          version: 2,
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        (mockUserRepo.findAuthoritativeUser as ReturnType<typeof vi.fn>).mockResolvedValue({
          id: admin.id,
          isActive: true,
          globalRole: 'ADMIN',
          memberships: [],
        });
        (mockTaskRepo.findById as ReturnType<typeof vi.fn>).mockResolvedValue(mockTask);
        (mockFindingRepo.findById as ReturnType<typeof vi.fn>).mockResolvedValue(mockFinding);

        const result = await taskService.getTask(admin, taskId);
        expect(result).toEqual(mockTask);
      });

      it('Analyst member can view task in permitted project', async () => {
        const analyst = createTestAnalystActor(projectId);
        const mockTask: RemediationTaskEntity = {
          id: taskId,
          findingId,
          assignedToId: dev1Id,
          assignedById: analystId,
          description: 'Fix SQL injection',
          notes: null,
          status: 'PENDING',
          dueDate: null,
          createdAt: new Date(),
          updatedAt: new Date(),
        };
        const mockFinding: FindingEntity = {
          id: findingId,
          projectId,
          title: 'SQL injection',
          description: 'SQLi in auth endpoint',
          severity: 'HIGH',
          category: 'INJECTION',
          cvssScore: 8.5,
          status: 'IN_PROGRESS',
          createdById: analystId,
          assignedToId: dev1Id,
          dueDate: null,
          isDeleted: false,
          version: 2,
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        (mockUserRepo.findAuthoritativeUser as ReturnType<typeof vi.fn>).mockResolvedValue({
          id: analyst.id,
          isActive: true,
          globalRole: 'ANALYST',
          memberships: [{ projectId, role: 'ANALYST' }],
        });
        (mockTaskRepo.findById as ReturnType<typeof vi.fn>).mockResolvedValue(mockTask);
        (mockFindingRepo.findById as ReturnType<typeof vi.fn>).mockResolvedValue(mockFinding);

        const result = await taskService.getTask(analyst, taskId);
        expect(result.id).toBe(taskId);
      });

      it('Developer assigned to task can view task', async () => {
        const dev = createTestDeveloperActor(projectId, { id: dev1Id });
        const mockTask: RemediationTaskEntity = {
          id: taskId,
          findingId,
          assignedToId: dev1Id,
          assignedById: analystId,
          description: 'Fix SQL injection',
          notes: 'Progress notes',
          status: 'IN_PROGRESS',
          dueDate: null,
          createdAt: new Date(),
          updatedAt: new Date(),
        };
        const mockFinding: FindingEntity = {
          id: findingId,
          projectId,
          title: 'SQL injection',
          description: 'SQLi in auth endpoint',
          severity: 'HIGH',
          category: 'INJECTION',
          cvssScore: 8.5,
          status: 'IN_PROGRESS',
          createdById: analystId,
          assignedToId: dev1Id,
          dueDate: null,
          isDeleted: false,
          version: 2,
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        (mockUserRepo.findAuthoritativeUser as ReturnType<typeof vi.fn>).mockResolvedValue({
          id: dev1Id,
          isActive: true,
          globalRole: 'DEVELOPER',
          memberships: [{ projectId, role: 'DEVELOPER' }],
        });
        (mockTaskRepo.findById as ReturnType<typeof vi.fn>).mockResolvedValue(mockTask);
        (mockFindingRepo.findById as ReturnType<typeof vi.fn>).mockResolvedValue(mockFinding);

        const result = await taskService.getTask(dev, taskId);
        expect(result.id).toBe(taskId);
      });

      it('Developer NOT assigned to task is denied with 404 EntityNotFoundError (existence hiding)', async () => {
        const dev = createTestDeveloperActor(projectId, { id: dev2Id });
        const mockTask: RemediationTaskEntity = {
          id: taskId,
          findingId,
          assignedToId: dev1Id, // Assigned to dev1, not dev2
          assignedById: analystId,
          description: 'Fix SQL injection',
          notes: null,
          status: 'IN_PROGRESS',
          dueDate: null,
          createdAt: new Date(),
          updatedAt: new Date(),
        };
        const mockFinding: FindingEntity = {
          id: findingId,
          projectId,
          title: 'SQL injection',
          description: 'SQLi',
          severity: 'HIGH',
          category: 'INJECTION',
          cvssScore: 8.5,
          status: 'IN_PROGRESS',
          createdById: analystId,
          assignedToId: dev1Id,
          dueDate: null,
          isDeleted: false,
          version: 2,
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        (mockUserRepo.findAuthoritativeUser as ReturnType<typeof vi.fn>).mockResolvedValue({
          id: dev2Id,
          isActive: true,
          globalRole: 'DEVELOPER',
          memberships: [{ projectId, role: 'DEVELOPER' }],
        });
        (mockTaskRepo.findById as ReturnType<typeof vi.fn>).mockResolvedValue(mockTask);
        (mockFindingRepo.findById as ReturnType<typeof vi.fn>).mockResolvedValue(mockFinding);

        await expect(taskService.getTask(dev, taskId)).rejects.toThrow(EntityNotFoundError);
      });

      it('Non-member Analyst receives 404 EntityNotFoundError (existence hiding)', async () => {
        const analyst = createTestAnalystActor(otherProjectId);
        const mockTask: RemediationTaskEntity = {
          id: taskId,
          findingId,
          assignedToId: dev1Id,
          assignedById: analystId,
          description: 'Fix SQL injection',
          notes: null,
          status: 'PENDING',
          dueDate: null,
          createdAt: new Date(),
          updatedAt: new Date(),
        };
        const mockFinding: FindingEntity = {
          id: findingId,
          projectId, // target project is projectId, but caller only member of otherProjectId
          title: 'SQL injection',
          description: 'SQLi',
          severity: 'HIGH',
          category: 'INJECTION',
          cvssScore: 8.5,
          status: 'IN_PROGRESS',
          createdById: analystId,
          assignedToId: dev1Id,
          dueDate: null,
          isDeleted: false,
          version: 2,
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        (mockUserRepo.findAuthoritativeUser as ReturnType<typeof vi.fn>).mockResolvedValue({
          id: analyst.id,
          isActive: true,
          globalRole: 'ANALYST',
          memberships: [{ projectId: otherProjectId, role: 'ANALYST' }],
        });
        (mockTaskRepo.findById as ReturnType<typeof vi.fn>).mockResolvedValue(mockTask);
        (mockFindingRepo.findById as ReturnType<typeof vi.fn>).mockResolvedValue(mockFinding);

        await expect(taskService.getTask(analyst, taskId)).rejects.toThrow(EntityNotFoundError);
      });

      it('throws 404 if task does not exist', async () => {
        const analyst = createTestAnalystActor(projectId);
        (mockUserRepo.findAuthoritativeUser as ReturnType<typeof vi.fn>).mockResolvedValue({
          id: analyst.id,
          isActive: true,
          globalRole: 'ANALYST',
          memberships: [{ projectId, role: 'ANALYST' }],
        });
        (mockTaskRepo.findById as ReturnType<typeof vi.fn>).mockResolvedValue(null);

        await expect(taskService.getTask(analyst, taskId)).rejects.toThrow(EntityNotFoundError);
      });

      it('throws 403 if caller account is deactivated', async () => {
        const analyst = createTestAnalystActor(projectId);
        (mockUserRepo.findAuthoritativeUser as ReturnType<typeof vi.fn>).mockResolvedValue({
          id: analyst.id,
          isActive: false, // Deactivated
          globalRole: 'ANALYST',
          memberships: [{ projectId, role: 'ANALYST' }],
        });

        await expect(taskService.getTask(analyst, taskId)).rejects.toThrow(ForbiddenError);
      });
    });

    describe('2. getTaskByFindingId', () => {
      it('Analyst retrieves active task for finding in member project', async () => {
        const analyst = createTestAnalystActor(projectId);
        const mockFinding: FindingEntity = {
          id: findingId,
          projectId,
          title: 'SQL injection',
          description: 'SQLi',
          severity: 'HIGH',
          category: 'INJECTION',
          cvssScore: 8.5,
          status: 'IN_PROGRESS',
          createdById: analystId,
          assignedToId: dev1Id,
          dueDate: null,
          isDeleted: false,
          version: 2,
          createdAt: new Date(),
          updatedAt: new Date(),
        };
        const mockTask: RemediationTaskEntity = {
          id: taskId,
          findingId,
          assignedToId: dev1Id,
          assignedById: analystId,
          description: 'Fix SQL injection',
          notes: null,
          status: 'PENDING',
          dueDate: null,
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        (mockUserRepo.findAuthoritativeUser as ReturnType<typeof vi.fn>).mockResolvedValue({
          id: analyst.id,
          isActive: true,
          globalRole: 'ANALYST',
          memberships: [{ projectId, role: 'ANALYST' }],
        });
        (mockFindingRepo.findById as ReturnType<typeof vi.fn>).mockResolvedValue(mockFinding);
        (mockTaskRepo.findActiveByFindingId as ReturnType<typeof vi.fn>).mockResolvedValue(mockTask);

        const result = await taskService.getTaskByFindingId(analyst, findingId);
        expect(result).toEqual(mockTask);
      });

      it('returns null if finding has no active task', async () => {
        const analyst = createTestAnalystActor(projectId);
        const mockFinding: FindingEntity = {
          id: findingId,
          projectId,
          title: 'SQL injection',
          description: 'SQLi',
          severity: 'HIGH',
          category: 'INJECTION',
          cvssScore: 8.5,
          status: 'TRIAGED',
          createdById: analystId,
          assignedToId: null,
          dueDate: null,
          isDeleted: false,
          version: 1,
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        (mockUserRepo.findAuthoritativeUser as ReturnType<typeof vi.fn>).mockResolvedValue({
          id: analyst.id,
          isActive: true,
          globalRole: 'ANALYST',
          memberships: [{ projectId, role: 'ANALYST' }],
        });
        (mockFindingRepo.findById as ReturnType<typeof vi.fn>).mockResolvedValue(mockFinding);
        (mockTaskRepo.findActiveByFindingId as ReturnType<typeof vi.fn>).mockResolvedValue(null);

        const result = await taskService.getTaskByFindingId(analyst, findingId);
        expect(result).toBeNull();
      });

      it('Developer retrieves active task for assigned finding', async () => {
        const dev = createTestDeveloperActor(projectId, { id: dev1Id });
        const mockFinding: FindingEntity = {
          id: findingId,
          projectId,
          title: 'SQL injection',
          description: 'SQLi',
          severity: 'HIGH',
          category: 'INJECTION',
          cvssScore: 8.5,
          status: 'IN_PROGRESS',
          createdById: analystId,
          assignedToId: dev1Id,
          dueDate: null,
          isDeleted: false,
          version: 2,
          createdAt: new Date(),
          updatedAt: new Date(),
        };
        const mockTask: RemediationTaskEntity = {
          id: taskId,
          findingId,
          assignedToId: dev1Id,
          assignedById: analystId,
          description: 'Fix SQL injection',
          notes: null,
          status: 'PENDING',
          dueDate: null,
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        (mockUserRepo.findAuthoritativeUser as ReturnType<typeof vi.fn>).mockResolvedValue({
          id: dev1Id,
          isActive: true,
          globalRole: 'DEVELOPER',
          memberships: [{ projectId, role: 'DEVELOPER' }],
        });
        (mockFindingRepo.findById as ReturnType<typeof vi.fn>).mockResolvedValue(mockFinding);
        (mockTaskRepo.findActiveByFindingId as ReturnType<typeof vi.fn>).mockResolvedValue(mockTask);

        const result = await taskService.getTaskByFindingId(dev, findingId);
        expect(result?.id).toBe(taskId);
      });
    });

    describe('3. updateTaskNotes', () => {
      it('assigned Developer updates task notes under canonical row lock hierarchy (0 -> 1 -> 2 -> 3 -> 4) with atomic audit', async () => {
        const dev = createTestDeveloperActor(projectId, { id: dev1Id });
        const mockTask: RemediationTaskEntity = {
          id: taskId,
          findingId,
          assignedToId: dev1Id,
          assignedById: analystId,
          description: 'Fix SQL injection',
          notes: 'Old notes',
          status: 'IN_PROGRESS',
          dueDate: null,
          createdAt: new Date(),
          updatedAt: new Date(),
        };
        const mockFinding: FindingEntity = {
          id: findingId,
          projectId,
          title: 'SQL injection',
          description: 'SQLi',
          severity: 'HIGH',
          category: 'INJECTION',
          cvssScore: 8.5,
          status: 'IN_PROGRESS',
          createdById: analystId,
          assignedToId: dev1Id,
          dueDate: null,
          isDeleted: false,
          version: 2,
          createdAt: new Date(),
          updatedAt: new Date(),
        };
        const mockProject: ProjectEntity = {
          id: projectId,
          name: 'Core Platform',
          slug: 'core-platform',
          description: null,
          isActive: true,
          createdById: analystId,
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        const executionOrder: string[] = [];

        (mockTaskRepo.findById as ReturnType<typeof vi.fn>).mockResolvedValue(mockTask);
        (mockFindingRepo.findById as ReturnType<typeof vi.fn>).mockResolvedValue(mockFinding);

        (mockUserRepo.lockUsers as ReturnType<typeof vi.fn>).mockImplementation((userIds: string[]) => {
          executionOrder.push('LOCK_USERS_0');
          const map = new Map<string, UserAuthEntity>();
          for (const id of userIds) {
            map.set(id, { id, isActive: true, globalRole: 'DEVELOPER' });
          }
          return Promise.resolve(map);
        });

        (mockProjectRepo.lockProject as ReturnType<typeof vi.fn>).mockImplementation(() => {
          executionOrder.push('LOCK_PROJECT_1');
          return Promise.resolve(mockProject);
        });

        (mockProjectRepo.lockMember as ReturnType<typeof vi.fn>).mockImplementation(() => {
          executionOrder.push('LOCK_MEMBER_2');
          return Promise.resolve({
            projectId,
            userId: dev1Id,
            role: 'DEVELOPER',
            addedById: analystId,
            createdAt: new Date(),
          });
        });

        (mockFindingRepo.lockFinding as ReturnType<typeof vi.fn>).mockImplementation(() => {
          executionOrder.push('LOCK_FINDING_3');
          return Promise.resolve(mockFinding);
        });

        (mockTaskRepo.lockTask as ReturnType<typeof vi.fn>).mockImplementation(() => {
          executionOrder.push('LOCK_TASK_4');
          return Promise.resolve(mockTask);
        });

        const updatedTaskEntity: RemediationTaskEntity = {
          ...mockTask,
          notes: 'New progress update: patch submitted to CI',
        };
        (mockTaskRepo.updateNotes as ReturnType<typeof vi.fn>).mockResolvedValue(updatedTaskEntity);

        const updated = await taskService.updateTaskNotes(dev, taskId, {
          notes: 'New progress update: patch submitted to CI',
        });

        expect(updated.notes).toBe('New progress update: patch submitted to CI');
        expect(executionOrder).toEqual([
          'LOCK_USERS_0',
          'LOCK_PROJECT_1',
          'LOCK_MEMBER_2',
          'LOCK_FINDING_3',
          'LOCK_TASK_4',
        ]);

        expect(mockAuditRepo.append).toHaveBeenCalledWith(
          expect.objectContaining({
            actorId: dev1Id,
            eventCategory: 'TASK',
            eventType: 'task.notes_updated',
            resourceId: taskId,
            resourceType: 'remediation_task',
            beforeState: { notes: 'Old notes' },
            afterState: { notes: 'New progress update: patch submitted to CI' },
          }),
        );
      });

      it('rejects updateTaskNotes by Analyst with 403 Forbidden', async () => {
        const analyst = createTestAnalystActor(projectId);
        const mockTask: RemediationTaskEntity = {
          id: taskId,
          findingId,
          assignedToId: dev1Id,
          assignedById: analystId,
          description: 'Fix SQL injection',
          notes: null,
          status: 'IN_PROGRESS',
          dueDate: null,
          createdAt: new Date(),
          updatedAt: new Date(),
        };
        const mockFinding: FindingEntity = {
          id: findingId,
          projectId,
          title: 'SQL injection',
          description: 'SQLi',
          severity: 'HIGH',
          category: 'INJECTION',
          cvssScore: 8.5,
          status: 'IN_PROGRESS',
          createdById: analystId,
          assignedToId: dev1Id,
          dueDate: null,
          isDeleted: false,
          version: 2,
          createdAt: new Date(),
          updatedAt: new Date(),
        };
        const mockProject: ProjectEntity = {
          id: projectId,
          name: 'Core Platform',
          slug: 'core-platform',
          description: null,
          isActive: true,
          createdById: analystId,
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        (mockTaskRepo.findById as ReturnType<typeof vi.fn>).mockResolvedValue(mockTask);
        (mockFindingRepo.findById as ReturnType<typeof vi.fn>).mockResolvedValue(mockFinding);
        (mockProjectRepo.lockProject as ReturnType<typeof vi.fn>).mockResolvedValue(mockProject);
        (mockProjectRepo.lockMember as ReturnType<typeof vi.fn>).mockResolvedValue({
          projectId,
          userId: analyst.id,
          role: 'ANALYST',
          addedById: analyst.id,
          createdAt: new Date(),
        });
        (mockFindingRepo.lockFinding as ReturnType<typeof vi.fn>).mockResolvedValue(mockFinding);
        (mockTaskRepo.lockTask as ReturnType<typeof vi.fn>).mockResolvedValue(mockTask);

        await expect(taskService.updateTaskNotes(analyst, taskId, { notes: 'Note' })).rejects.toThrow(ForbiddenError);
      });

      it('rejects updateTaskNotes by unassigned Developer with 403 Forbidden', async () => {
        const dev2 = createTestDeveloperActor(projectId, { id: dev2Id });
        const mockTask: RemediationTaskEntity = {
          id: taskId,
          findingId,
          assignedToId: dev1Id, // Assigned to dev1, caller is dev2
          assignedById: analystId,
          description: 'Fix SQL injection',
          notes: null,
          status: 'IN_PROGRESS',
          dueDate: null,
          createdAt: new Date(),
          updatedAt: new Date(),
        };
        const mockFinding: FindingEntity = {
          id: findingId,
          projectId,
          title: 'SQL injection',
          description: 'SQLi',
          severity: 'HIGH',
          category: 'INJECTION',
          cvssScore: 8.5,
          status: 'IN_PROGRESS',
          createdById: analystId,
          assignedToId: dev1Id,
          dueDate: null,
          isDeleted: false,
          version: 2,
          createdAt: new Date(),
          updatedAt: new Date(),
        };
        const mockProject: ProjectEntity = {
          id: projectId,
          name: 'Core Platform',
          slug: 'core-platform',
          description: null,
          isActive: true,
          createdById: analystId,
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        (mockTaskRepo.findById as ReturnType<typeof vi.fn>).mockResolvedValue(mockTask);
        (mockFindingRepo.findById as ReturnType<typeof vi.fn>).mockResolvedValue(mockFinding);
        (mockProjectRepo.lockProject as ReturnType<typeof vi.fn>).mockResolvedValue(mockProject);
        (mockProjectRepo.lockMember as ReturnType<typeof vi.fn>).mockResolvedValue({
          projectId,
          userId: dev2Id,
          role: 'DEVELOPER',
          addedById: analystId,
          createdAt: new Date(),
        });
        (mockFindingRepo.lockFinding as ReturnType<typeof vi.fn>).mockResolvedValue(mockFinding);
        (mockTaskRepo.lockTask as ReturnType<typeof vi.fn>).mockResolvedValue(mockTask);

        await expect(taskService.updateTaskNotes(dev2, taskId, { notes: 'Note' })).rejects.toThrow(ForbiddenError);
      });
    });
  });

  // ==========================================================================
  // Section B: FindingService Sub-Gate 3D.4 Methods
  // ==========================================================================
  describe('B. FindingService Sub-Gate 3D.4 Operations', () => {
    describe('1. assignFinding', () => {
      it('authorized Analyst assigns TRIAGED finding to Developer with Level 0-3 locks, PENDING task, and atomic events', async () => {
        const analyst = createTestAnalystActor(projectId);
        const mockFinding: FindingEntity = {
          id: findingId,
          projectId,
          title: 'XSS flaw',
          description: 'Stored XSS in user profile',
          severity: 'HIGH',
          category: 'XSS',
          cvssScore: 7.5,
          status: 'TRIAGED',
          createdById: analystId,
          assignedToId: null,
          dueDate: null,
          isDeleted: false,
          version: 2,
          createdAt: new Date(),
          updatedAt: new Date(),
        };
        const mockProject: ProjectEntity = {
          id: projectId,
          name: 'Core Platform',
          slug: 'core-platform',
          description: null,
          isActive: true,
          createdById: analystId,
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        const executionOrder: string[] = [];

        (mockFindingRepo.findById as ReturnType<typeof vi.fn>).mockResolvedValue(mockFinding);

        (mockUserRepo.lockUsers as ReturnType<typeof vi.fn>).mockImplementation((userIds: string[]) => {
          executionOrder.push('LOCK_USERS_0');
          // Invariant: userIds locked in ascending lexical order
          expect(userIds).toEqual([...userIds].sort());
          const map = new Map<string, UserAuthEntity>();
          for (const id of userIds) {
            map.set(id, { id, isActive: true, globalRole: id === analystId ? 'ANALYST' : 'DEVELOPER' });
          }
          return Promise.resolve(map);
        });

        (mockProjectRepo.lockProject as ReturnType<typeof vi.fn>).mockImplementation(() => {
          executionOrder.push('LOCK_PROJECT_1');
          return Promise.resolve(mockProject);
        });

        (mockProjectRepo.lockMember as ReturnType<typeof vi.fn>).mockImplementation((_pid: string, uid: string) => {
          executionOrder.push(`LOCK_MEMBER_2_${uid}`);
          return Promise.resolve({
            projectId,
            userId: uid,
            role: uid === analystId ? 'ANALYST' : 'DEVELOPER',
            addedById: analystId,
            createdAt: new Date(),
          });
        });

        (mockFindingRepo.lockFinding as ReturnType<typeof vi.fn>).mockImplementation(() => {
          executionOrder.push('LOCK_FINDING_3');
          return Promise.resolve(mockFinding);
        });

        (mockTaskRepo.findActiveByFindingId as ReturnType<typeof vi.fn>).mockResolvedValue(null);

        const updatedFindingEntity: FindingEntity = {
          ...mockFinding,
          status: 'IN_PROGRESS',
          assignedToId: dev1Id,
          version: 3,
        };
        (mockFindingRepo.updateAtomic as ReturnType<typeof vi.fn>).mockResolvedValue(updatedFindingEntity);

        const createdTaskEntity: RemediationTaskEntity = {
          id: taskId,
          findingId,
          assignedToId: dev1Id,
          assignedById: analystId,
          description: 'Fix XSS vulnerability in profile page',
          notes: null,
          status: 'PENDING',
          dueDate: null,
          createdAt: new Date(),
          updatedAt: new Date(),
        };
        (mockTaskRepo.create as ReturnType<typeof vi.fn>).mockResolvedValue(createdTaskEntity);

        const result = await findingService.assignFinding(analyst, findingId, {
          expectedVersion: 2,
          assignedToId: dev1Id,
          taskDescription: 'Fix XSS vulnerability in profile page',
        });

        expect(result.status).toBe('IN_PROGRESS');
        expect(result.assignedToId).toBe(dev1Id);
        expect(result.version).toBe(3);

        expect(executionOrder).toEqual([
          'LOCK_USERS_0',
          'LOCK_PROJECT_1',
          'LOCK_MEMBER_2_' + analystId,
          'LOCK_MEMBER_2_' + dev1Id,
          'LOCK_FINDING_3',
        ]);

        // Verify task creation in PENDING status
        expect(mockTaskRepo.create).toHaveBeenCalledWith({
          findingId,
          assignedToId: dev1Id,
          assignedById: analystId,
          description: 'Fix XSS vulnerability in profile page',
          dueDate: null,
        });

        // Verify FindingEvent ASSIGNED
        expect(mockFindingRepo.addEvent).toHaveBeenCalledWith(
          expect.objectContaining({
            findingId,
            actorId: analystId,
            eventType: 'ASSIGNED',
            previousStatus: 'TRIAGED',
            newStatus: 'IN_PROGRESS',
            metadata: expect.objectContaining({
              assignedToId: dev1Id,
              taskId,
            }),
          }),
        );

        // Verify atomic AuditEvents
        expect(mockAuditRepo.append).toHaveBeenCalledWith(
          expect.objectContaining({
            actorId: analystId,
            eventCategory: 'FINDING',
            eventType: 'finding.assigned',
          }),
        );
        expect(mockAuditRepo.append).toHaveBeenCalledWith(
          expect.objectContaining({
            actorId: analystId,
            eventCategory: 'TASK',
            eventType: 'task.created',
          }),
        );
      });

      it('authorized Analyst assigns REOPENED finding to Developer with PENDING task', async () => {
        const analyst = createTestAnalystActor(projectId);
        const mockFinding: FindingEntity = {
          id: findingId,
          projectId,
          title: 'XSS flaw',
          description: 'Stored XSS in user profile',
          severity: 'HIGH',
          category: 'XSS',
          cvssScore: 7.5,
          status: 'REOPENED',
          createdById: analystId,
          assignedToId: dev1Id,
          dueDate: null,
          isDeleted: false,
          version: 4,
          createdAt: new Date(),
          updatedAt: new Date(),
        };
        const mockProject: ProjectEntity = {
          id: projectId,
          name: 'Core Platform',
          slug: 'core-platform',
          description: null,
          isActive: true,
          createdById: analystId,
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        (mockFindingRepo.findById as ReturnType<typeof vi.fn>).mockResolvedValue(mockFinding);
        (mockProjectRepo.lockProject as ReturnType<typeof vi.fn>).mockResolvedValue(mockProject);
        (mockProjectRepo.lockMember as ReturnType<typeof vi.fn>).mockImplementation((_pid: string, uid: string) =>
          Promise.resolve({
            projectId,
            userId: uid,
            role: uid === analystId ? 'ANALYST' : 'DEVELOPER',
            addedById: analystId,
            createdAt: new Date(),
          }),
        );
        (mockFindingRepo.lockFinding as ReturnType<typeof vi.fn>).mockResolvedValue(mockFinding);
        (mockTaskRepo.findActiveByFindingId as ReturnType<typeof vi.fn>).mockResolvedValue(null);

        const updatedFindingEntity: FindingEntity = {
          ...mockFinding,
          status: 'IN_PROGRESS',
          assignedToId: dev2Id,
          version: 5,
        };
        (mockFindingRepo.updateAtomic as ReturnType<typeof vi.fn>).mockResolvedValue(updatedFindingEntity);
        (mockTaskRepo.create as ReturnType<typeof vi.fn>).mockResolvedValue({
          id: taskId,
          findingId,
          assignedToId: dev2Id,
          assignedById: analystId,
          description: 'Re-fix XSS flaw',
          notes: null,
          status: 'PENDING',
          dueDate: null,
          createdAt: new Date(),
          updatedAt: new Date(),
        });

        const result = await findingService.assignFinding(analyst, findingId, {
          expectedVersion: 4,
          assignedToId: dev2Id,
          taskDescription: 'Re-fix XSS flaw',
        });

        expect(result.status).toBe('IN_PROGRESS');
        expect(result.assignedToId).toBe(dev2Id);
        expect(result.version).toBe(5);
      });

      it('rejects assignment on OPEN finding with InvalidStateTransitionError', async () => {
        const analyst = createTestAnalystActor(projectId);
        const mockFinding: FindingEntity = {
          id: findingId,
          projectId,
          title: 'XSS flaw',
          description: 'Stored XSS in user profile',
          severity: 'HIGH',
          category: 'XSS',
          cvssScore: 7.5,
          status: 'OPEN', // OPEN cannot directly transition to IN_PROGRESS (must be TRIAGED first)
          createdById: analystId,
          assignedToId: null,
          dueDate: null,
          isDeleted: false,
          version: 1,
          createdAt: new Date(),
          updatedAt: new Date(),
        };
        const mockProject: ProjectEntity = {
          id: projectId,
          name: 'Core Platform',
          slug: 'core-platform',
          description: null,
          isActive: true,
          createdById: analystId,
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        (mockFindingRepo.findById as ReturnType<typeof vi.fn>).mockResolvedValue(mockFinding);
        (mockProjectRepo.lockProject as ReturnType<typeof vi.fn>).mockResolvedValue(mockProject);
        (mockProjectRepo.lockMember as ReturnType<typeof vi.fn>).mockImplementation((_pid: string, uid: string) =>
          Promise.resolve({
            projectId,
            userId: uid,
            role: uid === analystId ? 'ANALYST' : 'DEVELOPER',
            addedById: analystId,
            createdAt: new Date(),
          }),
        );
        (mockFindingRepo.lockFinding as ReturnType<typeof vi.fn>).mockResolvedValue(mockFinding);

        await expect(
          findingService.assignFinding(analyst, findingId, {
            expectedVersion: 1,
            assignedToId: dev1Id,
            taskDescription: 'Fix XSS',
          }),
        ).rejects.toThrow(InvalidStateTransitionError);
      });

      it('rejects assignment with stale expectedVersion with ConcurrencyConflictError (HTTP 409) before checking status', async () => {
        const analyst = createTestAnalystActor(projectId);
        const mockFinding: FindingEntity = {
          id: findingId,
          projectId,
          title: 'XSS flaw',
          description: 'Stored XSS in user profile',
          severity: 'HIGH',
          category: 'XSS',
          cvssScore: 7.5,
          status: 'OPEN',
          createdById: analystId,
          assignedToId: null,
          dueDate: null,
          isDeleted: false,
          version: 2,
          createdAt: new Date(),
          updatedAt: new Date(),
        };
        const mockProject: ProjectEntity = {
          id: projectId,
          name: 'Core Platform',
          slug: 'core-platform',
          description: null,
          isActive: true,
          createdById: analystId,
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        (mockFindingRepo.findById as ReturnType<typeof vi.fn>).mockResolvedValue(mockFinding);
        (mockProjectRepo.lockProject as ReturnType<typeof vi.fn>).mockResolvedValue(mockProject);
        (mockProjectRepo.lockMember as ReturnType<typeof vi.fn>).mockImplementation((_pid: string, uid: string) =>
          Promise.resolve({
            projectId,
            userId: uid,
            role: uid === analystId ? 'ANALYST' : 'DEVELOPER',
            addedById: analystId,
            createdAt: new Date(),
          }),
        );
        (mockFindingRepo.lockFinding as ReturnType<typeof vi.fn>).mockResolvedValue(mockFinding);

        const err = await findingService
          .assignFinding(analyst, findingId, {
            expectedVersion: 1,
            assignedToId: dev1Id,
            taskDescription: 'Fix XSS',
          })
          .catch((e) => e);

        expect(err).toBeInstanceOf(ConcurrencyConflictError);
        expect(err.statusCode).toBe(409);
      });

      it('rejects assignment when finding already has an active remediation task', async () => {
        const analyst = createTestAnalystActor(projectId);
        const mockFinding: FindingEntity = {
          id: findingId,
          projectId,
          title: 'XSS flaw',
          description: 'Stored XSS in user profile',
          severity: 'HIGH',
          category: 'XSS',
          cvssScore: 7.5,
          status: 'TRIAGED',
          createdById: analystId,
          assignedToId: null,
          dueDate: null,
          isDeleted: false,
          version: 2,
          createdAt: new Date(),
          updatedAt: new Date(),
        };
        const mockProject: ProjectEntity = {
          id: projectId,
          name: 'Core Platform',
          slug: 'core-platform',
          description: null,
          isActive: true,
          createdById: analystId,
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        (mockFindingRepo.findById as ReturnType<typeof vi.fn>).mockResolvedValue(mockFinding);
        (mockProjectRepo.lockProject as ReturnType<typeof vi.fn>).mockResolvedValue(mockProject);
        (mockProjectRepo.lockMember as ReturnType<typeof vi.fn>).mockImplementation((_pid: string, uid: string) =>
          Promise.resolve({
            projectId,
            userId: uid,
            role: uid === analystId ? 'ANALYST' : 'DEVELOPER',
            addedById: analystId,
            createdAt: new Date(),
          }),
        );
        (mockFindingRepo.lockFinding as ReturnType<typeof vi.fn>).mockResolvedValue(mockFinding);

        // Active task already present!
        (mockTaskRepo.findActiveByFindingId as ReturnType<typeof vi.fn>).mockResolvedValue({
          id: taskId,
          findingId,
          assignedToId: dev1Id,
          assignedById: analystId,
          description: 'Active task',
          notes: null,
          status: 'PENDING',
          dueDate: null,
          createdAt: new Date(),
          updatedAt: new Date(),
        });

        await expect(
          findingService.assignFinding(analyst, findingId, {
            expectedVersion: 2,
            assignedToId: dev1Id,
            taskDescription: 'Fix XSS',
          }),
        ).rejects.toThrow(InvalidStateTransitionError);
      });

      it('rejects assignment to non-member user with 403 Forbidden', async () => {
        const analyst = createTestAnalystActor(projectId);
        const mockFinding: FindingEntity = {
          id: findingId,
          projectId,
          title: 'XSS flaw',
          description: 'Stored XSS in user profile',
          severity: 'HIGH',
          category: 'XSS',
          cvssScore: 7.5,
          status: 'TRIAGED',
          createdById: analystId,
          assignedToId: null,
          dueDate: null,
          isDeleted: false,
          version: 2,
          createdAt: new Date(),
          updatedAt: new Date(),
        };
        const mockProject: ProjectEntity = {
          id: projectId,
          name: 'Core Platform',
          slug: 'core-platform',
          description: null,
          isActive: true,
          createdById: analystId,
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        (mockFindingRepo.findById as ReturnType<typeof vi.fn>).mockResolvedValue(mockFinding);
        (mockProjectRepo.lockProject as ReturnType<typeof vi.fn>).mockResolvedValue(mockProject);
        (mockProjectRepo.lockMember as ReturnType<typeof vi.fn>).mockImplementation((_pid: string, uid: string) => {
          if (uid === analystId) {
            return Promise.resolve({
              projectId,
              userId: analystId,
              role: 'ANALYST',
              addedById: analystId,
              createdAt: new Date(),
            });
          }
          return Promise.resolve(null); // Target developer is not a member!
        });

        await expect(
          findingService.assignFinding(analyst, findingId, {
            expectedVersion: 2,
            assignedToId: dev1Id,
            taskDescription: 'Fix XSS',
          }),
        ).rejects.toThrow(ForbiddenError);
      });

      it('rejects assignment when target assignee account is deactivated', async () => {
        const analyst = createTestAnalystActor(projectId);
        const mockFinding: FindingEntity = {
          id: findingId,
          projectId,
          title: 'XSS flaw',
          description: 'Stored XSS',
          severity: 'HIGH',
          category: 'XSS',
          cvssScore: 7.5,
          status: 'TRIAGED',
          createdById: analystId,
          assignedToId: null,
          dueDate: null,
          isDeleted: false,
          version: 2,
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        (mockFindingRepo.findById as ReturnType<typeof vi.fn>).mockResolvedValue(mockFinding);
        (mockUserRepo.lockUsers as ReturnType<typeof vi.fn>).mockImplementation((userIds: string[]) => {
          const map = new Map<string, UserAuthEntity>();
          for (const id of userIds) {
            map.set(id, {
              id,
              isActive: id !== dev1Id, // dev1 is deactivated!
              globalRole: id === analystId ? 'ANALYST' : 'DEVELOPER',
            });
          }
          return Promise.resolve(map);
        });

        await expect(
          findingService.assignFinding(analyst, findingId, {
            expectedVersion: 2,
            assignedToId: dev1Id,
            taskDescription: 'Fix XSS',
          }),
        ).rejects.toThrow(ForbiddenError);
      });
    });

    describe('2. submitRemediation', () => {
      it('authorized assigned Developer submits remediation: finding -> READY_FOR_REVIEW, task -> SUBMITTED, stores submitterId in event', async () => {
        const dev = createTestDeveloperActor(projectId, { id: dev1Id });
        const mockFinding: FindingEntity = {
          id: findingId,
          projectId,
          title: 'XSS flaw',
          description: 'Stored XSS',
          severity: 'HIGH',
          category: 'XSS',
          cvssScore: 7.5,
          status: 'IN_PROGRESS',
          createdById: analystId,
          assignedToId: dev1Id,
          dueDate: null,
          isDeleted: false,
          version: 3,
          createdAt: new Date(),
          updatedAt: new Date(),
        };
        const mockProject: ProjectEntity = {
          id: projectId,
          name: 'Core Platform',
          slug: 'core-platform',
          description: null,
          isActive: true,
          createdById: analystId,
          createdAt: new Date(),
          updatedAt: new Date(),
        };
        const mockTask: RemediationTaskEntity = {
          id: taskId,
          findingId,
          assignedToId: dev1Id,
          assignedById: analystId,
          description: 'Fix XSS flaw',
          notes: 'WIP',
          status: 'IN_PROGRESS',
          dueDate: null,
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        const executionOrder: string[] = [];

        (mockFindingRepo.findById as ReturnType<typeof vi.fn>).mockResolvedValue(mockFinding);

        (mockUserRepo.lockUsers as ReturnType<typeof vi.fn>).mockImplementation(() => {
          executionOrder.push('LOCK_USERS_0');
          const map = new Map<string, UserAuthEntity>();
          map.set(dev1Id, { id: dev1Id, isActive: true, globalRole: 'DEVELOPER' });
          return Promise.resolve(map);
        });

        (mockProjectRepo.lockProject as ReturnType<typeof vi.fn>).mockImplementation(() => {
          executionOrder.push('LOCK_PROJECT_1');
          return Promise.resolve(mockProject);
        });

        (mockProjectRepo.lockMember as ReturnType<typeof vi.fn>).mockImplementation(() => {
          executionOrder.push('LOCK_MEMBER_2');
          return Promise.resolve({
            projectId,
            userId: dev1Id,
            role: 'DEVELOPER',
            addedById: analystId,
            createdAt: new Date(),
          });
        });

        (mockFindingRepo.lockFinding as ReturnType<typeof vi.fn>).mockImplementation(() => {
          executionOrder.push('LOCK_FINDING_3');
          return Promise.resolve(mockFinding);
        });

        (mockTaskRepo.lockActiveTaskByFindingId as ReturnType<typeof vi.fn>).mockImplementation(() => {
          executionOrder.push('LOCK_TASK_4');
          return Promise.resolve(mockTask);
        });

        const updatedFindingEntity: FindingEntity = {
          ...mockFinding,
          status: 'READY_FOR_REVIEW',
          version: 4,
        };
        (mockFindingRepo.updateAtomic as ReturnType<typeof vi.fn>).mockResolvedValue(updatedFindingEntity);

        const updatedTaskEntity: RemediationTaskEntity = {
          ...mockTask,
          status: 'SUBMITTED',
          notes: 'Patch applied and sanitized inputs',
        };
        (mockTaskRepo.updateStatus as ReturnType<typeof vi.fn>).mockResolvedValue(updatedTaskEntity);

        const result = await findingService.submitRemediation(dev, findingId, {
          expectedVersion: 3,
          notes: 'Patch applied and sanitized inputs',
        });

        expect(result.status).toBe('READY_FOR_REVIEW');
        expect(result.version).toBe(4);

        expect(executionOrder).toEqual([
          'LOCK_USERS_0',
          'LOCK_PROJECT_1',
          'LOCK_MEMBER_2',
          'LOCK_FINDING_3',
          'LOCK_TASK_4',
        ]);

        expect(mockTaskRepo.updateStatus).toHaveBeenCalledWith(
          taskId,
          'SUBMITTED',
          'Patch applied and sanitized inputs',
        );

        // Verify submitterId stored in FindingEvent metadata for Separation of Duties (OLI-7)
        expect(mockFindingRepo.addEvent).toHaveBeenCalledWith(
          expect.objectContaining({
            findingId,
            actorId: dev1Id,
            eventType: 'STATUS_CHANGED',
            previousStatus: 'IN_PROGRESS',
            newStatus: 'READY_FOR_REVIEW',
            metadata: expect.objectContaining({
              submitterId: dev1Id,
              taskId,
              notes: 'Patch applied and sanitized inputs',
            }),
          }),
        );

        // Verify audit logs
        expect(mockAuditRepo.append).toHaveBeenCalledWith(
          expect.objectContaining({
            actorId: dev1Id,
            eventCategory: 'FINDING',
            eventType: 'finding.remediation_submitted',
          }),
        );
        expect(mockAuditRepo.append).toHaveBeenCalledWith(
          expect.objectContaining({
            actorId: dev1Id,
            eventCategory: 'TASK',
            eventType: 'task.submitted',
          }),
        );
      });

      it('rejects submission by unassigned Developer with 403 Forbidden', async () => {
        const dev2 = createTestDeveloperActor(projectId, { id: dev2Id });
        const mockFinding: FindingEntity = {
          id: findingId,
          projectId,
          title: 'XSS flaw',
          description: 'Stored XSS',
          severity: 'HIGH',
          category: 'XSS',
          cvssScore: 7.5,
          status: 'IN_PROGRESS',
          createdById: analystId,
          assignedToId: dev1Id, // Assigned to dev1, caller is dev2!
          dueDate: null,
          isDeleted: false,
          version: 3,
          createdAt: new Date(),
          updatedAt: new Date(),
        };
        const mockProject: ProjectEntity = {
          id: projectId,
          name: 'Core Platform',
          slug: 'core-platform',
          description: null,
          isActive: true,
          createdById: analystId,
          createdAt: new Date(),
          updatedAt: new Date(),
        };
        const mockTask: RemediationTaskEntity = {
          id: taskId,
          findingId,
          assignedToId: dev1Id,
          assignedById: analystId,
          description: 'Fix XSS flaw',
          notes: null,
          status: 'IN_PROGRESS',
          dueDate: null,
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        (mockFindingRepo.findById as ReturnType<typeof vi.fn>).mockResolvedValue(mockFinding);
        (mockProjectRepo.lockProject as ReturnType<typeof vi.fn>).mockResolvedValue(mockProject);
        (mockProjectRepo.lockMember as ReturnType<typeof vi.fn>).mockResolvedValue({
          projectId,
          userId: dev2Id,
          role: 'DEVELOPER',
          addedById: analystId,
          createdAt: new Date(),
        });
        (mockFindingRepo.lockFinding as ReturnType<typeof vi.fn>).mockResolvedValue(mockFinding);
        (mockTaskRepo.lockActiveTaskByFindingId as ReturnType<typeof vi.fn>).mockResolvedValue(mockTask);

        await expect(
          findingService.submitRemediation(dev2, findingId, {
            expectedVersion: 3,
          }),
        ).rejects.toThrow(ForbiddenError);
      });

      it('rejects submission when active remediation task is missing with 404 EntityNotFoundError', async () => {
        const dev = createTestDeveloperActor(projectId, { id: dev1Id });
        const mockFinding: FindingEntity = {
          id: findingId,
          projectId,
          title: 'XSS flaw',
          description: 'Stored XSS',
          severity: 'HIGH',
          category: 'XSS',
          cvssScore: 7.5,
          status: 'IN_PROGRESS',
          createdById: analystId,
          assignedToId: dev1Id,
          dueDate: null,
          isDeleted: false,
          version: 3,
          createdAt: new Date(),
          updatedAt: new Date(),
        };
        const mockProject: ProjectEntity = {
          id: projectId,
          name: 'Core Platform',
          slug: 'core-platform',
          description: null,
          isActive: true,
          createdById: analystId,
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        (mockFindingRepo.findById as ReturnType<typeof vi.fn>).mockResolvedValue(mockFinding);
        (mockProjectRepo.lockProject as ReturnType<typeof vi.fn>).mockResolvedValue(mockProject);
        (mockProjectRepo.lockMember as ReturnType<typeof vi.fn>).mockResolvedValue({
          projectId,
          userId: dev1Id,
          role: 'DEVELOPER',
          addedById: analystId,
          createdAt: new Date(),
        });
        (mockFindingRepo.lockFinding as ReturnType<typeof vi.fn>).mockResolvedValue(mockFinding);
        (mockTaskRepo.lockActiveTaskByFindingId as ReturnType<typeof vi.fn>).mockResolvedValue(null); // Missing active task!

        await expect(
          findingService.submitRemediation(dev, findingId, {
            expectedVersion: 3,
          }),
        ).rejects.toThrow(EntityNotFoundError);
      });
    });

    describe('3. verifyFinding (Verification & Rejection)', () => {
      it('authorized Analyst verifies remediation (outcome: VERIFIED): finding -> VERIFIED, task -> VERIFIED', async () => {
        const analyst = createTestAnalystActor(projectId);
        const mockFinding: FindingEntity = {
          id: findingId,
          projectId,
          title: 'XSS flaw',
          description: 'Stored XSS',
          severity: 'HIGH',
          category: 'XSS',
          cvssScore: 7.5,
          status: 'READY_FOR_REVIEW',
          createdById: analystId,
          assignedToId: dev1Id,
          dueDate: null,
          isDeleted: false,
          version: 4,
          createdAt: new Date(),
          updatedAt: new Date(),
        };
        const mockProject: ProjectEntity = {
          id: projectId,
          name: 'Core Platform',
          slug: 'core-platform',
          description: null,
          isActive: true,
          createdById: analystId,
          createdAt: new Date(),
          updatedAt: new Date(),
        };
        const mockTask: RemediationTaskEntity = {
          id: taskId,
          findingId,
          assignedToId: dev1Id,
          assignedById: analystId,
          description: 'Fix XSS flaw',
          notes: 'Patch submitted',
          status: 'SUBMITTED',
          dueDate: null,
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        (mockFindingRepo.findById as ReturnType<typeof vi.fn>).mockResolvedValue(mockFinding);
        (mockProjectRepo.lockProject as ReturnType<typeof vi.fn>).mockResolvedValue(mockProject);
        (mockProjectRepo.lockMember as ReturnType<typeof vi.fn>).mockResolvedValue({
          projectId,
          userId: analystId,
          role: 'ANALYST',
          addedById: analystId,
          createdAt: new Date(),
        });
        (mockFindingRepo.lockFinding as ReturnType<typeof vi.fn>).mockResolvedValue(mockFinding);
        (mockTaskRepo.lockActiveTaskByFindingId as ReturnType<typeof vi.fn>).mockResolvedValue(mockTask);

        // Submitter evidence: dev1 submitted remediation
        (mockFindingRepo.getEvents as ReturnType<typeof vi.fn>).mockResolvedValue([
          {
            id: 'ev-1',
            findingId,
            actorId: dev1Id,
            eventType: 'STATUS_CHANGED',
            newStatus: 'READY_FOR_REVIEW',
            metadata: { submitterId: dev1Id, taskId },
            createdAt: new Date(),
          },
        ]);

        const updatedFindingEntity: FindingEntity = {
          ...mockFinding,
          status: 'VERIFIED',
          version: 5,
        };
        (mockFindingRepo.updateAtomic as ReturnType<typeof vi.fn>).mockResolvedValue(updatedFindingEntity);
        (mockTaskRepo.updateStatus as ReturnType<typeof vi.fn>).mockResolvedValue({
          ...mockTask,
          status: 'VERIFIED',
          notes: 'Verified clean in staging',
        });

        const result = await findingService.verifyFinding(analyst, findingId, {
          expectedVersion: 4,
          outcome: 'VERIFIED',
          notes: 'Verified clean in staging',
        });

        expect(result.status).toBe('VERIFIED');
        expect(result.version).toBe(5);

        expect(mockTaskRepo.updateStatus).toHaveBeenCalledWith(
          taskId,
          'VERIFIED',
          'Verified clean in staging',
        );

        expect(mockAuditRepo.append).toHaveBeenCalledWith(
          expect.objectContaining({
            actorId: analystId,
            eventCategory: 'FINDING',
            eventType: 'finding.verified',
          }),
        );
        expect(mockAuditRepo.append).toHaveBeenCalledWith(
          expect.objectContaining({
            actorId: analystId,
            eventCategory: 'TASK',
            eventType: 'task.verified',
          }),
        );
      });

      it('authorized Analyst rejects remediation (outcome: REOPENED): finding -> REOPENED, task -> REJECTED (releases index)', async () => {
        const analyst = createTestAnalystActor(projectId);
        const mockFinding: FindingEntity = {
          id: findingId,
          projectId,
          title: 'XSS flaw',
          description: 'Stored XSS',
          severity: 'HIGH',
          category: 'XSS',
          cvssScore: 7.5,
          status: 'READY_FOR_REVIEW',
          createdById: analystId,
          assignedToId: dev1Id,
          dueDate: null,
          isDeleted: false,
          version: 4,
          createdAt: new Date(),
          updatedAt: new Date(),
        };
        const mockProject: ProjectEntity = {
          id: projectId,
          name: 'Core Platform',
          slug: 'core-platform',
          description: null,
          isActive: true,
          createdById: analystId,
          createdAt: new Date(),
          updatedAt: new Date(),
        };
        const mockTask: RemediationTaskEntity = {
          id: taskId,
          findingId,
          assignedToId: dev1Id,
          assignedById: analystId,
          description: 'Fix XSS flaw',
          notes: 'Patch submitted',
          status: 'SUBMITTED',
          dueDate: null,
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        (mockFindingRepo.findById as ReturnType<typeof vi.fn>).mockResolvedValue(mockFinding);
        (mockProjectRepo.lockProject as ReturnType<typeof vi.fn>).mockResolvedValue(mockProject);
        (mockProjectRepo.lockMember as ReturnType<typeof vi.fn>).mockResolvedValue({
          projectId,
          userId: analystId,
          role: 'ANALYST',
          addedById: analystId,
          createdAt: new Date(),
        });
        (mockFindingRepo.lockFinding as ReturnType<typeof vi.fn>).mockResolvedValue(mockFinding);
        (mockTaskRepo.lockActiveTaskByFindingId as ReturnType<typeof vi.fn>).mockResolvedValue(mockTask);

        // Submitter evidence: dev1 submitted remediation
        (mockFindingRepo.getEvents as ReturnType<typeof vi.fn>).mockResolvedValue([
          {
            id: 'ev-1',
            findingId,
            actorId: dev1Id,
            eventType: 'STATUS_CHANGED',
            newStatus: 'READY_FOR_REVIEW',
            metadata: { submitterId: dev1Id, taskId },
            createdAt: new Date(),
          },
        ]);

        const updatedFindingEntity: FindingEntity = {
          ...mockFinding,
          status: 'REOPENED',
          version: 5,
        };
        (mockFindingRepo.updateAtomic as ReturnType<typeof vi.fn>).mockResolvedValue(updatedFindingEntity);
        (mockTaskRepo.updateStatus as ReturnType<typeof vi.fn>).mockResolvedValue({
          ...mockTask,
          status: 'REJECTED',
          notes: 'XSS payload still fires on tag bypass',
        });

        const result = await findingService.rejectVerification(analyst, findingId, {
          expectedVersion: 4,
          notes: 'XSS payload still fires on tag bypass',
        });

        expect(result.status).toBe('REOPENED');
        expect(result.version).toBe(5);

        // Task transitioned to REJECTED (releasing partial unique index)
        expect(mockTaskRepo.updateStatus).toHaveBeenCalledWith(
          taskId,
          'REJECTED',
          'XSS payload still fires on tag bypass',
        );

        expect(mockAuditRepo.append).toHaveBeenCalledWith(
          expect.objectContaining({
            actorId: analystId,
            eventCategory: 'FINDING',
            eventType: 'finding.remediation_rejected',
          }),
        );
        expect(mockAuditRepo.append).toHaveBeenCalledWith(
          expect.objectContaining({
            actorId: analystId,
            eventCategory: 'TASK',
            eventType: 'task.rejected',
          }),
        );
      });

      it('rejects verification when Analyst is the same user who submitted remediation (OLI-7 Separation of Duties)', async () => {
        const analyst = createTestAnalystActor(projectId);
        const mockFinding: FindingEntity = {
          id: findingId,
          projectId,
          title: 'XSS flaw',
          description: 'Stored XSS',
          severity: 'HIGH',
          category: 'XSS',
          cvssScore: 7.5,
          status: 'READY_FOR_REVIEW',
          createdById: analystId,
          assignedToId: analystId,
          dueDate: null,
          isDeleted: false,
          version: 4,
          createdAt: new Date(),
          updatedAt: new Date(),
        };
        const mockProject: ProjectEntity = {
          id: projectId,
          name: 'Core Platform',
          slug: 'core-platform',
          description: null,
          isActive: true,
          createdById: analystId,
          createdAt: new Date(),
          updatedAt: new Date(),
        };
        const mockTask: RemediationTaskEntity = {
          id: taskId,
          findingId,
          assignedToId: analystId,
          assignedById: analystId,
          description: 'Fix XSS flaw',
          notes: 'Analyst fixed it',
          status: 'SUBMITTED',
          dueDate: null,
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        (mockFindingRepo.findById as ReturnType<typeof vi.fn>).mockResolvedValue(mockFinding);
        (mockProjectRepo.lockProject as ReturnType<typeof vi.fn>).mockResolvedValue(mockProject);
        (mockProjectRepo.lockMember as ReturnType<typeof vi.fn>).mockResolvedValue({
          projectId,
          userId: analystId,
          role: 'ANALYST',
          addedById: analystId,
          createdAt: new Date(),
        });
        (mockFindingRepo.lockFinding as ReturnType<typeof vi.fn>).mockResolvedValue(mockFinding);
        (mockTaskRepo.lockActiveTaskByFindingId as ReturnType<typeof vi.fn>).mockResolvedValue(mockTask);

        // Submitter evidence: actorId is analystId!
        (mockFindingRepo.getEvents as ReturnType<typeof vi.fn>).mockResolvedValue([
          {
            id: 'ev-1',
            findingId,
            actorId: analystId, // Self-submission!
            eventType: 'STATUS_CHANGED',
            newStatus: 'READY_FOR_REVIEW',
            createdAt: new Date(),
          },
        ]);

        await expect(
          findingService.verifyFinding(analyst, findingId, {
            expectedVersion: 4,
            outcome: 'VERIFIED',
          }),
        ).rejects.toThrow(ForbiddenError);
      });

      it('rejects verification when submitter evidence is missing or unrecorded (fail-closed OLI-7)', async () => {
        const analyst = createTestAnalystActor(projectId);
        const mockFinding: FindingEntity = {
          id: findingId,
          projectId,
          title: 'XSS flaw',
          description: 'Stored XSS',
          severity: 'HIGH',
          category: 'XSS',
          cvssScore: 7.5,
          status: 'READY_FOR_REVIEW',
          createdById: analystId,
          assignedToId: dev1Id,
          dueDate: null,
          isDeleted: false,
          version: 4,
          createdAt: new Date(),
          updatedAt: new Date(),
        };
        const mockProject: ProjectEntity = {
          id: projectId,
          name: 'Core Platform',
          slug: 'core-platform',
          description: null,
          isActive: true,
          createdById: analystId,
          createdAt: new Date(),
          updatedAt: new Date(),
        };
        const mockTask: RemediationTaskEntity = {
          id: taskId,
          findingId,
          assignedToId: dev1Id,
          assignedById: analystId,
          description: 'Fix XSS flaw',
          notes: null,
          status: 'SUBMITTED',
          dueDate: null,
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        (mockFindingRepo.findById as ReturnType<typeof vi.fn>).mockResolvedValue(mockFinding);
        (mockProjectRepo.lockProject as ReturnType<typeof vi.fn>).mockResolvedValue(mockProject);
        (mockProjectRepo.lockMember as ReturnType<typeof vi.fn>).mockResolvedValue({
          projectId,
          userId: analystId,
          role: 'ANALYST',
          addedById: analystId,
          createdAt: new Date(),
        });
        (mockFindingRepo.lockFinding as ReturnType<typeof vi.fn>).mockResolvedValue(mockFinding);
        (mockTaskRepo.lockActiveTaskByFindingId as ReturnType<typeof vi.fn>).mockResolvedValue(mockTask);

        // Zero submission events! Submitter cannot be verified!
        (mockFindingRepo.getEvents as ReturnType<typeof vi.fn>).mockResolvedValue([]);

        await expect(
          findingService.verifyFinding(analyst, findingId, {
            expectedVersion: 4,
            outcome: 'VERIFIED',
          }),
        ).rejects.toThrow(ForbiddenError);
      });
    });
  });

  // ==========================================================================
  // Section C: Dependency Injection & Service Initialization Boundaries
  // ==========================================================================
  describe('C. Dependency Injection & Service Initialization Boundaries', () => {
    it('TaskService constructor fails fast when init is null/undefined', () => {
      expect(() => new TaskService(null as unknown as DatabaseManager)).toThrow(
        expect.objectContaining({
          name: 'SecureFlowError',
          code: 'SERVICE_INITIALIZATION_ERROR',
          statusCode: 500,
        }),
      );
    });

    it('TaskService constructor fails fast when repository container is incomplete', () => {
      expect(
        () =>
          createTestTaskService({
            taskRepo: mockTaskRepo as ITaskRepository,
            // Missing other required repos
          } as RepositoryContainer),
      ).toThrow(
        expect.objectContaining({
          name: 'SecureFlowError',
          code: 'SERVICE_INITIALIZATION_ERROR',
          statusCode: 500,
        }),
      );
    });

    it('TaskService constructor rejects unauthorized direct repository injection outside @secureflow/domain/testing', () => {
      expect(
        () =>
          new TaskService({
            repositories: mockRepos,
          }),
      ).toThrow(
        expect.objectContaining({
          name: 'SecureFlowError',
          code: 'UNAUTHORIZED_PERSISTENCE_INJECTION',
          statusCode: 500,
        }),
      );
    });

    it('packages/domain root index does NOT export TaskService, TaskServiceInit, ProjectServiceInit, or AuditServiceInit', async () => {
      const domainIndex = await import('../../src/index.js');
      expect((domainIndex as Record<string, unknown>)['TaskService']).toBeUndefined();
      expect((domainIndex as Record<string, unknown>)['TaskServiceInit']).toBeUndefined();
      expect((domainIndex as Record<string, unknown>)['ProjectServiceInit']).toBeUndefined();
      expect((domainIndex as Record<string, unknown>)['AuditServiceInit']).toBeUndefined();
    });
  });

  // ==========================================================================
  // Section D: Archived Foreign-Project Existence Hiding Across All Operations
  // ==========================================================================
  describe('D. Archived Foreign-Project Existence Hiding (Non-member 404 vs Member 403)', () => {
    const archivedProjectId = '99999999-9999-4999-8999-999999999999';
    const archivedProject: ProjectEntity = {
      id: archivedProjectId,
      name: 'Archived Project',
      slug: 'archived-project',
      description: null,
      isActive: false, // ARCHIVED!
      createdById: analystId,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    const archivedFinding: FindingEntity = {
      id: findingId,
      projectId: archivedProjectId,
      title: 'Archived Bug',
      description: 'In archived project',
      severity: 'MEDIUM',
      category: 'MISCONFIG',
      cvssScore: 5.0,
      status: 'TRIAGED',
      createdById: analystId,
      assignedToId: null,
      dueDate: null,
      isDeleted: false,
      version: 1,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    const archivedTask: RemediationTaskEntity = {
      id: taskId,
      findingId,
      assignedToId: dev1Id,
      assignedById: analystId,
      description: 'Fix archived bug',
      notes: null,
      status: 'IN_PROGRESS',
      dueDate: null,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    it('TaskService.getTask: non-member targeting archived foreign project receives generic 404 EntityNotFoundError', async () => {
      const foreignDev = createTestDeveloperActor(projectId, { id: dev2Id }); // member of projectId, NOT archivedProjectId
      (mockTaskRepo.findById as ReturnType<typeof vi.fn>).mockResolvedValue(archivedTask);
      (mockFindingRepo.findById as ReturnType<typeof vi.fn>).mockResolvedValue(archivedFinding);
      (mockUserRepo.findAuthoritativeUser as ReturnType<typeof vi.fn>).mockResolvedValue({
        id: dev2Id,
        isActive: true,
        globalRole: 'DEVELOPER',
        memberships: [{ projectId, role: 'DEVELOPER' }], // no membership in archivedProjectId
      });

      await expect(taskService.getTask(foreignDev, taskId)).rejects.toThrow(EntityNotFoundError);
    });

    it('TaskService.getTaskByFindingId: non-member targeting archived foreign project receives generic 404 EntityNotFoundError', async () => {
      const foreignDev = createTestDeveloperActor(projectId, { id: dev2Id });
      (mockFindingRepo.findById as ReturnType<typeof vi.fn>).mockResolvedValue(archivedFinding);
      (mockUserRepo.findAuthoritativeUser as ReturnType<typeof vi.fn>).mockResolvedValue({
        id: dev2Id,
        isActive: true,
        globalRole: 'DEVELOPER',
        memberships: [{ projectId, role: 'DEVELOPER' }],
      });

      await expect(taskService.getTaskByFindingId(foreignDev, findingId)).rejects.toThrow(EntityNotFoundError);
    });

    it('TaskService.updateTaskNotes: non-member targeting archived foreign project receives 404; member receives 403', async () => {
      const foreignDev = createTestDeveloperActor(projectId, { id: dev2Id });
      (mockTaskRepo.findById as ReturnType<typeof vi.fn>).mockResolvedValue(archivedTask);
      (mockFindingRepo.findById as ReturnType<typeof vi.fn>).mockResolvedValue(archivedFinding);
      (mockProjectRepo.lockProject as ReturnType<typeof vi.fn>).mockResolvedValue(archivedProject);
      (mockProjectRepo.lockMember as ReturnType<typeof vi.fn>).mockResolvedValue(null); // non-member

      // Non-member receives 404 (existence hiding)
      await expect(
        taskService.updateTaskNotes(foreignDev, taskId, { notes: 'Attempted note' }),
      ).rejects.toThrow(EntityNotFoundError);

      // Authorized member receives 403 (action prohibited on archived project)
      const memberDev = createTestDeveloperActor(archivedProjectId, { id: dev1Id });
      (mockProjectRepo.lockMember as ReturnType<typeof vi.fn>).mockResolvedValue({
        projectId: archivedProjectId,
        userId: dev1Id,
        role: 'DEVELOPER',
        addedById: analystId,
        createdAt: new Date(),
      });

      await expect(
        taskService.updateTaskNotes(memberDev, taskId, { notes: 'Attempted note' }),
      ).rejects.toThrow(ForbiddenError);
    });

    it('FindingService.assignFinding: non-member targeting archived foreign project receives 404; member receives 403', async () => {
      const foreignAnalyst = createTestAnalystActor(projectId);
      (mockFindingRepo.findById as ReturnType<typeof vi.fn>).mockResolvedValue(archivedFinding);
      (mockProjectRepo.lockProject as ReturnType<typeof vi.fn>).mockResolvedValue(archivedProject);
      (mockProjectRepo.lockMember as ReturnType<typeof vi.fn>).mockResolvedValue(null); // non-member

      // Non-member receives 404
      await expect(
        findingService.assignFinding(foreignAnalyst, findingId, {
          expectedVersion: 1,
          assignedToId: dev1Id,
          taskDescription: 'Fix archived bug',
        }),
      ).rejects.toThrow(EntityNotFoundError);

      // Authorized member receives 403
      const memberAnalyst = createTestAnalystActor(archivedProjectId, { id: analystId });
      (mockProjectRepo.lockMember as ReturnType<typeof vi.fn>).mockResolvedValue({
        projectId: archivedProjectId,
        userId: analystId,
        role: 'ANALYST',
        addedById: analystId,
        createdAt: new Date(),
      });

      await expect(
        findingService.assignFinding(memberAnalyst, findingId, {
          expectedVersion: 1,
          assignedToId: dev1Id,
          taskDescription: 'Fix archived bug',
        }),
      ).rejects.toThrow(ForbiddenError);
    });

    it('FindingService.submitRemediation: non-member targeting archived foreign project receives 404; member receives 403', async () => {
      const foreignDev = createTestDeveloperActor(projectId, { id: dev2Id });
      const inProgressFinding: FindingEntity = { ...archivedFinding, status: 'IN_PROGRESS', assignedToId: dev1Id };
      (mockFindingRepo.findById as ReturnType<typeof vi.fn>).mockResolvedValue(inProgressFinding);
      (mockProjectRepo.lockProject as ReturnType<typeof vi.fn>).mockResolvedValue(archivedProject);
      (mockProjectRepo.lockMember as ReturnType<typeof vi.fn>).mockResolvedValue(null);

      // Non-member receives 404
      await expect(
        findingService.submitRemediation(foreignDev, findingId, {
          expectedVersion: 1,
          notes: 'Fixed',
        }),
      ).rejects.toThrow(EntityNotFoundError);

      // Authorized member receives 403
      const memberDev = createTestDeveloperActor(archivedProjectId, { id: dev1Id });
      (mockProjectRepo.lockMember as ReturnType<typeof vi.fn>).mockResolvedValue({
        projectId: archivedProjectId,
        userId: dev1Id,
        role: 'DEVELOPER',
        addedById: analystId,
        createdAt: new Date(),
      });

      await expect(
        findingService.submitRemediation(memberDev, findingId, {
          expectedVersion: 1,
          notes: 'Fixed',
        }),
      ).rejects.toThrow(ForbiddenError);
    });

    it('FindingService.verifyFinding: non-member targeting archived foreign project receives 404; member receives 403', async () => {
      const foreignAnalyst = createTestAnalystActor(projectId);
      const readyFinding: FindingEntity = { ...archivedFinding, status: 'READY_FOR_REVIEW', assignedToId: dev1Id };
      (mockFindingRepo.findById as ReturnType<typeof vi.fn>).mockResolvedValue(readyFinding);
      (mockProjectRepo.lockProject as ReturnType<typeof vi.fn>).mockResolvedValue(archivedProject);
      (mockProjectRepo.lockMember as ReturnType<typeof vi.fn>).mockResolvedValue(null);

      // Non-member receives 404
      await expect(
        findingService.verifyFinding(foreignAnalyst, findingId, {
          expectedVersion: 1,
          outcome: 'VERIFIED',
        }),
      ).rejects.toThrow(EntityNotFoundError);

      // Authorized member receives 403
      const memberAnalyst = createTestAnalystActor(archivedProjectId, { id: analystId });
      (mockProjectRepo.lockMember as ReturnType<typeof vi.fn>).mockResolvedValue({
        projectId: archivedProjectId,
        userId: analystId,
        role: 'ANALYST',
        addedById: analystId,
        createdAt: new Date(),
      });

      await expect(
        findingService.verifyFinding(memberAnalyst, findingId, {
          expectedVersion: 1,
          outcome: 'VERIFIED',
        }),
      ).rejects.toThrow(ForbiddenError);
    });
  });

  // ==========================================================================
  // Section E: Separation-of-Duties (SoD OLI-7) Evidence Integrity & Timestamp Collision Ordering
  // ==========================================================================
  describe('E. Separation-of-Duties (SoD OLI-7) Evidence Integrity & Timestamp Collision Ordering', () => {
    const readyFinding: FindingEntity = {
      id: findingId,
      projectId,
      title: 'XSS flaw',
      description: 'Stored XSS',
      severity: 'HIGH',
      category: 'XSS',
      cvssScore: 7.5,
      status: 'READY_FOR_REVIEW',
      createdById: analystId,
      assignedToId: dev1Id,
      dueDate: null,
      isDeleted: false,
      version: 4,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    const activeTask: RemediationTaskEntity = {
      id: taskId,
      findingId,
      assignedToId: dev1Id,
      assignedById: analystId,
      description: 'Fix XSS flaw',
      notes: 'Patch applied',
      status: 'SUBMITTED',
      dueDate: null,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    const activeProject: ProjectEntity = {
      id: projectId,
      name: 'Core Platform',
      slug: 'core-platform',
      description: null,
      isActive: true,
      createdById: analystId,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    beforeEach(() => {
      (mockFindingRepo.findById as ReturnType<typeof vi.fn>).mockResolvedValue(readyFinding);
      (mockProjectRepo.lockProject as ReturnType<typeof vi.fn>).mockResolvedValue(activeProject);
      (mockProjectRepo.lockMember as ReturnType<typeof vi.fn>).mockResolvedValue({
        projectId,
        userId: analystId,
        role: 'ANALYST',
        addedById: analystId,
        createdAt: new Date(),
      });
      (mockFindingRepo.lockFinding as ReturnType<typeof vi.fn>).mockResolvedValue(readyFinding);
      (mockTaskRepo.lockActiveTaskByFindingId as ReturnType<typeof vi.fn>).mockResolvedValue(activeTask);
    });

    it('rejects verification when event metadata.taskId does not match active task id', async () => {
      const analyst = createTestAnalystActor(projectId);
      (mockFindingRepo.getEvents as ReturnType<typeof vi.fn>).mockResolvedValue([
        {
          id: 'ev-1',
          findingId,
          actorId: dev1Id,
          eventType: 'STATUS_CHANGED',
          newStatus: 'READY_FOR_REVIEW',
          metadata: { submitterId: dev1Id, taskId: 'mismatched-task-id' }, // WRONG task ID
          createdAt: new Date(),
        },
      ]);

      await expect(
        findingService.verifyFinding(analyst, findingId, {
          expectedVersion: 4,
          outcome: 'VERIFIED',
        }),
      ).rejects.toThrow(
        expect.objectContaining({
          name: 'ForbiddenError',
          statusCode: 403,
          message: expect.stringContaining('remediation submitter evidence is missing or unavailable for active task'),
        }),
      );
    });

    it('rejects verification when event actorId disagrees with metadata.submitterId (contradictory evidence)', async () => {
      const analyst = createTestAnalystActor(projectId);
      (mockFindingRepo.getEvents as ReturnType<typeof vi.fn>).mockResolvedValue([
        {
          id: 'ev-1',
          findingId,
          actorId: dev1Id,
          eventType: 'STATUS_CHANGED',
          newStatus: 'READY_FOR_REVIEW',
          metadata: { submitterId: dev2Id, taskId }, // actorId is dev1, but submitterId says dev2!
          createdAt: new Date(),
        },
      ]);

      await expect(
        findingService.verifyFinding(analyst, findingId, {
          expectedVersion: 4,
          outcome: 'VERIFIED',
        }),
      ).rejects.toThrow(
        expect.objectContaining({
          name: 'ForbiddenError',
          statusCode: 403,
          message: expect.stringContaining('contradictory remediation submitter evidence'),
        }),
      );
    });

    it('rejects verification when submitter does not match task assigned developer', async () => {
      const analyst = createTestAnalystActor(projectId);
      // Active task is assigned to dev1Id, but submitter was dev2Id
      (mockFindingRepo.getEvents as ReturnType<typeof vi.fn>).mockResolvedValue([
        {
          id: 'ev-1',
          findingId,
          actorId: dev2Id,
          eventType: 'STATUS_CHANGED',
          newStatus: 'READY_FOR_REVIEW',
          metadata: { submitterId: dev2Id, taskId },
          createdAt: new Date(),
        },
      ]);

      await expect(
        findingService.verifyFinding(analyst, findingId, {
          expectedVersion: 4,
          outcome: 'VERIFIED',
        }),
      ).rejects.toThrow(
        expect.objectContaining({
          name: 'ForbiddenError',
          statusCode: 403,
          message: expect.stringContaining('submitter does not match assigned developer'),
        }),
      );
    });

    it('historical remediation cycle cannot supply evidence for current cycle', async () => {
      const analyst = createTestAnalystActor(projectId);
      // Historical cycle 1 submission event
      (mockFindingRepo.getEvents as ReturnType<typeof vi.fn>).mockResolvedValue([
        {
          id: 'ev-cycle-1',
          findingId,
          actorId: dev1Id,
          eventType: 'STATUS_CHANGED',
          newStatus: 'READY_FOR_REVIEW',
          metadata: { submitterId: dev1Id, taskId: 'cycle-1-old-task-id' }, // Prior task
          createdAt: new Date(Date.now() - 3600000),
        },
      ]);

      await expect(
        findingService.verifyFinding(analyst, findingId, {
          expectedVersion: 4,
          outcome: 'VERIFIED',
        }),
      ).rejects.toThrow(
        expect.objectContaining({
          name: 'ForbiddenError',
          statusCode: 403,
          message: expect.stringContaining('remediation submitter evidence is missing or unavailable for active task'),
        }),
      );
    });

    it('rejects verification with stale expectedVersion with ConcurrencyConflictError (HTTP 409)', async () => {
      const analyst = createTestAnalystActor(projectId);
      const err = await findingService
        .verifyFinding(analyst, findingId, {
          expectedVersion: 3, // Current version is 4!
          outcome: 'VERIFIED',
        })
        .catch((e) => e);

      expect(err).toBeInstanceOf(ConcurrencyConflictError);
      expect(err.statusCode).toBe(409);
    });

    it('rejects verification when multiple submission events for same active task have conflicting submitters', async () => {
      const analyst = createTestAnalystActor(projectId);
      (mockFindingRepo.getEvents as ReturnType<typeof vi.fn>).mockResolvedValue([
        {
          id: 'ev-1',
          findingId,
          actorId: dev1Id,
          eventType: 'STATUS_CHANGED',
          newStatus: 'READY_FOR_REVIEW',
          metadata: { submitterId: dev1Id, taskId },
          createdAt: new Date(Date.now() - 1000),
        },
        {
          id: 'ev-2',
          findingId,
          actorId: dev2Id,
          eventType: 'STATUS_CHANGED',
          newStatus: 'READY_FOR_REVIEW',
          metadata: { submitterId: dev2Id, taskId },
          createdAt: new Date(),
        },
      ]);

      await expect(
        findingService.verifyFinding(analyst, findingId, {
          expectedVersion: 4,
          outcome: 'VERIFIED',
        }),
      ).rejects.toThrow(
        expect.objectContaining({
          name: 'ForbiddenError',
          statusCode: 403,
          message: expect.stringContaining('ambiguous remediation submission evidence; active task has multiple submission events'),
        }),
      );
    });

    it('rejects verification when multiple submission events for same active task conflict at identical timestamps', async () => {
      const analyst = createTestAnalystActor(projectId);
      const sharedTime = new Date('2026-10-31T14:00:00.000Z');
      (mockFindingRepo.getEvents as ReturnType<typeof vi.fn>).mockResolvedValue([
        {
          id: 'ev-1',
          findingId,
          actorId: dev1Id,
          eventType: 'STATUS_CHANGED',
          newStatus: 'READY_FOR_REVIEW',
          metadata: { submitterId: dev1Id, taskId, patchNotes: 'Dev1 fix' },
          createdAt: sharedTime,
        },
        {
          id: 'ev-2',
          findingId,
          actorId: dev1Id,
          eventType: 'STATUS_CHANGED',
          newStatus: 'READY_FOR_REVIEW',
          metadata: { submitterId: dev1Id, taskId, patchNotes: 'Conflicting fix' },
          createdAt: sharedTime,
        },
      ]);

      await expect(
        findingService.verifyFinding(analyst, findingId, {
          expectedVersion: 4,
          outcome: 'VERIFIED',
        }),
      ).rejects.toThrow(
        expect.objectContaining({
          name: 'ForbiddenError',
          statusCode: 403,
          message: expect.stringContaining('ambiguous remediation submission evidence; active task has multiple submission events'),
        }),
      );
    });

    it('rejects verification when two otherwise identical submission events exist for the same active task (single-submission-event invariant regression)', async () => {
      const analyst = createTestAnalystActor(projectId);
      const submissionTime = new Date('2026-10-31T14:00:00.000Z');
      (mockFindingRepo.getEvents as ReturnType<typeof vi.fn>).mockResolvedValue([
        {
          id: 'ev-1',
          findingId,
          actorId: dev1Id,
          eventType: 'STATUS_CHANGED',
          newStatus: 'READY_FOR_REVIEW',
          metadata: { submitterId: dev1Id, taskId, patchNotes: 'Identical fix notes' },
          createdAt: submissionTime,
        },
        {
          id: 'ev-2',
          findingId,
          actorId: dev1Id,
          eventType: 'STATUS_CHANGED',
          newStatus: 'READY_FOR_REVIEW',
          metadata: { submitterId: dev1Id, taskId, patchNotes: 'Identical fix notes' },
          createdAt: submissionTime,
        },
      ]);

      await expect(
        findingService.verifyFinding(analyst, findingId, {
          expectedVersion: 4,
          outcome: 'VERIFIED',
        }),
      ).rejects.toThrow(
        expect.objectContaining({
          name: 'ForbiddenError',
          statusCode: 403,
          message: expect.stringContaining('ambiguous remediation submission evidence; active task has multiple submission events'),
        }),
      );
    });

    it('handles timestamp collisions with deterministic secondary sort on event id', async () => {
      const analyst = createTestAnalystActor(projectId);
      const fixedTimestamp = new Date('2026-10-31T12:00:00.000Z');

      // Two events sharing the EXACT SAME timestamp:
      // Event 'ev-a' is earlier in lexical ID, 'ev-b' is later.
      // Even if array order is arbitrary, sorted order must be ev-a then ev-b.
      (mockFindingRepo.getEvents as ReturnType<typeof vi.fn>).mockResolvedValue([
        {
          id: 'ev-b',
          findingId,
          actorId: dev1Id,
          eventType: 'STATUS_CHANGED',
          newStatus: 'READY_FOR_REVIEW',
          metadata: { submitterId: dev1Id, taskId },
          createdAt: fixedTimestamp,
        },
        {
          id: 'ev-a',
          findingId,
          actorId: dev1Id,
          eventType: 'STATUS_CHANGED',
          previousStatus: 'OPEN',
          newStatus: 'IN_PROGRESS',
          metadata: null,
          createdAt: fixedTimestamp,
        },
      ]);

      (mockFindingRepo.updateAtomic as ReturnType<typeof vi.fn>).mockResolvedValue({
        ...readyFinding,
        status: 'VERIFIED',
        version: 5,
      });
      (mockTaskRepo.updateStatus as ReturnType<typeof vi.fn>).mockResolvedValue({
        ...activeTask,
        status: 'VERIFIED',
      });

      const result = await findingService.verifyFinding(analyst, findingId, {
        expectedVersion: 4,
        outcome: 'VERIFIED',
      });

      expect(result.status).toBe('VERIFIED');
    });
  });

  // ==========================================================================
  // Section F: Error Contract Verification
  // ==========================================================================
  describe('F. Error Contract Verification', () => {
    it('InvalidStateTransitionError conforms to HTTP 422 Unprocessable Entity', () => {
      const err = new InvalidStateTransitionError('finding', 'OPEN', 'VERIFIED');
      expect(err.statusCode).toBe(422);
      expect(err.code).toBe('INVALID_STATE_TRANSITION');
    });
  });
});
