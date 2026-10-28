import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  AuditService,
  type IAuditRepository,
  type IUserRepository,
  type IProjectRepository,
  type IFindingRepository,
  type ITaskRepository,
  type AuditEventEntity,
} from '../../src/index.js';
import {
  createTestAdminActor,
  createTestAnalystActor,
  createTestDeveloperActor,
  createSyntheticActorContext,
  createTestAuditService,
  type RepositoryContainer,
} from '../../src/testing/index.js';
import {
  ForbiddenError,
  UnauthorizedError,
} from '@secureflow/shared';

describe('Gate 3D.2 — AuditService (Unit Tests)', () => {
  let mockAuditRepo: Partial<IAuditRepository>;
  let mockUserRepo: Partial<IUserRepository>;
  let mockRepos: RepositoryContainer;
  let service: AuditService;

  beforeEach(() => {
    mockAuditRepo = {
      append: vi.fn(),
      query: vi.fn().mockResolvedValue({
        items: [
          {
            id: 'audit-1',
            actorId: 'admin-1',
            eventCategory: 'PROJECT',
            eventType: 'project.created',
            resourceId: 'project-1',
            resourceType: 'Project',
            beforeState: null,
            afterState: { name: 'Alpha' },
            ipAddress: null,
            userAgent: null,
            createdAt: new Date(),
          } as AuditEventEntity,
        ],
        total: 1,
        page: 1,
        limit: 25,
        totalPages: 1,
      }),
    };

    mockUserRepo = {
      findById: vi.fn().mockResolvedValue({
        id: '00000000-0000-0000-0000-000000000001',
        isActive: true,
        globalRole: 'ADMIN',
      }),
      lockUser: vi.fn(),
      deactivateUser: vi.fn(),
      updateGlobalRole: vi.fn(),
    };

    mockRepos = {
      auditRepo: mockAuditRepo as IAuditRepository,
      userRepo: mockUserRepo as IUserRepository,
      projectRepo: {} as IProjectRepository,
      findingRepo: {} as IFindingRepository,
      taskRepo: {} as ITaskRepository,
    };

    service = createTestAuditService(mockRepos);
  });

  describe('0. Service Initialization Contract & Dependency Boundaries', () => {
    it('rejects construction with missing or undefined dependencies', () => {
      expect(() => new AuditService(undefined as unknown as RepositoryContainer))
        .toThrow(expect.objectContaining({
          code: 'SERVICE_INITIALIZATION_ERROR',
          statusCode: 500,
        }));
    });

    it('rejects construction with incomplete repository container', () => {
      expect(() => new AuditService({ repositories: {} as unknown as RepositoryContainer }))
        .toThrow(expect.objectContaining({
          code: 'SERVICE_INITIALIZATION_ERROR',
          statusCode: 500,
        }));
    });
  });

  describe('1. AuditService Authorization & Permissions', () => {
    it('Admin caller is permitted to query audit logs', async () => {
      const admin = createTestAdminActor();
      const result = await service.queryAuditLogs(admin, {
        eventCategory: 'PROJECT',
        page: 1,
        limit: 25,
      });

      expect(result.total).toBe(1);
      expect(result.items.length).toBe(1);
      expect(mockAuditRepo.query).toHaveBeenCalledWith(
        expect.objectContaining({
          eventCategory: 'PROJECT',
          page: 1,
          limit: 25,
        }),
      );
    });

    it('Non-admin caller (Analyst) is rejected with 403 Forbidden without disclosing logs', async () => {
      const analyst = createTestAnalystActor('project-1');
      await expect(service.queryAuditLogs(analyst, { page: 1, limit: 10 }))
        .rejects.toThrow(ForbiddenError);
      expect(mockAuditRepo.query).not.toHaveBeenCalled();
    });

    it('Non-admin caller (Developer) is rejected with 403 Forbidden without disclosing logs', async () => {
      const dev = createTestDeveloperActor('project-1');
      await expect(service.queryAuditLogs(dev, { page: 1, limit: 10 }))
        .rejects.toThrow(ForbiddenError);
      expect(mockAuditRepo.query).not.toHaveBeenCalled();
    });

    it('Unauthenticated request is rejected with 401 Unauthorized', async () => {
      await expect(service.queryAuditLogs(null as unknown as ActorContext, { page: 1, limit: 10 }))
        .rejects.toThrow(UnauthorizedError);
      expect(mockAuditRepo.query).not.toHaveBeenCalled();
    });

    it('Inactive admin caller is rejected with 403 ACCOUNT_INACTIVE', async () => {
      const inactiveAdmin = createSyntheticActorContext({
        id: 'admin-1',
        globalRole: 'ADMIN',
        isActive: false,
      });
      await expect(service.queryAuditLogs(inactiveAdmin, { page: 1, limit: 10 }))
        .rejects.toThrow(ForbiddenError);
      expect(mockAuditRepo.query).not.toHaveBeenCalled();
    });

    it('Stale global-role: caller has in-memory ADMIN role, but PostgreSQL returns ANALYST -> rejected with 403', async () => {
      const staleAdmin = createTestAdminActor();
      (mockUserRepo.findById as ReturnType<typeof vi.fn>).mockResolvedValue({
        id: staleAdmin.id,
        isActive: true,
        globalRole: 'ANALYST',
      });

      await expect(service.queryAuditLogs(staleAdmin, { page: 1, limit: 10 }))
        .rejects.toThrow(ForbiddenError);
      expect(mockAuditRepo.query).not.toHaveBeenCalled();
    });

    it('Authorization check precedes query validation: non-admin caller receives 403 even if query is malformed', async () => {
      const dev = createTestDeveloperActor('project-1');
      await expect(
        service.queryAuditLogs(dev, {
          fromTimestamp: 'malformed-date-string',
          limit: 9999, // also invalid
        }),
      ).rejects.toThrow(ForbiddenError);
      expect(mockAuditRepo.query).not.toHaveBeenCalled();
    });
  });

  describe('2. Audit Query Filtering, Validation & Date Parsing', () => {
    it('Parses ISO 8601 datetime strings into Date objects for repository filter', async () => {
      const admin = createTestAdminActor();
      const fromStr = '2026-01-01T00:00:00.000Z';
      const toStr = '2026-01-31T23:59:59.999Z';

      await service.queryAuditLogs(admin, {
        fromTimestamp: fromStr,
        toTimestamp: toStr,
        page: 2,
        limit: 50,
      });

      expect(mockAuditRepo.query).toHaveBeenCalledWith(
        expect.objectContaining({
          fromTimestamp: new Date(fromStr),
          toTimestamp: new Date(toStr),
          page: 2,
          limit: 50,
        }),
      );
    });

    it('Rejects reversed date ranges (fromTimestamp > toTimestamp) with HTTP 400 INVALID_DATE_RANGE', async () => {
      const admin = createTestAdminActor();
      const fromStr = '2026-02-01T00:00:00.000Z';
      const toStr = '2026-01-01T00:00:00.000Z';

      await expect(
        service.queryAuditLogs(admin, {
          fromTimestamp: fromStr,
          toTimestamp: toStr,
        }),
      ).rejects.toThrow(expect.objectContaining({
        code: 'INVALID_DATE_RANGE',
        statusCode: 400,
      }));
      expect(mockAuditRepo.query).not.toHaveBeenCalled();
    });

    it('Rejects invalid date string formats via schema validation', async () => {
      const admin = createTestAdminActor();
      await expect(
        service.queryAuditLogs(admin, {
          fromTimestamp: 'not-a-date',
        }),
      ).rejects.toThrow();
      expect(mockAuditRepo.query).not.toHaveBeenCalled();
    });

    it('Rejects unapproved extra properties via strict DTO validation', async () => {
      const admin = createTestAdminActor();
      await expect(
        service.queryAuditLogs(admin, {
          unapprovedProp: 'injection',
        } as unknown as { page: number }),
      ).rejects.toThrow();
      expect(mockAuditRepo.query).not.toHaveBeenCalled();
    });

    it('Rejects limit greater than 100 via schema validation', async () => {
      const admin = createTestAdminActor();
      await expect(
        service.queryAuditLogs(admin, {
          limit: 101,
        }),
      ).rejects.toThrow();
    });
  });
});
