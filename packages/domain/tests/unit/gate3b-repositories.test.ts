import { describe, it, expect, vi } from 'vitest';
import {
  createRepositories,
  PrismaProjectRepository,
  PrismaFindingRepository,
  PrismaTaskRepository,
  PrismaAuditRepository,
  type PrismaDbClient,
} from '../../src/db/repositories/index.js';
import {
  ConcurrencyConflictError,
  DomainValidationError,
  EntityNotFoundError,
} from '@secureflow/shared';

describe('Gate 3B — Repository Abstractions, Security Boundaries & Query Scoping (Offline Unit Tests)', () => {
  const createMockDbClient = () =>
    ({
      project: {
        findFirst: vi.fn(),
        findMany: vi.fn().mockResolvedValue([]),
        count: vi.fn().mockResolvedValue(0),
        create: vi.fn(),
        update: vi.fn(),
      },
      projectMember: {
        create: vi.fn(),
        deleteMany: vi.fn().mockResolvedValue({ count: 1 }),
        findMany: vi.fn().mockResolvedValue([]),
        findUnique: vi.fn(),
      },
      finding: {
        findFirst: vi.fn(),
        findMany: vi.fn().mockResolvedValue([]),
        count: vi.fn().mockResolvedValue(0),
        create: vi.fn(),
        updateMany: vi.fn(),
        findUnique: vi.fn(),
      },
      findingEvent: {
        create: vi.fn(),
        findMany: vi.fn().mockResolvedValue([]),
      },
      remediationTask: {
        findUnique: vi.fn(),
        findMany: vi.fn().mockResolvedValue([]),
        findFirst: vi.fn(),
        create: vi.fn(),
        update: vi.fn(),
      },
      auditEvent: {
        create: vi.fn(),
        findMany: vi.fn().mockResolvedValue([]),
        count: vi.fn().mockResolvedValue(0),
      },
    }) as unknown as PrismaDbClient;

  describe('Repository Factory (createRepositories) & Transaction Isolation', () => {
    it('instantiates all 4 repositories bound to the passed database client', () => {
      const mockClient = createMockDbClient();
      const repos = createRepositories(mockClient);

      expect(repos.projectRepo).toBeInstanceOf(PrismaProjectRepository);
      expect(repos.findingRepo).toBeInstanceOf(PrismaFindingRepository);
      expect(repos.taskRepo).toBeInstanceOf(PrismaTaskRepository);
      expect(repos.auditRepo).toBeInstanceOf(PrismaAuditRepository);
    });

    it('ensures every transaction repository uses the exact same Prisma transaction client', () => {
      const mockTxClient = createMockDbClient();
      const repos = createRepositories(mockTxClient);

      // Access private client to verify identical object reference
      const projClient = (repos.projectRepo as unknown as { client: PrismaDbClient }).client;
      const findClient = (repos.findingRepo as unknown as { client: PrismaDbClient }).client;
      const taskClient = (repos.taskRepo as unknown as { client: PrismaDbClient }).client;
      const auditClient = (repos.auditRepo as unknown as { client: PrismaDbClient }).client;

      expect(projClient).toBe(mockTxClient);
      expect(findClient).toBe(mockTxClient);
      expect(taskClient).toBe(mockTxClient);
      expect(auditClient).toBe(mockTxClient);
    });
  });

  describe('ProjectRepository Query Scoping & Fail-Closed Boundaries', () => {
    it('restricts findMany to accessibleProjectIds by default', async () => {
      const mockClient = createMockDbClient();
      const repo = new PrismaProjectRepository(mockClient);

      await repo.findMany({
        scope: { accessibleProjectIds: ['p-1', 'p-2'] },
      });

      expect(mockClient.project.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({
            AND: expect.arrayContaining([
              { id: { in: ['p-1', 'p-2'] } },
              { isActive: true },
            ]),
          }),
        }),
      );
    });

    it('NEGATIVE: returns empty set if restricted scope has empty accessibleProjectIds', async () => {
      const mockClient = createMockDbClient();
      const repo = new PrismaProjectRepository(mockClient);

      await repo.findMany({
        scope: { accessibleProjectIds: [] },
      });

      expect(mockClient.project.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { id: { in: [] } },
        }),
      );
    });

    it('NEGATIVE: returns empty set if scope is missing (fail-closed default)', async () => {
      const mockClient = createMockDbClient();
      const repo = new PrismaProjectRepository(mockClient);

      // Cast to test missing scope edge case
      await repo.findMany({} as unknown as { scope: { accessibleProjectIds: string[] } });

      expect(mockClient.project.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { id: { in: [] } },
        }),
      );
    });

    it('NEGATIVE: findById with empty accessibleProjectIds returns null without finding project', async () => {
      const mockClient = createMockDbClient();
      const repo = new PrismaProjectRepository(mockClient);
      (mockClient.project.findFirst as ReturnType<typeof vi.fn>).mockResolvedValueOnce(null);

      const result = await repo.findById('p-1', { accessibleProjectIds: [] });

      expect(result).toBeNull();
      expect(mockClient.project.findFirst).toHaveBeenCalledWith(
        expect.objectContaining({
          where: {
            AND: [{ id: 'p-1' }, { id: { in: [] } }],
          },
        }),
      );
    });

    it('allows unrestricted query only when explicit unrestricted flag is set', async () => {
      const mockClient = createMockDbClient();
      const repo = new PrismaProjectRepository(mockClient);

      await repo.findMany({
        scope: { unrestricted: true, includeInactive: true },
      });

      expect(mockClient.project.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: {},
        }),
      );
    });
  });

  describe('FindingRepository Query Scoping & Security Boundaries', () => {
    it('restricts findMany to accessibleProjectIds and excludes soft-deleted records by default (OLI-12)', async () => {
      const mockClient = createMockDbClient();
      const repo = new PrismaFindingRepository(mockClient);

      await repo.findMany({
        scope: { accessibleProjectIds: ['p-1'] },
      });

      expect(mockClient.finding.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({
            AND: expect.arrayContaining([
              { projectId: { in: ['p-1'] } },
              { isDeleted: false },
            ]),
          }),
        }),
      );
    });

    it('NEGATIVE: returns empty set when accessibleProjectIds is empty', async () => {
      const mockClient = createMockDbClient();
      const repo = new PrismaFindingRepository(mockClient);

      await repo.findMany({
        scope: { accessibleProjectIds: [] },
      });

      expect(mockClient.finding.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { projectId: { in: [] } },
        }),
      );
      expect(mockClient.finding.count).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { projectId: { in: [] } },
        }),
      );
    });

    it('NEGATIVE: returns empty set when scope is completely undefined', async () => {
      const mockClient = createMockDbClient();
      const repo = new PrismaFindingRepository(mockClient);

      await repo.findMany({} as unknown as { scope: { accessibleProjectIds: string[] } });

      expect(mockClient.finding.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { projectId: { in: [] } },
        }),
      );
    });

    it('NEGATIVE: findById with unauthorized scope returns null', async () => {
      const mockClient = createMockDbClient();
      const repo = new PrismaFindingRepository(mockClient);
      (mockClient.finding.findFirst as ReturnType<typeof vi.fn>).mockResolvedValueOnce(null);

      const result = await repo.findById('f-1', { accessibleProjectIds: ['p-other'] });

      expect(result).toBeNull();
      expect(mockClient.finding.findFirst).toHaveBeenCalledWith(
        expect.objectContaining({
          where: {
            AND: [
              { id: 'f-1' },
              expect.objectContaining({
                AND: expect.arrayContaining([{ projectId: { in: ['p-other'] } }]),
              }),
            ],
          },
        }),
      );
    });

    it('constrains developer persona assignments strictly to accessible projects', async () => {
      const mockClient = createMockDbClient();
      const repo = new PrismaFindingRepository(mockClient);

      await repo.findMany({
        scope: { accessibleProjectIds: ['p-1'], assignedToUserId: 'dev-user-1' },
      });

      expect(mockClient.finding.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({
            AND: expect.arrayContaining([
              { projectId: { in: ['p-1'] } },
              { assignedToId: 'dev-user-1' },
              { isDeleted: false },
            ]),
          }),
        }),
      );
    });

    it('NEGATIVE: developer assignment with empty accessible projects fails closed to zero rows', async () => {
      const mockClient = createMockDbClient();
      const repo = new PrismaFindingRepository(mockClient);

      await repo.findMany({
        scope: { accessibleProjectIds: [], assignedToUserId: 'dev-user-1' },
      });

      expect(mockClient.finding.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { projectId: { in: [] } },
        }),
      );
    });
  });

  describe('FindingRepository OCC & Atomic Mutation Invariants', () => {
    it('updateAtomic strictly rejects expectedVersion < 1 with DomainValidationError', async () => {
      const mockClient = createMockDbClient();
      const repo = new PrismaFindingRepository(mockClient);

      await expect(repo.updateAtomic('f-1', { expectedVersion: 0, title: 'New' })).rejects.toThrow(
        DomainValidationError,
      );
      await expect(repo.updateAtomic('f-1', { expectedVersion: -1, title: 'New' })).rejects.toThrow(
        DomainValidationError,
      );
    });

    it('updateAtomic throws ConcurrencyConflictError (409) when version does not match', async () => {
      const mockClient = createMockDbClient();
      const repo = new PrismaFindingRepository(mockClient);

      // updateMany affects 0 rows due to version mismatch
      (mockClient.finding.updateMany as ReturnType<typeof vi.fn>).mockResolvedValueOnce({ count: 0 });
      // current version in DB is 2 (caller expected 1)
      (mockClient.finding.findUnique as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
        id: 'f-1',
        version: 2,
      });

      await expect(
        repo.updateAtomic('f-1', { expectedVersion: 1, title: 'Updated' }),
      ).rejects.toThrow(ConcurrencyConflictError);
    });

    it('updateAtomic throws EntityNotFoundError (404) when finding does not exist', async () => {
      const mockClient = createMockDbClient();
      const repo = new PrismaFindingRepository(mockClient);

      (mockClient.finding.updateMany as ReturnType<typeof vi.fn>).mockResolvedValueOnce({ count: 0 });
      (mockClient.finding.findUnique as ReturnType<typeof vi.fn>).mockResolvedValueOnce(null);

      await expect(
        repo.updateAtomic('f-nonexistent', { expectedVersion: 1, title: 'Updated' }),
      ).rejects.toThrow(EntityNotFoundError);
    });
  });

  describe('AuditRepository Immutability Contracts', () => {
    it('AuditRepository does not define update, delete, or remove methods', () => {
      const mockClient = createMockDbClient();
      const repo = new PrismaAuditRepository(mockClient);

      expect((repo as unknown as Record<string, unknown>)['update']).toBeUndefined();
      expect((repo as unknown as Record<string, unknown>)['delete']).toBeUndefined();
      expect((repo as unknown as Record<string, unknown>)['remove']).toBeUndefined();
      expect((repo as unknown as Record<string, unknown>)['modify']).toBeUndefined();
    });
  });
});
