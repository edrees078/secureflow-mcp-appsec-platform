import { Prisma } from '../../generated/prisma/client.js';
import {
  ConcurrencyConflictError,
  DomainValidationError,
  EntityNotFoundError,
} from '@secureflow/shared';
import type {
  CreateFindingEventRepoData,
  CreateFindingRepoData,
  FindingEntity,
  FindingEventEntity,
  FindingFilter,
  FindingQueryScope,
  IFindingRepository,
  PaginatedResult,
  PrismaDbClient,
  UpdateFindingRepoData,
} from './types.js';

export class PrismaFindingRepository implements IFindingRepository {
  constructor(private readonly client: PrismaDbClient) {}

  private mapFinding(m: Prisma.FindingModel): FindingEntity {
    return {
      id: m.id,
      projectId: m.projectId,
      title: m.title,
      description: m.description,
      severity: m.severity,
      category: m.category,
      cvssScore: m.cvssScore !== null ? Number(m.cvssScore) : null,
      status: m.status,
      createdById: m.createdById,
      assignedToId: m.assignedToId,
      dueDate: m.dueDate,
      isDeleted: m.isDeleted,
      version: m.version,
      createdAt: m.createdAt,
      updatedAt: m.updatedAt,
    };
  }

  private mapEvent(m: Prisma.FindingEventModel): FindingEventEntity {
    return {
      id: m.id,
      findingId: m.findingId,
      actorId: m.actorId,
      eventType: m.eventType,
      previousStatus: m.previousStatus,
      newStatus: m.newStatus,
      metadata: m.metadata ? (m.metadata as Record<string, unknown>) : null,
      createdAt: m.createdAt,
    };
  }

  private buildWhereClause(
    scope?: FindingQueryScope,
    filter?: Omit<FindingFilter, 'scope'>,
  ): Prisma.FindingWhereInput {
    const conditions: Prisma.FindingWhereInput[] = [];

    // 1. Project-level query scoping (fail-closed if unrestricted is not true)
    if (!scope || scope.unrestricted !== true) {
      if (!scope?.accessibleProjectIds || scope.accessibleProjectIds.length === 0) {
        // Restricted scope without accessible projects matches zero rows (fail-closed)
        return { projectId: { in: [] } };
      }
      conditions.push({ projectId: { in: scope.accessibleProjectIds } });
    }

    // 2. Assignment scoping (Developer persona: sees only assigned findings)
    if (scope?.assignedToUserId) {
      conditions.push({ assignedToId: scope.assignedToUserId });
    }

    // 3. Invariant OLI-12: Exclude soft-deleted findings unless explicitly authorized
    if (!scope?.includeDeleted) {
      conditions.push({ isDeleted: false });
    }

    // 4. Optional user filters
    if (filter?.projectId) {
      conditions.push({ projectId: filter.projectId });
    }
    if (filter?.status) {
      conditions.push({ status: filter.status });
    }
    if (filter?.severity) {
      conditions.push({ severity: filter.severity });
    }
    if (filter?.category) {
      conditions.push({ category: filter.category });
    }
    if (filter?.assignedToId) {
      conditions.push({ assignedToId: filter.assignedToId });
    }
    if (filter?.search && filter.search.trim().length > 0) {
      const term = filter.search.trim();
      conditions.push({
        OR: [
          { title: { contains: term, mode: 'insensitive' } },
          { description: { contains: term, mode: 'insensitive' } },
        ],
      });
    }

    if (conditions.length === 0) {
      return {};
    }
    if (conditions.length === 1 && conditions[0]) {
      return conditions[0];
    }
    return { AND: conditions };
  }

  public async findById(id: string, scope?: FindingQueryScope): Promise<FindingEntity | null> {
    const where = this.buildWhereClause(scope);
    const finding = await this.client.finding.findFirst({
      where: {
        AND: [{ id }, where],
      },
    });
    return finding ? this.mapFinding(finding) : null;
  }

  public async findMany(filter: FindingFilter): Promise<PaginatedResult<FindingEntity>> {
    const where = this.buildWhereClause(filter.scope, filter);
    const page = Math.max(1, filter.page ?? 1);
    const limit = Math.min(100, Math.max(1, filter.limit ?? 25));
    const skip = (page - 1) * limit;

    const [items, total] = await Promise.all([
      this.client.finding.findMany({
        where,
        orderBy: [{ createdAt: 'desc' }, { id: 'asc' }],
        skip,
        take: limit,
      }),
      this.client.finding.count({ where }),
    ]);

    return {
      items: items.map((f) => this.mapFinding(f)),
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit) || 1,
    };
  }

  public async create(data: CreateFindingRepoData): Promise<FindingEntity> {
    const created = await this.client.finding.create({
      data: {
        projectId: data.projectId,
        title: data.title,
        description: data.description,
        severity: data.severity,
        category: data.category,
        cvssScore: data.cvssScore !== undefined && data.cvssScore !== null ? data.cvssScore : null,
        status: 'OPEN',
        createdById: data.createdById,
        assignedToId: data.assignedToId ?? null,
        dueDate: data.dueDate ?? null,
        isDeleted: false,
        version: 1,
      },
    });
    return this.mapFinding(created);
  }

  /**
   * Atomic OCC Update (Finding.version Compare-and-Increment).
   *
   * Executes atomic UPDATE with WHERE id = :id AND version = :expectedVersion.
   * If updateMany affected 0 rows, diagnoses whether the record is missing or conflicted.
   */
  public async updateAtomic(id: string, data: UpdateFindingRepoData): Promise<FindingEntity> {
    if (typeof data.expectedVersion !== 'number' || data.expectedVersion < 1) {
      throw new DomainValidationError(
        'Atomic update requires a valid integer expectedVersion >= 1',
        [
          {
            path: ['expectedVersion'],
            message: 'expectedVersion must be a positive integer',
          },
        ],
      );
    }

    const prismaUpdate: Prisma.FindingUncheckedUpdateManyInput = {
      version: { increment: 1 },
    };

    if (data.title !== undefined) prismaUpdate.title = data.title;
    if (data.description !== undefined) prismaUpdate.description = data.description;
    if (data.severity !== undefined) prismaUpdate.severity = data.severity;
    if (data.category !== undefined) prismaUpdate.category = data.category;
    if (data.cvssScore !== undefined) prismaUpdate.cvssScore = data.cvssScore;
    if (data.status !== undefined) prismaUpdate.status = data.status;
    if (data.assignedToId !== undefined) prismaUpdate.assignedToId = data.assignedToId;
    if (data.dueDate !== undefined) prismaUpdate.dueDate = data.dueDate;
    if (data.isDeleted !== undefined) prismaUpdate.isDeleted = data.isDeleted;

    const result = await this.client.finding.updateMany({
      where: {
        id,
        version: data.expectedVersion,
      },
      data: prismaUpdate,
    });

    if (result.count === 0) {
      const current = await this.client.finding.findUnique({
        where: { id },
        select: { id: true, version: true },
      });

      if (!current) {
        throw new EntityNotFoundError('Finding', id);
      }

      throw new ConcurrencyConflictError(
        `Optimistic concurrency conflict on Finding '${id}'. Expected version ${data.expectedVersion}, but found version ${current.version}.`,
        current.version,
        data.expectedVersion,
      );
    }

    const updated = await this.client.finding.findUnique({
      where: { id },
    });

    if (!updated) {
      throw new EntityNotFoundError('Finding', id);
    }

    return this.mapFinding(updated);
  }

  /**
   * Soft-deletes a finding with atomic OCC version check.
   */
  public async softDelete(id: string, expectedVersion: number): Promise<FindingEntity> {
    return await this.updateAtomic(id, {
      expectedVersion,
      isDeleted: true,
    });
  }

  public async addEvent(data: CreateFindingEventRepoData): Promise<FindingEventEntity> {
    const created = await this.client.findingEvent.create({
      data: {
        findingId: data.findingId,
        actorId: data.actorId,
        eventType: data.eventType,
        previousStatus: data.previousStatus ?? null,
        newStatus: data.newStatus ?? null,
        metadata: data.metadata ? (data.metadata as Prisma.InputJsonValue) : Prisma.JsonNull,
      },
    });
    return this.mapEvent(created);
  }

  public async getEvents(findingId: string): Promise<FindingEventEntity[]> {
    const events = await this.client.findingEvent.findMany({
      where: { findingId },
      orderBy: { createdAt: 'asc' },
    });
    return events.map((e) => this.mapEvent(e));
  }
}
