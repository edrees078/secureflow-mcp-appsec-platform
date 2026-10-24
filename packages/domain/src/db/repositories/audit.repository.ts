import { Prisma } from '../../generated/prisma/client.js';
import type {
  AuditEventEntity,
  AuditEventFilter,
  CreateAuditEventRepoData,
  IAuditRepository,
  PaginatedResult,
  PrismaDbClient,
} from './types.js';

/**
 * Append-only Audit Repository.
 *
 * Invariant: Audit records are strictly immutable at the application layer.
 * No update, modify, or delete methods are exposed by this interface or implementation.
 *
 * Note: This is an application-level immutability guarantee. Database-level permissions
 * (e.g. REVOKE UPDATE, DELETE ON audit_events), row-level security, and cryptographic tamper resistance
 * remain separate infrastructure and authorization concerns.
 */
export class PrismaAuditRepository implements IAuditRepository {
  constructor(private readonly client: PrismaDbClient) {}

  private mapAudit(m: Prisma.AuditEventModel): AuditEventEntity {
    return {
      id: m.id,
      actorId: m.actorId,
      eventCategory: m.eventCategory,
      eventType: m.eventType,
      resourceId: m.resourceId,
      resourceType: m.resourceType,
      beforeState: m.beforeState ? (m.beforeState as Record<string, unknown>) : null,
      afterState: m.afterState ? (m.afterState as Record<string, unknown>) : null,
      ipAddress: m.ipAddress,
      userAgent: m.userAgent,
      createdAt: m.createdAt,
    };
  }

  public async append(data: CreateAuditEventRepoData): Promise<AuditEventEntity> {
    const created = await this.client.auditEvent.create({
      data: {
        actorId: data.actorId ?? null,
        eventCategory: data.eventCategory,
        eventType: data.eventType,
        resourceId: data.resourceId ?? null,
        resourceType: data.resourceType ?? null,
        beforeState: data.beforeState ? (data.beforeState as Prisma.InputJsonValue) : Prisma.JsonNull,
        afterState: data.afterState ? (data.afterState as Prisma.InputJsonValue) : Prisma.JsonNull,
        ipAddress: data.ipAddress ?? null,
        userAgent: data.userAgent ?? null,
      },
    });
    return this.mapAudit(created);
  }

  public async query(filter: AuditEventFilter): Promise<PaginatedResult<AuditEventEntity>> {
    const conditions: Prisma.AuditEventWhereInput[] = [];

    if (filter.eventCategory) {
      conditions.push({ eventCategory: filter.eventCategory });
    }
    if (filter.eventType) {
      conditions.push({ eventType: filter.eventType });
    }
    if (filter.resourceId) {
      conditions.push({ resourceId: filter.resourceId });
    }
    if (filter.resourceType) {
      conditions.push({ resourceType: filter.resourceType });
    }
    if (filter.actorId) {
      conditions.push({ actorId: filter.actorId });
    }
    if (filter.fromTimestamp || filter.toTimestamp) {
      const createdAtFilter: Prisma.DateTimeFilter = {};
      if (filter.fromTimestamp) {
        createdAtFilter.gte = filter.fromTimestamp;
      }
      if (filter.toTimestamp) {
        createdAtFilter.lte = filter.toTimestamp;
      }
      conditions.push({ createdAt: createdAtFilter });
    }

    const where: Prisma.AuditEventWhereInput =
      conditions.length === 0 ? {} : conditions.length === 1 && conditions[0] ? conditions[0] : { AND: conditions };

    const page = Math.max(1, filter.page ?? 1);
    const limit = Math.min(100, Math.max(1, filter.limit ?? 25));
    const skip = (page - 1) * limit;

    const [items, total] = await Promise.all([
      this.client.auditEvent.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        skip,
        take: limit,
      }),
      this.client.auditEvent.count({ where }),
    ]);

    return {
      items: items.map((a) => this.mapAudit(a)),
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit) || 1,
    };
  }
}
