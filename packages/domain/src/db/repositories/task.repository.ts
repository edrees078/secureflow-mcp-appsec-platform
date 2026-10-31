import type { RemediationTaskStatus } from '@secureflow/schemas';
import { Prisma } from '../../generated/prisma/client.js';
import type {
  CreateTaskRepoData,
  ITaskRepository,
  PrismaDbClient,
  RemediationTaskEntity,
} from './types.js';

export class PrismaTaskRepository implements ITaskRepository {
  constructor(private readonly client: PrismaDbClient) {}

  private mapTask(m: Prisma.RemediationTaskModel): RemediationTaskEntity {
    return {
      id: m.id,
      findingId: m.findingId,
      assignedToId: m.assignedToId,
      assignedById: m.assignedById,
      description: m.description,
      notes: m.notes,
      status: m.status,
      dueDate: m.dueDate,
      createdAt: m.createdAt,
      updatedAt: m.updatedAt,
    };
  }

  public async findById(id: string): Promise<RemediationTaskEntity | null> {
    const task = await this.client.remediationTask.findUnique({
      where: { id },
    });
    return task ? this.mapTask(task) : null;
  }

  public async findByFindingId(findingId: string): Promise<RemediationTaskEntity[]> {
    const tasks = await this.client.remediationTask.findMany({
      where: { findingId },
      orderBy: { createdAt: 'asc' },
    });
    return tasks.map((t) => this.mapTask(t));
  }

  public async findActiveByFindingId(findingId: string): Promise<RemediationTaskEntity | null> {
    const activeStatuses: RemediationTaskStatus[] = ['PENDING', 'IN_PROGRESS', 'SUBMITTED'];
    const task = await this.client.remediationTask.findFirst({
      where: {
        findingId,
        status: { in: activeStatuses },
      },
    });
    return task ? this.mapTask(task) : null;
  }

  public async create(data: CreateTaskRepoData): Promise<RemediationTaskEntity> {
    const created = await this.client.remediationTask.create({
      data: {
        findingId: data.findingId,
        assignedToId: data.assignedToId,
        assignedById: data.assignedById,
        description: data.description,
        status: 'PENDING',
        dueDate: data.dueDate ?? null,
      },
    });
    return this.mapTask(created);
  }

  public async updateNotes(id: string, notes: string | null): Promise<RemediationTaskEntity> {
    const updated = await this.client.remediationTask.update({
      where: { id },
      data: { notes },
    });
    return this.mapTask(updated);
  }

  public async updateStatus(
    id: string,
    status: RemediationTaskStatus,
    notes?: string | null,
  ): Promise<RemediationTaskEntity> {
    const updateData: Prisma.RemediationTaskUpdateInput = { status };
    if (notes !== undefined) {
      updateData.notes = notes;
    }
    const updated = await this.client.remediationTask.update({
      where: { id },
      data: updateData,
    });
    return this.mapTask(updated);
  }

  public async lockTask(
    id: string,
    mode: 'SHARE' | 'UPDATE' = 'SHARE',
  ): Promise<RemediationTaskEntity | null> {
    const lockClause = mode === 'UPDATE' ? Prisma.sql`FOR UPDATE` : Prisma.sql`FOR SHARE`;
    const rows = await this.client.$queryRaw<
      Array<{
        id: string;
        finding_id: string;
        assigned_to_id: string;
        assigned_by_id: string;
        description: string;
        notes: string | null;
        status: RemediationTaskStatus;
        due_date: Date | null;
        created_at: Date;
        updated_at: Date;
      }>
    >(
      Prisma.sql`SELECT id, finding_id, assigned_to_id, assigned_by_id, description, notes, status, due_date, created_at, updated_at FROM remediation_tasks WHERE id = ${id}::uuid ${lockClause}`,
    );
    const row = rows[0];
    if (!row) {
      return null;
    }
    return {
      id: row.id,
      findingId: row.finding_id,
      assignedToId: row.assigned_to_id,
      assignedById: row.assigned_by_id,
      description: row.description,
      notes: row.notes,
      status: row.status,
      dueDate: row.due_date,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }

  public async lockActiveTaskByFindingId(
    findingId: string,
    mode: 'SHARE' | 'UPDATE' = 'SHARE',
  ): Promise<RemediationTaskEntity | null> {
    const lockClause = mode === 'UPDATE' ? Prisma.sql`FOR UPDATE` : Prisma.sql`FOR SHARE`;
    const rows = await this.client.$queryRaw<
      Array<{
        id: string;
        finding_id: string;
        assigned_to_id: string;
        assigned_by_id: string;
        description: string;
        notes: string | null;
        status: RemediationTaskStatus;
        due_date: Date | null;
        created_at: Date;
        updated_at: Date;
      }>
    >(
      Prisma.sql`SELECT id, finding_id, assigned_to_id, assigned_by_id, description, notes, status, due_date, created_at, updated_at FROM remediation_tasks WHERE finding_id = ${findingId}::uuid AND status NOT IN ('VERIFIED', 'REJECTED') LIMIT 1 ${lockClause}`,
    );
    const row = rows[0];
    if (!row) {
      return null;
    }
    return {
      id: row.id,
      findingId: row.finding_id,
      assignedToId: row.assigned_to_id,
      assignedById: row.assigned_by_id,
      description: row.description,
      notes: row.notes,
      status: row.status,
      dueDate: row.due_date,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }
}
