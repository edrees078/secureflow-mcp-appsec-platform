import { Prisma } from '../../generated/prisma/client.js';
import type { ProjectRole } from '@secureflow/schemas';
import type {
  CreateProjectRepoData,
  IProjectRepository,
  PaginatedResult,
  ProjectEntity,
  ProjectFilter,
  ProjectMemberEntity,
  ProjectQueryScope,
  AddProjectMemberRepoData,
  UpdateProjectRepoData,
  PrismaDbClient,
} from './types.js';

export class PrismaProjectRepository implements IProjectRepository {
  constructor(private readonly client: PrismaDbClient) {}

  private mapProject(m: Prisma.ProjectModel): ProjectEntity {
    return {
      id: m.id,
      name: m.name,
      slug: m.slug,
      description: m.description,
      isActive: m.isActive,
      createdById: m.createdById,
      createdAt: m.createdAt,
      updatedAt: m.updatedAt,
    };
  }

  private mapMember(m: Prisma.ProjectMemberModel): ProjectMemberEntity {
    return {
      id: m.id,
      projectId: m.projectId,
      userId: m.userId,
      role: m.role,
      addedById: m.addedById,
      createdAt: m.createdAt,
      updatedAt: m.updatedAt,
    };
  }

  private buildWhereClause(scope?: ProjectQueryScope, search?: string): Prisma.ProjectWhereInput {
    const conditions: Prisma.ProjectWhereInput[] = [];

    if (!scope || scope.unrestricted !== true) {
      if (!scope?.accessibleProjectIds || scope.accessibleProjectIds.length === 0) {
        // Restricted scope with no accessible projects matches zero rows (fail-closed)
        return { id: { in: [] } };
      }
      conditions.push({ id: { in: scope.accessibleProjectIds } });
    }

    if (!scope?.includeInactive) {
      conditions.push({ isActive: true });
    }

    if (search && search.trim().length > 0) {
      const term = search.trim();
      conditions.push({
        OR: [
          { name: { contains: term, mode: 'insensitive' } },
          { slug: { contains: term, mode: 'insensitive' } },
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

  public async findById(id: string, scope?: ProjectQueryScope): Promise<ProjectEntity | null> {
    const where = this.buildWhereClause(scope);
    const project = await this.client.project.findFirst({
      where: {
        AND: [{ id }, where],
      },
    });
    return project ? this.mapProject(project) : null;
  }

  public async findBySlug(slug: string, scope?: ProjectQueryScope): Promise<ProjectEntity | null> {
    const where = this.buildWhereClause(scope);
    const project = await this.client.project.findFirst({
      where: {
        AND: [{ slug }, where],
      },
    });
    return project ? this.mapProject(project) : null;
  }

  public async findMany(filter: ProjectFilter): Promise<PaginatedResult<ProjectEntity>> {
    const where = this.buildWhereClause(filter.scope, filter.search);
    const page = Math.max(1, filter.page ?? 1);
    const limit = Math.min(100, Math.max(1, filter.limit ?? 25));
    const skip = (page - 1) * limit;

    const [items, total] = await Promise.all([
      this.client.project.findMany({
        where,
        orderBy: [{ name: 'asc' }, { id: 'asc' }],
        skip,
        take: limit,
      }),
      this.client.project.count({ where }),
    ]);

    return {
      items: items.map((p) => this.mapProject(p)),
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit) || 1,
    };
  }

  public async create(data: CreateProjectRepoData): Promise<ProjectEntity> {
    const created = await this.client.project.create({
      data: {
        name: data.name,
        slug: data.slug,
        description: data.description ?? null,
        createdById: data.createdById,
        isActive: true,
      },
    });
    return this.mapProject(created);
  }

  public async update(id: string, data: UpdateProjectRepoData): Promise<ProjectEntity> {
    const updateData: Prisma.ProjectUpdateInput = {};
    if (data.name !== undefined) {
      updateData.name = data.name;
    }
    if (data.description !== undefined) {
      updateData.description = data.description;
    }
    if (data.isActive !== undefined) {
      updateData.isActive = data.isActive;
    }

    const updated = await this.client.project.update({
      where: { id },
      data: updateData,
    });
    return this.mapProject(updated);
  }

  public async addMember(
    projectId: string,
    data: AddProjectMemberRepoData,
  ): Promise<ProjectMemberEntity> {
    const member = await this.client.projectMember.create({
      data: {
        projectId,
        userId: data.userId,
        role: data.role,
        addedById: data.addedById,
      },
    });
    return this.mapMember(member);
  }

  public async removeMember(projectId: string, userId: string): Promise<boolean> {
    const result = await this.client.projectMember.deleteMany({
      where: {
        projectId,
        userId,
      },
    });
    return result.count > 0;
  }

  public async getMembers(projectId: string): Promise<ProjectMemberEntity[]> {
    const members = await this.client.projectMember.findMany({
      where: { projectId },
      orderBy: { createdAt: 'asc' },
    });
    return members.map((m) => this.mapMember(m));
  }

  public async isMember(projectId: string, userId: string): Promise<boolean> {
    const count = await this.client.projectMember.count({
      where: {
        projectId,
        userId,
      },
    });
    return count > 0;
  }

  public async lockProject(
    id: string,
    mode: 'SHARE' | 'UPDATE' = 'SHARE',
  ): Promise<ProjectEntity | null> {
    const lockClause = mode === 'UPDATE' ? Prisma.sql`FOR UPDATE` : Prisma.sql`FOR SHARE`;
    const rows = await this.client.$queryRaw<
      Array<{
        id: string;
        name: string;
        slug: string;
        description: string | null;
        is_active: boolean;
        created_by_id: string;
        created_at: Date;
        updated_at: Date;
      }>
    >(
      Prisma.sql`SELECT id, name, slug, description, is_active, created_by_id, created_at, updated_at FROM projects WHERE id = ${id}::uuid ${lockClause}`,
    );
    const row = rows[0];
    if (!row) {
      return null;
    }
    return {
      id: row.id,
      name: row.name,
      slug: row.slug,
      description: row.description,
      isActive: row.is_active,
      createdById: row.created_by_id,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }

  public async lockMember(
    projectId: string,
    userId: string,
    mode: 'SHARE' | 'UPDATE' = 'SHARE',
  ): Promise<ProjectMemberEntity | null> {
    const lockClause = mode === 'UPDATE' ? Prisma.sql`FOR UPDATE` : Prisma.sql`FOR SHARE`;
    const rows = await this.client.$queryRaw<
      Array<{
        id: string;
        project_id: string;
        user_id: string;
        role: string;
        added_by_id: string;
        created_at: Date;
        updated_at: Date;
      }>
    >(
      Prisma.sql`SELECT id, project_id, user_id, role, added_by_id, created_at, updated_at FROM project_members WHERE project_id = ${projectId}::uuid AND user_id = ${userId}::uuid ${lockClause}`,
    );
    const row = rows[0];
    if (!row) {
      return null;
    }
    return {
      id: row.id,
      projectId: row.project_id,
      userId: row.user_id,
      role: row.role as ProjectRole,
      addedById: row.added_by_id,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }

  public async lockMembers(
    projectId: string,
    userIds: string[],
    mode: 'SHARE' | 'UPDATE' = 'SHARE',
  ): Promise<ProjectMemberEntity[]> {
    if (userIds.length === 0) {
      return [];
    }
    // Canonical rule: Sort target user_id values in ascending lexical order prior to lock acquisition to eliminate deadlock cycles
    const sorted = [...userIds].sort();
    const lockClause = mode === 'UPDATE' ? Prisma.sql`FOR UPDATE` : Prisma.sql`FOR SHARE`;
    const rows = await this.client.$queryRaw<
      Array<{
        id: string;
        project_id: string;
        user_id: string;
        role: string;
        added_by_id: string;
        created_at: Date;
        updated_at: Date;
      }>
    >(
      Prisma.sql`SELECT id, project_id, user_id, role, added_by_id, created_at, updated_at FROM project_members WHERE project_id = ${projectId}::uuid AND user_id = ANY(${sorted}::uuid[]) ORDER BY user_id ASC ${lockClause}`,
    );
    return rows.map((row) => ({
      id: row.id,
      projectId: row.project_id,
      userId: row.user_id,
      role: row.role as ProjectRole,
      addedById: row.added_by_id,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    }));
  }

  public async getMemberRole(projectId: string, userId: string): Promise<ProjectRole | null> {
    const rows = await this.client.$queryRaw<Array<{ role: string }>>(
      Prisma.sql`SELECT role FROM project_members WHERE project_id = ${projectId}::uuid AND user_id = ${userId}::uuid FOR SHARE`,
    );
    const row = rows[0];
    return row ? (row.role as ProjectRole) : null;
  }
}
