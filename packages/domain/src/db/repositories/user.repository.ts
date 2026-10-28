import { Prisma } from '../../generated/prisma/client.js';
import type { GlobalRole, ProjectRole } from '@secureflow/schemas';
import type {
  AuthoritativeUserEntity,
  IUserRepository,
  PrismaDbClient,
  UserAuthEntity,
} from './types.js';

export class PrismaUserRepository implements IUserRepository {
  constructor(private readonly client: PrismaDbClient) {}

  public async findById(id: string): Promise<UserAuthEntity | null> {
    const user = await this.client.user.findUnique({
      where: { id },
      select: {
        id: true,
        isActive: true,
        globalRole: true,
      },
    });
    if (!user) {
      return null;
    }
    return {
      id: user.id,
      isActive: user.isActive,
      globalRole: user.globalRole as GlobalRole,
    };
  }

  public async findAuthoritativeUser(id: string): Promise<AuthoritativeUserEntity | null> {
    const user = await this.client.user.findUnique({
      where: { id },
      select: {
        id: true,
        isActive: true,
        globalRole: true,
        projectMemberships: {
          select: {
            projectId: true,
            role: true,
          },
        },
      },
    });
    if (!user) {
      return null;
    }
    return {
      id: user.id,
      isActive: user.isActive,
      globalRole: user.globalRole as GlobalRole,
      memberships: user.projectMemberships.map((m) => ({
        projectId: m.projectId,
        role: m.role as ProjectRole,
      })),
    };
  }

  public async lockUser(
    id: string,
    mode: 'SHARE' | 'UPDATE' = 'SHARE',
  ): Promise<UserAuthEntity | null> {
    const lockClause = mode === 'UPDATE' ? Prisma.sql`FOR UPDATE` : Prisma.sql`FOR SHARE`;
    const rows = await this.client.$queryRaw<
      Array<{ id: string; is_active: boolean; global_role: string }>
    >(
      Prisma.sql`SELECT id, is_active, global_role FROM users WHERE id = ${id}::uuid ${lockClause}`,
    );
    const row = rows[0];
    if (!row) {
      return null;
    }
    return {
      id: row.id,
      isActive: row.is_active,
      globalRole: row.global_role as GlobalRole,
    };
  }

  public async lockUsers(
    userIds: string[],
    mode: 'SHARE' | 'UPDATE' = 'SHARE',
  ): Promise<Map<string, UserAuthEntity>> {
    const uniqueSortedIds = [...new Set(userIds)].sort();
    const result = new Map<string, UserAuthEntity>();
    for (const id of uniqueSortedIds) {
      const user = await this.lockUser(id, mode);
      if (user) {
        result.set(user.id, user);
      }
    }
    return result;
  }

  public async deactivateUser(id: string): Promise<UserAuthEntity> {
    const updated = await this.client.user.update({
      where: { id },
      data: { isActive: false },
      select: { id: true, isActive: true, globalRole: true },
    });
    return {
      id: updated.id,
      isActive: updated.isActive,
      globalRole: updated.globalRole as GlobalRole,
    };
  }

  public async updateGlobalRole(id: string, role: GlobalRole): Promise<UserAuthEntity> {
    const updated = await this.client.user.update({
      where: { id },
      data: { globalRole: role },
      select: { id: true, isActive: true, globalRole: true },
    });
    return {
      id: updated.id,
      isActive: updated.isActive,
      globalRole: updated.globalRole as GlobalRole,
    };
  }
}
