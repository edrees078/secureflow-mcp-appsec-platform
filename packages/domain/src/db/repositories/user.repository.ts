import { createHash } from 'node:crypto';
import { Prisma } from '../../generated/prisma/client.js';
import type { GlobalRole, ProjectRole } from '@secureflow/schemas';
import type {
  AuthoritativeUserEntity,
  CreateUserRepoData,
  IUserRepository,
  PrismaDbClient,
  UserAuthEntity,
  UserProfileEntity,
} from './types.js';

/**
 * Deterministic 64-bit split advisory lock key pair for initial Admin bootstrap serialization:
 * Class key: 2147483001 ('SF_AUTH')
 * Object key: 4001 ('INITIAL_ADMIN_BOOTSTRAP')
 */
const BOOTSTRAP_ADVISORY_LOCK_KEY_1 = 2147483001;
const BOOTSTRAP_ADVISORY_LOCK_KEY_2 = 4001;

interface RawUserProfileRow {
  id: string;
  sub: string;
  email: string;
  display_name: string;
  global_role: string;
  is_active: boolean;
  created_at: Date;
  updated_at: Date;
}

export class PrismaUserRepository implements IUserRepository {
  constructor(private readonly client: PrismaDbClient) {}

  private mapProfileRow(row: RawUserProfileRow): UserProfileEntity {
    return {
      id: row.id,
      sub: row.sub,
      email: row.email,
      displayName: row.display_name,
      globalRole: row.global_role as GlobalRole,
      isActive: row.is_active,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }

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

  public async findProfileById(id: string): Promise<UserProfileEntity | null> {
    const user = await this.client.user.findUnique({
      where: { id },
    });
    if (!user) {
      return null;
    }
    return {
      id: user.id,
      sub: user.sub,
      email: user.email,
      displayName: user.displayName,
      globalRole: user.globalRole as GlobalRole,
      isActive: user.isActive,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    };
  }

  public async findBySub(sub: string): Promise<UserProfileEntity | null> {
    const user = await this.client.user.findUnique({
      where: { sub },
    });
    if (!user) {
      return null;
    }
    return {
      id: user.id,
      sub: user.sub,
      email: user.email,
      displayName: user.displayName,
      globalRole: user.globalRole as GlobalRole,
      isActive: user.isActive,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    };
  }

  public async findByEmail(email: string): Promise<UserProfileEntity | null> {
    const user = await this.client.user.findFirst({
      where: {
        email: {
          equals: email,
          mode: 'insensitive',
        },
      },
    });
    if (!user) {
      return null;
    }
    return {
      id: user.id,
      sub: user.sub,
      email: user.email,
      displayName: user.displayName,
      globalRole: user.globalRole as GlobalRole,
      isActive: user.isActive,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
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

  public async lockUserBySub(
    sub: string,
    mode: 'SHARE' | 'UPDATE' = 'UPDATE',
  ): Promise<UserProfileEntity | null> {
    const lockClause = mode === 'UPDATE' ? Prisma.sql`FOR UPDATE` : Prisma.sql`FOR SHARE`;
    const rows = await this.client.$queryRaw<RawUserProfileRow[]>(
      Prisma.sql`SELECT id, sub, email, display_name, global_role, is_active, created_at, updated_at FROM users WHERE sub = ${sub} ${lockClause}`,
    );
    const row = rows[0];
    if (!row) {
      return null;
    }
    return this.mapProfileRow(row);
  }

  public async lockUserByEmail(
    email: string,
    mode: 'SHARE' | 'UPDATE' = 'UPDATE',
  ): Promise<UserProfileEntity | null> {
    const lockClause = mode === 'UPDATE' ? Prisma.sql`FOR UPDATE` : Prisma.sql`FOR SHARE`;
    const rows = await this.client.$queryRaw<RawUserProfileRow[]>(
      Prisma.sql`SELECT id, sub, email, display_name, global_role, is_active, created_at, updated_at FROM users WHERE LOWER(email) = LOWER(${email}) ${lockClause}`,
    );
    const row = rows[0];
    if (!row) {
      return null;
    }
    return this.mapProfileRow(row);
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

  public async createUser(data: CreateUserRepoData): Promise<UserProfileEntity> {
    const created = await this.client.user.create({
      data: {
        sub: data.sub,
        email: data.email,
        displayName: data.displayName,
        globalRole: data.globalRole,
        isActive: data.isActive ?? true,
      },
    });
    return {
      id: created.id,
      sub: created.sub,
      email: created.email,
      displayName: created.displayName,
      globalRole: created.globalRole as GlobalRole,
      isActive: created.isActive,
      createdAt: created.createdAt,
      updatedAt: created.updatedAt,
    };
  }

  public async updateDisplayName(id: string, displayName: string): Promise<UserProfileEntity> {
    const updated = await this.client.user.update({
      where: { id },
      data: { displayName },
    });
    return {
      id: updated.id,
      sub: updated.sub,
      email: updated.email,
      displayName: updated.displayName,
      globalRole: updated.globalRole as GlobalRole,
      isActive: updated.isActive,
      createdAt: updated.createdAt,
      updatedAt: updated.updatedAt,
    };
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

  public async acquireBootstrapAdvisoryLock(): Promise<void> {
    await this.client.$queryRaw(
      Prisma.sql`SELECT pg_advisory_xact_lock(${BOOTSTRAP_ADVISORY_LOCK_KEY_1}::int, ${BOOTSTRAP_ADVISORY_LOCK_KEY_2}::int)::text AS lock_acquired`,
    );
  }

  /**
   * Acquires deterministic transaction-scoped PostgreSQL advisory locks for canonical
   * `(LOWER(email), sub)` identity pairs in ascending lock-rank order (`email` first, `sub` second).
   * Prevents phantom-read race conditions during concurrent JIT provisioning without deadlocks.
   */
  public async acquireIdentityProvisioningLocks(
    sub: string,
    normalizedEmail: string,
  ): Promise<void> {
    const emailKey = deriveIdentityAdvisoryLockKey('email', normalizedEmail.toLowerCase());
    const subKey = deriveIdentityAdvisoryLockKey('sub', sub);
    const orderedKeys = [emailKey, subKey].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));

    for (const lockKey of orderedKeys) {
      await this.client.$queryRaw(
        Prisma.sql`SELECT pg_advisory_xact_lock(CAST(${lockKey.toString()} AS bigint))::text AS lock_acquired`,
      );
    }
  }

  public async countActiveAdmins(): Promise<number> {
    return await this.client.user.count({
      where: {
        globalRole: 'ADMIN',
        isActive: true,
      },
    });
  }
}

function deriveIdentityAdvisoryLockKey(namespace: 'email' | 'sub', value: string): bigint {
  const digest = createHash('sha256').update(`identity:${namespace}:${value}`, 'utf8').digest();
  // Tag MSB nibble with 0x1 (email) or 0x2 (sub) so lock ranks are strictly ordered and non-negative.
  const firstByte = digest[0] ?? 0;
  digest[0] = (firstByte & 0x0f) | (namespace === 'email' ? 0x10 : 0x20);
  return digest.readBigInt64BE(0);
}
