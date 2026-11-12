import { randomBytes } from 'node:crypto';
import { SecureFlowError } from '@secureflow/shared';
import type { Prisma } from '../../generated/prisma/client.js';
import type {
  CreateUserSessionRepoData,
  ISessionRepository,
  PrismaDbClient,
  UserSessionEntity,
} from './types.js';

export class PrismaSessionRepository implements ISessionRepository {
  constructor(private readonly client: PrismaDbClient) {}

  private get delegate(): Prisma.UserSessionDelegate {
    if (!this.client.userSession) {
      throw new SecureFlowError(
        'PrismaClient is missing userSession delegate',
        'DATABASE_CONFIG_ERROR',
        500,
      );
    }
    return this.client.userSession;
  }

  private mapToEntity(row: {
    id: string;
    userId: string;
    sessionTokenHash: string;
    csrfToken: string;
    oidcSid: string | null;
    ipAddress: string | null;
    userAgent: string | null;
    createdAt: Date;
    lastActiveAt: Date;
    idleExpiresAt: Date;
    expiresAt: Date;
    revokedAt: Date | null;
    revokeReason: string | null;
  }): UserSessionEntity {
    return {
      id: row.id,
      userId: row.userId,
      tokenHash: row.sessionTokenHash,
      csrfToken: row.csrfToken,
      oidcSid: row.oidcSid,
      ipAddress: row.ipAddress,
      userAgent: row.userAgent,
      createdAt: row.createdAt,
      lastActivityAt: row.lastActiveAt,
      idleExpiresAt: row.idleExpiresAt,
      expiresAt: row.expiresAt,
      revokedAt: row.revokedAt,
      revocationReason: row.revokeReason,
    };
  }

  public async create(data: CreateUserSessionRepoData): Promise<UserSessionEntity> {
    const created = await this.delegate.create({
      data: {
        userId: data.userId,
        sessionTokenHash: data.tokenHash,
        csrfToken: data.csrfToken ?? randomBytes(32).toString('base64url'),
        oidcSid: data.oidcSid ?? null,
        ipAddress: data.ipAddress ?? null,
        userAgent: data.userAgent ?? null,
        lastActiveAt: data.lastActivityAt,
        idleExpiresAt: data.idleExpiresAt,
        expiresAt: data.expiresAt,
      },
    });
    return this.mapToEntity(created);
  }

  public async findByTokenHash(tokenHash: string): Promise<UserSessionEntity | null> {
    const row = await this.delegate.findUnique({
      where: { sessionTokenHash: tokenHash },
    });
    return row ? this.mapToEntity(row) : null;
  }

  public async findById(id: string): Promise<UserSessionEntity | null> {
    const row = await this.delegate.findUnique({
      where: { id },
    });
    return row ? this.mapToEntity(row) : null;
  }

  public async listActiveByUserId(
    userId: string,
    now: Date = new Date(),
  ): Promise<UserSessionEntity[]> {
    const rows = await this.delegate.findMany({
      where: {
        userId,
        revokedAt: null,
        expiresAt: { gt: now },
        idleExpiresAt: { gt: now },
      },
      orderBy: {
        createdAt: 'asc',
      },
    });
    return rows.map((r) => this.mapToEntity(r));
  }

  public async touchActivity(
    id: string,
    lastActivityAt: Date,
    idleExpiresAt: Date,
  ): Promise<UserSessionEntity> {
    const updated = await this.delegate.update({
      where: { id },
      data: {
        lastActiveAt: lastActivityAt,
        idleExpiresAt,
      },
    });
    return this.mapToEntity(updated);
  }

  public async revokeById(
    id: string,
    reason: string,
    revokedAt: Date = new Date(),
  ): Promise<boolean> {
    const res = await this.delegate.updateMany({
      where: {
        id,
        revokedAt: null,
      },
      data: {
        revokedAt,
        revokeReason: reason,
      },
    });
    return res.count > 0;
  }

  public async revokeByTokenHash(
    tokenHash: string,
    reason: string,
    revokedAt: Date = new Date(),
  ): Promise<UserSessionEntity | null> {
    const existing = await this.delegate.findUnique({
      where: { sessionTokenHash: tokenHash },
    });
    if (!existing) {
      return null;
    }
    if (existing.revokedAt !== null) {
      return this.mapToEntity(existing);
    }
    const res = await this.delegate.updateMany({
      where: {
        id: existing.id,
        revokedAt: null,
      },
      data: {
        revokedAt,
        revokeReason: reason,
      },
    });
    if (res.count === 0) {
      const reloaded = await this.delegate.findUnique({ where: { id: existing.id } });
      return reloaded ? this.mapToEntity(reloaded) : null;
    }
    return this.mapToEntity({
      ...existing,
      revokedAt,
      revokeReason: reason,
    });
  }

  public async revokeAllActiveForUser(
    userId: string,
    reason: string,
    revokedAt: Date = new Date(),
  ): Promise<number> {
    const res = await this.delegate.updateMany({
      where: {
        userId,
        revokedAt: null,
      },
      data: {
        revokedAt,
        revokeReason: reason,
      },
    });
    return res.count;
  }

  public async revokeActiveByOidcSid(
    oidcSid: string,
    reason: string,
    revokedAt: Date = new Date(),
  ): Promise<number> {
    const res = await this.delegate.updateMany({
      where: {
        oidcSid,
        revokedAt: null,
      },
      data: {
        revokedAt,
        revokeReason: reason,
      },
    });
    return res.count;
  }
}
