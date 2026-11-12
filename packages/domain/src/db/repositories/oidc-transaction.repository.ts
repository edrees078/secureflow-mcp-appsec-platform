import { Prisma } from '../../generated/prisma/client.js';
import { SecureFlowError } from '@secureflow/shared';
import type {
  CreateOidcTransactionRepoData,
  IOidcTransactionRepository,
  OidcTransactionEntity,
  PrismaDbClient,
} from './types.js';

interface RawOidcTransactionRow {
  id: string;
  txn_token_hash: string;
  state_hash: string;
  nonce: string;
  code_verifier: string;
  return_to: string;
  created_at: Date;
  expires_at: Date;
  consumed_at: Date | null;
}

export class PrismaOidcTransactionRepository implements IOidcTransactionRepository {
  constructor(private readonly client: PrismaDbClient) {}

  private get delegate(): Prisma.OidcTransactionDelegate {
    if (!this.client.oidcTransaction) {
      throw new SecureFlowError(
        'PrismaClient is missing oidcTransaction delegate',
        'DATABASE_CONFIG_ERROR',
        500,
      );
    }
    return this.client.oidcTransaction;
  }

  private mapToEntity(row: {
    id: string;
    txnTokenHash: string;
    stateHash: string;
    nonce: string;
    codeVerifier: string;
    returnTo: string;
    createdAt: Date;
    expiresAt: Date;
    consumedAt: Date | null;
  }): OidcTransactionEntity {
    return {
      id: row.id,
      txnTokenHash: row.txnTokenHash,
      stateHash: row.stateHash,
      nonce: row.nonce,
      codeVerifier: row.codeVerifier,
      returnTo: row.returnTo,
      createdAt: row.createdAt,
      expiresAt: row.expiresAt,
      consumedAt: row.consumedAt,
    };
  }

  private mapRawRow(row: RawOidcTransactionRow): OidcTransactionEntity {
    return {
      id: row.id,
      txnTokenHash: row.txn_token_hash,
      stateHash: row.state_hash,
      nonce: row.nonce,
      codeVerifier: row.code_verifier,
      returnTo: row.return_to,
      createdAt: row.created_at,
      expiresAt: row.expires_at,
      consumedAt: row.consumed_at,
    };
  }

  public async create(data: CreateOidcTransactionRepoData): Promise<OidcTransactionEntity> {
    const created = await this.delegate.create({
      data: {
        txnTokenHash: data.txnTokenHash,
        stateHash: data.stateHash,
        nonce: data.nonce,
        codeVerifier: data.codeVerifier,
        returnTo: data.returnTo,
        expiresAt: data.expiresAt,
      },
    });
    return this.mapToEntity(created);
  }

  public async findByTokenHash(txnTokenHash: string): Promise<OidcTransactionEntity | null> {
    const row = await this.delegate.findUnique({
      where: { txnTokenHash },
    });
    return row ? this.mapToEntity(row) : null;
  }

  /**
   * Atomically marks an OIDC transaction as consumed in a single database statement
   * iff it exists, has not yet been consumed (`consumed_at IS NULL`), and has not expired
   * (`expires_at > now`). Under concurrent callback races with the same token, PostgreSQL
   * row locking ensures at most one caller receives the row while all others receive `null`.
   */
  public async consumeAtomically(
    txnTokenHash: string,
    now: Date = new Date(),
  ): Promise<OidcTransactionEntity | null> {
    const rows = await this.client.$queryRaw<RawOidcTransactionRow[]>(
      Prisma.sql`
        UPDATE "oidc_transactions"
        SET "consumed_at" = ${now}
        WHERE "txn_token_hash" = ${txnTokenHash}
          AND "consumed_at" IS NULL
          AND "expires_at" > ${now}
        RETURNING
          "id",
          "txn_token_hash",
          "state_hash",
          "nonce",
          "code_verifier",
          "return_to",
          "created_at",
          "expires_at",
          "consumed_at"
      `,
    );
    const row = rows[0];
    if (!row) {
      return null;
    }
    return this.mapRawRow(row);
  }

  public async deleteExpired(before: Date): Promise<number> {
    const res = await this.delegate.deleteMany({
      where: {
        expiresAt: { lte: before },
      },
    });
    return res.count;
  }
}
