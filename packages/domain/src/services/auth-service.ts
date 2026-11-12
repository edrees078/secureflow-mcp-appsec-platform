import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import {
  BootstrapInitialAdminInputSchema,
  ConsumeOidcTransactionInputSchema,
  CreateOidcTransactionInputSchema,
  DeactivateUserInputSchema,
  RecordAuthFailureInputSchema,
  ResolveSessionInputSchema,
  RevokeSessionInputSchema,
  UpdateUserGlobalRoleInputSchema,
  UuidSchema,
  VerifiedOidcIdentityInputSchema,
  type BootstrapInitialAdminInput,
  type ConsumeOidcTransactionInput,
  type CreateOidcTransactionInput,
  type DeactivateUserInput,
  type RecordAuthFailureInput,
  type ResolveSessionInput,
  type RevokeSessionInput,
  type UpdateUserGlobalRoleInput,
  type VerifiedOidcIdentityInput,
} from '@secureflow/schemas';
import {
  ConcurrencyConflictError,
  DomainValidationError,
  EntityNotFoundError,
  ForbiddenError,
  SecureFlowError,
  UnauthorizedError,
} from '@secureflow/shared';

import { ActorContext } from '../policy/actor-context.js';
import { DatabaseManager } from '../db/database-manager.js';
import type {
  AuditEventEntity,
  RepositoryContainer,
  UserAuthEntity,
  UserProfileEntity,
} from '../db/repositories/types.js';
import type {
  ConsumedOidcTransactionResult,
  CreatedOidcTransactionResult,
  EstablishedSessionResult,
  IAuthService,
  ResolvedSessionActorResult,
} from './types.js';
import { handleDatabaseConcurrencyError } from './concurrency-handler.js';
import { isAuthorizedTestPersistence } from './persistence-token.js';

const MAX_ACTIVE_SESSIONS_PER_USER = 5;
const SLIDING_IDLE_TOUCH_THRESHOLD_MS = 60_000; // 60 seconds
const DEFAULT_IDLE_TIMEOUT_MS = 30 * 60 * 1000; // 30 minutes

const SENSITIVE_AUDIT_KEYS = new Set([
  'token',
  'rawsessiontoken',
  'rawtxntoken',
  'code',
  'codeverifier',
  'code_verifier',
  'secret',
  'clientsecret',
  'client_secret',
  'accesstoken',
  'access_token',
  'idtoken',
  'id_token',
  'refreshtoken',
  'refresh_token',
  'cookie',
  'set-cookie',
  'authorization',
  'password',
]);

/**
 * Computes the 64-character lowercase hexadecimal SHA-256 digest of an opaque token.
 * Raw tokens are never persisted in PostgreSQL or written to audit logs.
 */
export function hashOpaqueToken(rawToken: string): string {
  return createHash('sha256').update(rawToken, 'utf8').digest('hex');
}

/**
 * Generates a 256-bit (32-byte) cryptographically random base64url-encoded token.
 */
export function generateOpaqueToken(byteLength = 32): string {
  return randomBytes(byteLength).toString('base64url');
}

/**
 * Computes RFC 7636 PKCE S256 code_challenge from a code_verifier.
 */
export function computePkceS256Challenge(codeVerifier: string): string {
  return createHash('sha256').update(codeVerifier, 'ascii').digest('base64url');
}

/**
 * Performs constant-time string equality comparison via SHA-256 digest comparison
 * combined with exact byte-length verification.
 */
function constantTimeEqualStrings(a: string, b: string): boolean {
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  const digestA = createHash('sha256').update(bufA).digest();
  const digestB = createHash('sha256').update(bufB).digest();
  const digestsMatch = timingSafeEqual(digestA, digestB);
  return digestsMatch && bufA.byteLength === bufB.byteLength;
}

/**
 * Strips any secret, token, code, verifier, or cookie fields from failure audit metadata.
 */
function sanitizeFailureMetadata(
  metadata: Record<string, unknown> | undefined,
): Record<string, unknown> {
  if (!metadata) {
    return {};
  }
  const clean: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(metadata)) {
    const normalized = key.toLowerCase().replace(/[^a-z0-9_]/g, '');
    if (SENSITIVE_AUDIT_KEYS.has(normalized)) {
      continue;
    }
    if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
      clean[key] = sanitizeFailureMetadata(value as Record<string, unknown>);
    } else {
      clean[key] = value;
    }
  }
  return clean;
}

function formatZodValidationError(
  err: { issues: ReadonlyArray<{ path: ReadonlyArray<PropertyKey>; message: string }> },
  messagePrefix: string,
): DomainValidationError {
  const details = err.issues
    .map((i) => `${i.path.map(String).join('.') || 'input'}: ${i.message}`)
    .join('; ');
  return new DomainValidationError(`${messagePrefix}: ${details}`, {
    issues: err.issues,
  });
}

/**
 * Authentication, Session Lifecycle, Least-Privilege Provisioning, and Bootstrap Domain Service.
 *
 * Security Invariants (Sub-Gate 4B.1):
 * 1. Opaque Token Hashing: Only SHA-256 digests of session tokens, OIDC transaction tokens,
 *    and OIDC state values are stored in PostgreSQL.
 * 2. Atomic Single-Use OIDC Transactions: `consumeOidcTransaction` uses an atomic database
 *    UPDATE ... WHERE consumed_at IS NULL AND expires_at > NOW() RETURNING ... statement so
 *    concurrent callback replays cannot both succeed.
 * 3. Strict Least-Privilege JIT Provisioning: Unknown verified OIDC identities are provisioned
 *    exclusively with `globalRole = 'DEVELOPER'` and zero `project_members` rows. Any IdP role
 *    or group claims (`realmRoles`) are ignored for authorization.
 * 4. Concurrent-Safe Admin Bootstrap: `bootstrapInitialAdmin` serializes bootstrap attempts using
 *    a transaction-scoped PostgreSQL exclusive advisory lock (`pg_advisory_xact_lock`) before
 *    checking `countActiveAdmins() === 0` and verifying `issuer` and `sub`.
 * 5. Separate Rollback-Safe Failed-Login Auditing: Failed authentication attempts roll back any
 *    domain mutations and persist `auth.login_failed` in a separate root-connection operation
 *    with `actorId: null` for unverified/unknown/conflicting identities.
 * 6. Audit-Failure Resilience: A failure in `recordAuthenticationFailure` never masks an
 *    authentication rejection or authorizes a login; a failure in `auth.login_succeeded` inside
 *    the login transaction rolls back session creation completely.
 */
export class AuthService implements IAuthService {
  private readonly db: DatabaseManager | undefined;
  private readonly directRepos: RepositoryContainer | undefined;

  public constructor(db: DatabaseManager);
  public constructor(testInit: unknown);
  public constructor(init: unknown) {
    if (!init) {
      throw new SecureFlowError(
        'AuthService initialization failed: valid DatabaseManager or test repository container required',
        'SERVICE_INITIALIZATION_ERROR',
        500,
      );
    }

    if (init instanceof DatabaseManager) {
      this.db = init;
      this.directRepos = undefined;
    } else if (isAuthorizedTestPersistence(init)) {
      const repos = init.repositories;
      if (
        !repos.userRepo ||
        !repos.auditRepo ||
        !repos.sessionRepo ||
        !repos.oidcTransactionRepo
      ) {
        throw new SecureFlowError(
          'AuthService initialization failed: incomplete repository container (userRepo, auditRepo, sessionRepo, and oidcTransactionRepo required)',
          'SERVICE_INITIALIZATION_ERROR',
          500,
        );
      }
      this.directRepos = repos;
      this.db = undefined;
    } else {
      throw new SecureFlowError(
        'Direct repository injection is prohibited outside @secureflow/domain/testing',
        'UNAUTHORIZED_PERSISTENCE_INJECTION',
        500,
      );
    }
  }

  private getRootRepos(): RepositoryContainer {
    if (this.directRepos) {
      return this.directRepos;
    }
    if (this.db) {
      return this.db.getRepositories();
    }
    throw new SecureFlowError(
      'AuthService database connection not configured',
      'DATABASE_CONFIG_ERROR',
      500,
    );
  }

  private assertAuthRepos(repos: RepositoryContainer): {
    userRepo: Required<
      Pick<
        RepositoryContainer['userRepo'],
        | 'findById'
        | 'findAuthoritativeUser'
        | 'lockUser'
        | 'lockUsers'
        | 'deactivateUser'
        | 'updateGlobalRole'
        | 'findBySub'
        | 'findByEmail'
        | 'findProfileById'
        | 'lockUserBySub'
        | 'lockUserByEmail'
        | 'createUser'
        | 'updateDisplayName'
        | 'acquireBootstrapAdvisoryLock'
        | 'countActiveAdmins'
      >
    > &
      Pick<RepositoryContainer['userRepo'], 'acquireIdentityProvisioningLocks'>;
    sessionRepo: NonNullable<RepositoryContainer['sessionRepo']>;
    oidcTransactionRepo: NonNullable<RepositoryContainer['oidcTransactionRepo']>;
    auditRepo: RepositoryContainer['auditRepo'];
  } {
    const { userRepo, sessionRepo, oidcTransactionRepo, auditRepo } = repos;
    if (
      !sessionRepo ||
      !oidcTransactionRepo ||
      !userRepo.findBySub ||
      !userRepo.findByEmail ||
      !userRepo.findProfileById ||
      !userRepo.lockUserBySub ||
      !userRepo.lockUserByEmail ||
      !userRepo.createUser ||
      !userRepo.updateDisplayName ||
      !userRepo.acquireBootstrapAdvisoryLock ||
      !userRepo.countActiveAdmins
    ) {
      throw new SecureFlowError(
        'AuthService requires full authentication repository capabilities',
        'SERVICE_INITIALIZATION_ERROR',
        500,
      );
    }

    return {
      userRepo: userRepo as Required<typeof userRepo>,
      sessionRepo,
      oidcTransactionRepo,
      auditRepo,
    };
  }

  private async executeInTransaction<T>(
    fn: (repos: RepositoryContainer) => Promise<T>,
  ): Promise<T> {
    if (this.db) {
      try {
        return await this.db.runTransaction(async (repos) => {
          return await fn(repos);
        });
      } catch (err: unknown) {
        handleDatabaseConcurrencyError(err);
      }
    }

    if (this.directRepos) {
      try {
        return await fn(this.directRepos);
      } catch (err: unknown) {
        handleDatabaseConcurrencyError(err);
      }
    }

    throw new SecureFlowError(
      'AuthService transaction execution failed: no database manager configured',
      'DATABASE_CONFIG_ERROR',
      500,
    );
  }

  /**
   * Records a failed authentication attempt (`auth.login_failed`) using the root
   * database connection outside any rolled-back transaction.
   *
   * Security Guarantees (Sections 6 & 7):
   * - `actorId` is strictly `null` unless `reason === 'USER_DEACTIVATED'` for a verified,
   *   existing `users.id` row.
   * - Sensitive keys (tokens, codes, PKCE verifiers, secrets, cookies) are stripped.
   * - Never throws if the audit write itself fails, ensuring audit errors never mask
   *   authentication rejection or authorize a login.
   */
  public async recordAuthenticationFailure(
    input: RecordAuthFailureInput,
  ): Promise<AuditEventEntity | null> {
    const parsedResult = RecordAuthFailureInputSchema.safeParse(input);
    if (!parsedResult.success) {
      return null;
    }
    const parsed = parsedResult.data;

    // FK & attribution safety: Only set actorId when the user's sub matched an existing
    // verified users.id row that is deactivated. All other failures use actorId = null.
    const safeActorId =
      parsed.reason === 'USER_DEACTIVATED' && parsed.actorId ? parsed.actorId : null;

    const safeResourceId = parsed.resourceUserId ?? null;
    const safeResourceType = safeResourceId ? 'User' : 'AuthenticationAttempt';
    const sanitizedMetadata = sanitizeFailureMetadata(parsed.metadata);

    try {
      const rootRepos = this.getRootRepos();
      return await rootRepos.auditRepo.append({
        actorId: safeActorId,
        eventCategory: 'AUTH',
        eventType: 'auth.login_failed',
        resourceId: safeResourceId,
        resourceType: safeResourceType,
        beforeState: null,
        afterState: {
          outcome: 'FAILURE',
          reason: parsed.reason,
          ...sanitizedMetadata,
        },
        ipAddress: parsed.ipAddress ?? null,
        userAgent: parsed.userAgent ?? null,
      });
    } catch {
      // Fail-closed for authentication: if the failure audit append itself fails,
      // swallow the secondary audit error so the caller still rejects the login.
      return null;
    }
  }

  /**
   * Creates a single-use OIDC authorization transaction with 256-bit CSPRNG state,
   * nonce, PKCE S256 code_verifier/code_challenge, and opaque transaction cookie token.
   * Only SHA-256 digests of the transaction token and state are stored in PostgreSQL.
   */
  public async createOidcTransaction(
    input?: CreateOidcTransactionInput,
    now: Date = new Date(),
  ): Promise<CreatedOidcTransactionResult> {
    const parsedResult = CreateOidcTransactionInputSchema.safeParse(input ?? {});
    if (!parsedResult.success) {
      throw formatZodValidationError(parsedResult.error, 'Invalid OIDC transaction parameters');
    }
    const parsed = parsedResult.data;

    const rawTxnToken = generateOpaqueToken(32);
    const state = generateOpaqueToken(32);
    const nonce = generateOpaqueToken(32);
    const codeVerifier = generateOpaqueToken(32);
    const codeChallenge = computePkceS256Challenge(codeVerifier);

    const txnTokenHash = hashOpaqueToken(rawTxnToken);
    const stateHash = hashOpaqueToken(state);
    const expiresAt = new Date(now.getTime() + parsed.ttlSeconds * 1000);

    const { oidcTransactionRepo } = this.assertAuthRepos(this.getRootRepos());
    const created = await oidcTransactionRepo.create({
      txnTokenHash,
      stateHash,
      nonce,
      codeVerifier,
      returnTo: parsed.returnTo,
      expiresAt,
    });

    return {
      id: created.id,
      rawTxnToken,
      state,
      nonce,
      codeVerifier,
      codeChallenge,
      codeChallengeMethod: 'S256',
      returnTo: created.returnTo,
      expiresAt: created.expiresAt,
    };
  }

  /**
   * Atomically consumes a single-use OIDC transaction by its raw transaction token
   * and verifies the callback `state` parameter in constant time.
   * Replay, expiration, missing transaction, or state mismatch triggers `auth.login_failed`
   * and throws `UnauthorizedError` (HTTP 401).
   */
  public async consumeOidcTransaction(
    input: ConsumeOidcTransactionInput,
    now: Date = new Date(),
  ): Promise<ConsumedOidcTransactionResult> {
    const parsedResult = ConsumeOidcTransactionInputSchema.safeParse(input);
    if (!parsedResult.success) {
      await this.recordAuthenticationFailure({
        reason: 'MISSING_OR_EXPIRED_OIDC_TRANSACTION',
        actorId: null,
        resourceUserId: null,
        ipAddress: input?.ipAddress ?? null,
        userAgent: input?.userAgent ?? null,
        metadata: { validationFailed: true },
      });
      throw new UnauthorizedError('Invalid or missing OIDC transaction parameters');
    }
    const parsed = parsedResult.data;

    const txnTokenHash = hashOpaqueToken(parsed.rawTxnToken);
    const { oidcTransactionRepo } = this.assertAuthRepos(this.getRootRepos());

    const consumed = await oidcTransactionRepo.consumeAtomically(txnTokenHash, now);
    if (!consumed) {
      await this.recordAuthenticationFailure({
        reason: 'MISSING_OR_EXPIRED_OIDC_TRANSACTION',
        actorId: null,
        resourceUserId: null,
        ipAddress: parsed.ipAddress ?? null,
        userAgent: parsed.userAgent ?? null,
        metadata: {},
      });
      throw new UnauthorizedError('Invalid, expired, or already-consumed OIDC transaction');
    }

    const candidateStateHash = hashOpaqueToken(parsed.state);
    if (!constantTimeEqualStrings(candidateStateHash, consumed.stateHash)) {
      await this.recordAuthenticationFailure({
        reason: 'OIDC_STATE_MISMATCH',
        actorId: null,
        resourceUserId: null,
        ipAddress: parsed.ipAddress ?? null,
        userAgent: parsed.userAgent ?? null,
        metadata: { oidcTransactionId: consumed.id },
      });
      throw new UnauthorizedError('OIDC state parameter mismatch');
    }

    return {
      id: consumed.id,
      nonce: consumed.nonce,
      codeVerifier: consumed.codeVerifier,
      returnTo: consumed.returnTo,
      consumedAt: consumed.consumedAt ?? now,
    };
  }

  /**
   * Establishes an authenticated server-managed session for a verified OIDC identity.
   *
   * Security Invariants:
   * - Requires `emailVerified === true` (fails closed with 403 and `auth.login_failed` otherwise).
   * - Locks user records under `FOR UPDATE` inside a PostgreSQL transaction.
   * - Rejects email-to-sub account conflicts (`EMAIL_SUB_CONFLICT` -> 403) without auto-linking.
   * - Rejects deactivated users (`USER_DEACTIVATED` -> 403).
   * - Provisions unknown verified users strictly as `DEVELOPER` with zero project memberships,
   *   ignoring any `realmRoles` claims from Keycloak.
   * - Stores only the SHA-256 digest of the 256-bit opaque session token.
   * - Atomically writes `auth.login_succeeded` in the same transaction; if audit write fails,
   *   rolls back user/session creation completely.
   */
  public async establishAuthenticatedSession(
    input: VerifiedOidcIdentityInput,
    now: Date = new Date(),
  ): Promise<EstablishedSessionResult> {
    const parsedResult = VerifiedOidcIdentityInputSchema.safeParse(input);
    if (!parsedResult.success) {
      throw formatZodValidationError(parsedResult.error, 'Invalid OIDC identity input');
    }
    const parsed = parsedResult.data;

    if (!parsed.emailVerified) {
      await this.recordAuthenticationFailure({
        reason: 'EMAIL_NOT_VERIFIED',
        actorId: null,
        resourceUserId: null,
        ipAddress: parsed.ipAddress ?? null,
        userAgent: parsed.userAgent ?? null,
        metadata: { emailVerified: false },
      });
      throw new ForbiddenError('Verified email claim is required for authentication');
    }

    const normalizedEmail = parsed.email.toLowerCase();
    const resolvedDisplayName =
      parsed.displayName ?? normalizedEmail.split('@')[0] ?? 'SecureFlow User';

    try {
      return await this.executeEstablishAuthenticatedSessionAttempt(
        parsed,
        normalizedEmail,
        resolvedDisplayName,
        now,
      );
    } catch (err: unknown) {
      if (isUniqueConstraintViolationError(err)) {
        return await this.recoverFromEstablishSessionUniqueConflict(
          parsed,
          normalizedEmail,
          resolvedDisplayName,
          now,
        );
      }
      throw err;
    }
  }

  private async executeEstablishAuthenticatedSessionAttempt(
    parsed: VerifiedOidcIdentityInput,
    normalizedEmail: string,
    resolvedDisplayName: string,
    now: Date,
  ): Promise<EstablishedSessionResult> {
    let pendingFailureAudit: RecordAuthFailureInput | undefined;

    try {
      return await this.executeInTransaction(async (repos) => {
        const { userRepo, sessionRepo, auditRepo } = this.assertAuthRepos(repos);

        // Acquire canonical transaction-scoped PostgreSQL advisory locks (email -> sub)
        // before locking rows under FOR UPDATE so concurrent first-logins cannot phantom-read.
        await userRepo.acquireIdentityProvisioningLocks?.(parsed.sub, normalizedEmail);

        // Lock candidate user rows by sub and email under FOR UPDATE
        const subUser = await userRepo.lockUserBySub(parsed.sub, 'UPDATE');
        const emailUser = await userRepo.lockUserByEmail(normalizedEmail, 'UPDATE');

        let user: UserProfileEntity;
        let jitProvisioned = false;

        if (subUser) {
          if (emailUser && emailUser.id !== subUser.id) {
            pendingFailureAudit = {
              reason: 'EMAIL_SUB_CONFLICT',
              actorId: null,
              resourceUserId: emailUser.id,
              ipAddress: parsed.ipAddress ?? null,
              userAgent: parsed.userAgent ?? null,
              metadata: { conflictType: 'EMAIL_OWNED_BY_DIFFERENT_SUB' },
            };
            throw new ForbiddenError(
              'Email address is already associated with a different identity subject',
            );
          }

          if (!subUser.isActive) {
            pendingFailureAudit = {
              reason: 'USER_DEACTIVATED',
              actorId: subUser.id,
              resourceUserId: subUser.id,
              ipAddress: parsed.ipAddress ?? null,
              userAgent: parsed.userAgent ?? null,
              metadata: { userId: subUser.id },
            };
            throw new ForbiddenError('User account is deactivated');
          }

          user = subUser;
        } else if (emailUser) {
          // Strict account-linking conflict prevention: never auto-link an existing email
          // to a different OIDC subject.
          pendingFailureAudit = {
            reason: 'EMAIL_SUB_CONFLICT',
            actorId: null,
            resourceUserId: emailUser.id,
            ipAddress: parsed.ipAddress ?? null,
            userAgent: parsed.userAgent ?? null,
            metadata: { conflictType: 'UNRECOGNIZED_SUB_FOR_EXISTING_EMAIL' },
          };
          throw new ForbiddenError(
            'Email address is already associated with a different identity subject',
          );
        } else {
          // Strict Least-Privilege JIT Provisioning (Section 8):
          // Unknown verified users are provisioned exclusively with globalRole = 'DEVELOPER'
          // and zero project memberships. Any IdP realmRoles claims are ignored.
          user = await userRepo.createUser({
            sub: parsed.sub,
            email: normalizedEmail,
            displayName: resolvedDisplayName,
            globalRole: 'DEVELOPER',
            isActive: true,
          });
          jitProvisioned = true;

          await auditRepo.append({
            actorId: user.id,
            eventCategory: 'AUTH',
            eventType: 'auth.user_jit_provisioned',
            resourceId: user.id,
            resourceType: 'User',
            beforeState: null,
            afterState: {
              userId: user.id,
              globalRole: user.globalRole,
              isActive: user.isActive,
              projectMembershipsCount: 0,
              ignoredIdpRoleClaimsCount: parsed.realmRoles?.length ?? 0,
            },
            ipAddress: parsed.ipAddress ?? null,
            userAgent: parsed.userAgent ?? null,
          });
        }

        // Enforce maximum concurrent active sessions per user (oldest evicted first)
        const activeSessions = await sessionRepo.listActiveByUserId(user.id, now);
        if (activeSessions.length >= MAX_ACTIVE_SESSIONS_PER_USER) {
          const sessionsToEvict = activeSessions.slice(
            0,
            activeSessions.length - MAX_ACTIVE_SESSIONS_PER_USER + 1,
          );
          for (const oldSession of sessionsToEvict) {
            await sessionRepo.revokeById(
              oldSession.id,
              'MAX_CONCURRENT_SESSIONS_EXCEEDED',
              now,
            );
          }
        }

        const rawSessionToken = generateOpaqueToken(32);
        const tokenHash = hashOpaqueToken(rawSessionToken);
        const idleExpiresAt = new Date(now.getTime() + parsed.idleTimeoutSeconds * 1000);
        const expiresAt = new Date(now.getTime() + parsed.absoluteTimeoutSeconds * 1000);

        const session = await sessionRepo.create({
          userId: user.id,
          tokenHash,
          oidcSid: parsed.oidcSid ?? null,
          ipAddress: parsed.ipAddress ?? null,
          userAgent: parsed.userAgent ?? null,
          lastActivityAt: now,
          idleExpiresAt,
          expiresAt,
        });

        await auditRepo.append({
          actorId: user.id,
          eventCategory: 'AUTH',
          eventType: 'auth.login_succeeded',
          resourceId: session.id,
          resourceType: 'UserSession',
          beforeState: null,
          afterState: {
            userId: user.id,
            sessionId: session.id,
            globalRole: user.globalRole,
            jitProvisioned,
            oidcSid: session.oidcSid,
            idleExpiresAt: session.idleExpiresAt.toISOString(),
            expiresAt: session.expiresAt.toISOString(),
          },
          ipAddress: parsed.ipAddress ?? null,
          userAgent: parsed.userAgent ?? null,
        });

        const authoritativeUser = await userRepo.findAuthoritativeUser(user.id);
        const actor = new ActorContext({
          id: user.id,
          globalRole: authoritativeUser?.globalRole ?? user.globalRole,
          isActive: user.isActive,
          memberships: authoritativeUser?.memberships ?? [],
        });

        return {
          rawSessionToken,
          session,
          user,
          actor,
          jitProvisioned,
        };
      });
    } catch (err: unknown) {
      if (pendingFailureAudit) {
        await this.recordAuthenticationFailure(pendingFailureAudit);
      }
      throw err;
    }
  }

  private async throwIfEmailSubUniqueConflict(
    sub: string,
    normalizedEmail: string,
    conflictType: string,
    message: string,
    ipAddress: string | null | undefined,
    userAgent: string | null | undefined,
  ): Promise<void> {
    const rootUserRepo = this.getRootRepos().userRepo;
    const existingByEmail = await rootUserRepo.findByEmail?.(normalizedEmail);
    if (existingByEmail && existingByEmail.sub !== sub) {
      await this.recordAuthenticationFailure({
        reason: 'EMAIL_SUB_CONFLICT',
        actorId: null,
        resourceUserId: existingByEmail.id,
        ipAddress: ipAddress ?? null,
        userAgent: userAgent ?? null,
        metadata: { conflictType },
      });
      throw new ForbiddenError(message);
    }
  }

  private async recoverFromEstablishSessionUniqueConflict(
    parsed: VerifiedOidcIdentityInput,
    normalizedEmail: string,
    resolvedDisplayName: string,
    now: Date,
  ): Promise<EstablishedSessionResult> {
    await this.throwIfEmailSubUniqueConflict(
      parsed.sub,
      normalizedEmail,
      'CONCURRENT_EMAIL_SUB_CONFLICT',
      'Email address is already associated with a different identity subject',
      parsed.ipAddress,
      parsed.userAgent,
    );

    const rootUserRepo = this.getRootRepos().userRepo;
    const existingBySub = await rootUserRepo.findBySub?.(parsed.sub);
    if (existingBySub) {
      try {
        return await this.executeEstablishAuthenticatedSessionAttempt(
          parsed,
          normalizedEmail,
          resolvedDisplayName,
          now,
        );
      } catch (retryErr: unknown) {
        if (isUniqueConstraintViolationError(retryErr)) {
          await this.throwIfEmailSubUniqueConflict(
            parsed.sub,
            normalizedEmail,
            'CONCURRENT_EMAIL_SUB_CONFLICT',
            'Email address is already associated with a different identity subject',
            parsed.ipAddress,
            parsed.userAgent,
          );
          throw new ConcurrencyConflictError(
            'Concurrent authentication provisioning conflict, please retry',
          );
        }
        throw retryErr;
      }
    }

    throw new ConcurrencyConflictError(
      'Concurrent authentication provisioning conflict, please retry',
    );
  }

  /**
   * Resolves a raw opaque session token into a fresh, PostgreSQL-authoritative ActorContext.
   * Enforces revocation status, absolute expiration, sliding idle expiration, and live user
   * active status / role / project memberships.
   */
  public async resolveSessionActor(
    input: ResolveSessionInput,
    now: Date = new Date(),
  ): Promise<ResolvedSessionActorResult> {
    const parsedResult = ResolveSessionInputSchema.safeParse(input);
    if (!parsedResult.success) {
      throw new UnauthorizedError('Invalid or missing session token');
    }
    const parsed = parsedResult.data;

    const tokenHash = hashOpaqueToken(parsed.rawSessionToken);
    const { userRepo, sessionRepo } = this.assertAuthRepos(this.getRootRepos());

    let session = await sessionRepo.findByTokenHash(tokenHash);
    if (!session || session.revokedAt !== null) {
      throw new UnauthorizedError('Invalid or revoked session');
    }

    if (session.expiresAt.getTime() <= now.getTime()) {
      await sessionRepo.revokeById(session.id, 'ABSOLUTE_TIMEOUT_EXPIRED', now);
      throw new UnauthorizedError('Session has expired');
    }

    if (session.idleExpiresAt.getTime() <= now.getTime()) {
      await sessionRepo.revokeById(session.id, 'IDLE_TIMEOUT_EXPIRED', now);
      throw new UnauthorizedError('Session idle timeout exceeded');
    }

    const authoritativeUser = await userRepo.findAuthoritativeUser(session.userId);
    if (!authoritativeUser) {
      await sessionRepo.revokeById(session.id, 'USER_NOT_FOUND', now);
      throw new UnauthorizedError('Session user no longer exists');
    }

    if (!authoritativeUser.isActive) {
      await sessionRepo.revokeAllActiveForUser(authoritativeUser.id, 'USER_DEACTIVATED', now);
      throw new ForbiddenError('User account is deactivated');
    }

    // Sliding idle window update (debounced to >= 60s elapsed since lastActivityAt)
    const elapsedSinceLastActivityMs = now.getTime() - session.lastActivityAt.getTime();
    if (elapsedSinceLastActivityMs >= SLIDING_IDLE_TOUCH_THRESHOLD_MS) {
      const configuredIdleWindowMs = Math.max(
        DEFAULT_IDLE_TIMEOUT_MS,
        session.idleExpiresAt.getTime() - session.lastActivityAt.getTime(),
      );
      const nextIdleExpiresAt = new Date(
        Math.min(session.expiresAt.getTime(), now.getTime() + configuredIdleWindowMs),
      );
      session = await sessionRepo.touchActivity(session.id, now, nextIdleExpiresAt);
    }

    const actor = new ActorContext({
      id: authoritativeUser.id,
      globalRole: authoritativeUser.globalRole,
      isActive: authoritativeUser.isActive,
      memberships: authoritativeUser.memberships,
    });

    return {
      actor,
      session,
    };
  }

  /**
   * Revokes a single session by its raw opaque token (e.g. during logout) and appends
   * an atomic `auth.logout` audit event.
   */
  public async revokeSession(
    input: RevokeSessionInput,
    now: Date = new Date(),
  ): Promise<boolean> {
    const parsedResult = RevokeSessionInputSchema.safeParse(input);
    if (!parsedResult.success) {
      return false;
    }
    const parsed = parsedResult.data;
    const tokenHash = hashOpaqueToken(parsed.rawSessionToken);

    return await this.executeInTransaction(async (repos) => {
      const { sessionRepo, auditRepo } = this.assertAuthRepos(repos);
      const existing = await sessionRepo.findByTokenHash(tokenHash);
      if (!existing || existing.revokedAt !== null) {
        return false;
      }

      const revoked = await sessionRepo.revokeById(existing.id, parsed.reason, now);
      if (revoked) {
        await auditRepo.append({
          actorId: existing.userId,
          eventCategory: 'AUTH',
          eventType: 'auth.logout',
          resourceId: existing.id,
          resourceType: 'UserSession',
          beforeState: {
            revokedAt: null,
          },
          afterState: {
            revokedAt: now.toISOString(),
            revocationReason: parsed.reason,
          },
          ipAddress: parsed.ipAddress ?? null,
          userAgent: parsed.userAgent ?? null,
        });
      }
      return revoked;
    });
  }

  /**
   * Revokes all active sessions for a target user. Permitted for the user themselves
   * or an active Global Admin.
   */
  public async revokeAllUserSessions(
    actor: ActorContext,
    targetUserId: string,
    reason = 'USER_SESSIONS_REVOKED',
    now: Date = new Date(),
  ): Promise<number> {
    const targetIdParse = UuidSchema.safeParse(targetUserId);
    if (!targetIdParse.success) {
      throw new DomainValidationError('Invalid targetUserId UUID format');
    }

    return await this.executeInTransaction(async (repos) => {
      const { userRepo, sessionRepo, auditRepo } = this.assertAuthRepos(repos);

      const lockedUsers = await userRepo.lockUsers([actor.id, targetIdParse.data], 'UPDATE');
      const freshActor = lockedUsers.get(actor.id);
      if (!freshActor) {
        throw new UnauthorizedError('Actor account not found');
      }
      if (!freshActor.isActive) {
        throw new ForbiddenError('Actor account is deactivated');
      }
      if (freshActor.id !== targetIdParse.data && freshActor.globalRole !== 'ADMIN') {
        throw new ForbiddenError(
          'Only a Global Admin or the account owner may revoke all user sessions',
        );
      }

      const targetUser = lockedUsers.get(targetIdParse.data);
      if (!targetUser) {
        throw new EntityNotFoundError('Target user not found');
      }

      const revokedCount = await sessionRepo.revokeAllActiveForUser(
        targetUser.id,
        reason,
        now,
      );

      await auditRepo.append({
        actorId: freshActor.id,
        eventCategory: 'AUTH',
        eventType: 'auth.sessions_revoked',
        resourceId: targetUser.id,
        resourceType: 'User',
        beforeState: null,
        afterState: {
          targetUserId: targetUser.id,
          revokedSessionCount: revokedCount,
          reason,
        },
        ipAddress: null,
        userAgent: null,
      });

      return revokedCount;
    });
  }

  /**
   * Revokes active sessions matching an OIDC `sid` claim (for back-channel logout support).
   */
  public async revokeSessionsByOidcSid(
    oidcSid: string,
    reason = 'OIDC_BACKCHANNEL_LOGOUT',
    now: Date = new Date(),
  ): Promise<number> {
    const trimmedSid = oidcSid.trim();
    if (!trimmedSid) {
      throw new DomainValidationError('oidcSid cannot be empty');
    }
    const { sessionRepo } = this.assertAuthRepos(this.getRootRepos());
    return await sessionRepo.revokeActiveByOidcSid(trimmedSid, reason, now);
  }

  /**
   * Concurrent-safe initial Global Admin bootstrap (Section 5).
   *
   * Acquires a transaction-scoped exclusive PostgreSQL advisory lock
   * (`SELECT pg_advisory_xact_lock(2147483001, 4001)`) before checking whether any
   * active Global Admin exists, verifying `issuer === expectedIssuer` and `sub === expectedSub`,
   * provisioning/promoting the initial Admin, and writing an atomic `auth.admin_bootstrapped`
   * audit event.
   */
  public async bootstrapInitialAdmin(
    input: BootstrapInitialAdminInput,
    now: Date = new Date(),
  ): Promise<UserProfileEntity> {
    const parsedResult = BootstrapInitialAdminInputSchema.safeParse(input);
    if (!parsedResult.success) {
      throw formatZodValidationError(parsedResult.error, 'Invalid bootstrap input');
    }
    const parsed = parsedResult.data;

    const issuerMatches = constantTimeEqualStrings(parsed.issuer, parsed.expectedIssuer);
    const subMatches = constantTimeEqualStrings(parsed.sub, parsed.expectedSub);

    if (!issuerMatches || !subMatches) {
      await this.recordAuthenticationFailure({
        reason: 'INVALID_BOOTSTRAP_CREDENTIALS',
        actorId: null,
        resourceUserId: null,
        ipAddress: parsed.ipAddress ?? null,
        userAgent: parsed.userAgent ?? null,
        metadata: {
          issuerMatched: issuerMatches,
          subMatched: subMatches,
        },
      });
      throw new ForbiddenError(
        'Bootstrap identity does not match configured initial Admin subject or issuer',
      );
    }

    const normalizedEmail = parsed.email.toLowerCase();
    const resolvedDisplayName =
      parsed.displayName ?? normalizedEmail.split('@')[0] ?? 'Initial Admin';

    let pendingFailureAudit: RecordAuthFailureInput | undefined;

    try {
      return await this.executeInTransaction(async (repos) => {
        const { userRepo, auditRepo } = this.assertAuthRepos(repos);

        // Step 1: Acquire transaction-scoped exclusive PostgreSQL advisory lock.
        // Concurrent bootstrap transactions block here until this transaction commits or rolls back.
        await userRepo.acquireBootstrapAdvisoryLock();

        // Step 2: Check whether any active Global Admin already exists under the advisory lock.
        const activeAdminCount = await userRepo.countActiveAdmins();
        if (activeAdminCount > 0) {
          pendingFailureAudit = {
            reason: 'INITIAL_ADMIN_ALREADY_EXISTS',
            actorId: null,
            resourceUserId: null,
            ipAddress: parsed.ipAddress ?? null,
            userAgent: parsed.userAgent ?? null,
            metadata: { activeAdminCount },
          };
          throw new ConcurrencyConflictError(
            'Initial Global Admin has already been bootstrapped',
          );
        }

        // Step 2b: Acquire canonical identity locks before reading/creating the admin user row.
        await userRepo.acquireIdentityProvisioningLocks?.(parsed.sub, normalizedEmail);

        // Step 3: Lock candidate user rows by sub and email
        const subUser = await userRepo.lockUserBySub(parsed.sub, 'UPDATE');
        const emailUser = await userRepo.lockUserByEmail(normalizedEmail, 'UPDATE');

        let bootstrappedUser: UserProfileEntity;
        let previousRole: string | null = null;

        if (subUser) {
          if (emailUser && emailUser.id !== subUser.id) {
            pendingFailureAudit = {
              reason: 'EMAIL_SUB_CONFLICT',
              actorId: null,
              resourceUserId: emailUser.id,
              ipAddress: parsed.ipAddress ?? null,
              userAgent: parsed.userAgent ?? null,
              metadata: { conflictType: 'BOOTSTRAP_EMAIL_CONFLICT' },
            };
            throw new ForbiddenError(
              'Bootstrap email address is already associated with a different identity subject',
            );
          }

          if (!subUser.isActive) {
            pendingFailureAudit = {
              reason: 'USER_DEACTIVATED',
              actorId: subUser.id,
              resourceUserId: subUser.id,
              ipAddress: parsed.ipAddress ?? null,
              userAgent: parsed.userAgent ?? null,
              metadata: { userId: subUser.id },
            };
            throw new ForbiddenError('Cannot bootstrap a deactivated user account');
          }

          previousRole = subUser.globalRole;
          await userRepo.updateGlobalRole(subUser.id, 'ADMIN');
          const reloaded = await userRepo.findProfileById(subUser.id);
          if (!reloaded) {
            throw new EntityNotFoundError('Bootstrapped user profile not found');
          }
          bootstrappedUser = reloaded;
        } else if (emailUser) {
          pendingFailureAudit = {
            reason: 'EMAIL_SUB_CONFLICT',
            actorId: null,
            resourceUserId: emailUser.id,
            ipAddress: parsed.ipAddress ?? null,
            userAgent: parsed.userAgent ?? null,
            metadata: { conflictType: 'BOOTSTRAP_EMAIL_CONFLICT' },
          };
          throw new ForbiddenError(
            'Bootstrap email address is already associated with a different identity subject',
          );
        } else {
          bootstrappedUser = await userRepo.createUser({
            sub: parsed.sub,
            email: normalizedEmail,
            displayName: resolvedDisplayName,
            globalRole: 'ADMIN',
            isActive: true,
          });
        }

        // Step 4: Append atomic bootstrap audit event
        await auditRepo.append({
          actorId: bootstrappedUser.id,
          eventCategory: 'AUTH',
          eventType: 'auth.admin_bootstrapped',
          resourceId: bootstrappedUser.id,
          resourceType: 'User',
          beforeState: previousRole ? { globalRole: previousRole } : null,
          afterState: {
            userId: bootstrappedUser.id,
            sub: bootstrappedUser.sub,
            email: bootstrappedUser.email,
            globalRole: 'ADMIN',
            issuer: parsed.issuer,
            justification: parsed.justification,
            bootstrappedAt: now.toISOString(),
          },
          ipAddress: parsed.ipAddress ?? null,
          userAgent: parsed.userAgent ?? null,
        });

        return bootstrappedUser;
      });
    } catch (err: unknown) {
      if (pendingFailureAudit) {
        await this.recordAuthenticationFailure(pendingFailureAudit);
      }
      if (isUniqueConstraintViolationError(err)) {
        await this.throwIfEmailSubUniqueConflict(
          parsed.sub,
          normalizedEmail,
          'CONCURRENT_BOOTSTRAP_EMAIL_CONFLICT',
          'Bootstrap email address is already associated with a different identity subject',
          parsed.ipAddress,
          parsed.userAgent,
        );
        throw new ConcurrencyConflictError(
          'Concurrent admin bootstrap conflict, please retry',
        );
      }
      throw err;
    }
  }

  /**
   * Updates a user's GlobalRole (Admin-only), revoking all active sessions for the target
   * user so new permissions take effect cleanly and writing an atomic audit event.
   */
  public async updateUserGlobalRole(
    actor: ActorContext,
    targetUserId: string,
    input: UpdateUserGlobalRoleInput,
    now: Date = new Date(),
  ): Promise<UserAuthEntity> {
    const targetIdParse = UuidSchema.safeParse(targetUserId);
    if (!targetIdParse.success) {
      throw new DomainValidationError('Invalid targetUserId UUID format');
    }
    const parsedResult = UpdateUserGlobalRoleInputSchema.safeParse(input);
    if (!parsedResult.success) {
      throw formatZodValidationError(parsedResult.error, 'Invalid global role update input');
    }
    const parsed = parsedResult.data;

    return await this.executeInTransaction(async (repos) => {
      const { userRepo, sessionRepo, auditRepo } = this.assertAuthRepos(repos);

      // Level 0 lock in ascending lexical UUID order
      const lockedUsers = await userRepo.lockUsers([actor.id, targetIdParse.data], 'UPDATE');
      const freshActor = lockedUsers.get(actor.id);
      if (!freshActor) {
        throw new UnauthorizedError('Actor account not found');
      }
      if (!freshActor.isActive) {
        throw new ForbiddenError('Actor account is deactivated');
      }
      if (freshActor.globalRole !== 'ADMIN') {
        throw new ForbiddenError('Only Global Admins can update user global roles');
      }

      const targetUser = lockedUsers.get(targetIdParse.data);
      if (!targetUser) {
        throw new EntityNotFoundError('Target user not found');
      }

      if (
        targetUser.globalRole === 'ADMIN' &&
        parsed.globalRole !== 'ADMIN' &&
        targetUser.isActive
      ) {
        const activeAdmins = await userRepo.countActiveAdmins();
        if (activeAdmins <= 1) {
          throw new DomainValidationError('Cannot demote the last active Global Admin');
        }
      }

      const updatedUser = await userRepo.updateGlobalRole(targetUser.id, parsed.globalRole);
      const revokedSessionCount = await sessionRepo.revokeAllActiveForUser(
        targetUser.id,
        'GLOBAL_ROLE_CHANGED',
        now,
      );

      await auditRepo.append({
        actorId: freshActor.id,
        eventCategory: 'AUTH',
        eventType: 'auth.user_global_role_updated',
        resourceId: targetUser.id,
        resourceType: 'User',
        beforeState: {
          globalRole: targetUser.globalRole,
        },
        afterState: {
          globalRole: updatedUser.globalRole,
          justification: parsed.justification,
          revokedSessionCount,
        },
        ipAddress: parsed.ipAddress ?? null,
        userAgent: parsed.userAgent ?? null,
      });

      return updatedUser;
    });
  }

  /**
   * Deactivates a user account (Admin-only), immediately revoking all active sessions
   * for the deactivated user and writing an atomic audit event.
   */
  public async deactivateUser(
    actor: ActorContext,
    targetUserId: string,
    input: DeactivateUserInput,
    now: Date = new Date(),
  ): Promise<UserAuthEntity> {
    const targetIdParse = UuidSchema.safeParse(targetUserId);
    if (!targetIdParse.success) {
      throw new DomainValidationError('Invalid targetUserId UUID format');
    }
    const parsedResult = DeactivateUserInputSchema.safeParse(input);
    if (!parsedResult.success) {
      throw formatZodValidationError(parsedResult.error, 'Invalid user deactivation input');
    }
    const parsed = parsedResult.data;

    return await this.executeInTransaction(async (repos) => {
      const { userRepo, sessionRepo, auditRepo } = this.assertAuthRepos(repos);

      // Level 0 lock in ascending lexical UUID order
      const lockedUsers = await userRepo.lockUsers([actor.id, targetIdParse.data], 'UPDATE');
      const freshActor = lockedUsers.get(actor.id);
      if (!freshActor) {
        throw new UnauthorizedError('Actor account not found');
      }
      if (!freshActor.isActive) {
        throw new ForbiddenError('Actor account is deactivated');
      }
      if (freshActor.globalRole !== 'ADMIN') {
        throw new ForbiddenError('Only Global Admins can deactivate user accounts');
      }

      const targetUser = lockedUsers.get(targetIdParse.data);
      if (!targetUser) {
        throw new EntityNotFoundError('Target user not found');
      }

      if (targetUser.globalRole === 'ADMIN' && targetUser.isActive) {
        const activeAdmins = await userRepo.countActiveAdmins();
        if (activeAdmins <= 1) {
          throw new DomainValidationError('Cannot deactivate the last active Global Admin');
        }
      }

      const updatedUser = await userRepo.deactivateUser(targetUser.id);
      const revokedSessionCount = await sessionRepo.revokeAllActiveForUser(
        targetUser.id,
        'USER_DEACTIVATED',
        now,
      );

      await auditRepo.append({
        actorId: freshActor.id,
        eventCategory: 'AUTH',
        eventType: 'auth.user_deactivated',
        resourceId: targetUser.id,
        resourceType: 'User',
        beforeState: {
          isActive: targetUser.isActive,
        },
        afterState: {
          isActive: updatedUser.isActive,
          justification: parsed.justification,
          revokedSessionCount,
        },
        ipAddress: parsed.ipAddress ?? null,
        userAgent: parsed.userAgent ?? null,
      });

      return updatedUser;
    });
  }
}

function isUniqueConstraintViolationError(err: unknown): boolean {
  if (err instanceof SecureFlowError && err.code === 'UNIQUE_CONSTRAINT_VIOLATION') {
    return true;
  }
  if (typeof err === 'object' && err !== null) {
    const record = err as { code?: unknown; cause?: { code?: unknown } };
    if (record.code === 'P2002' || record.code === '23505') {
      return true;
    }
    if (record.cause && (record.cause.code === 'P2002' || record.cause.code === '23505')) {
      return true;
    }
  }
  return false;
}
