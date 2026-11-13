import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  AuthService,
  hashOpaqueToken,
  generateOpaqueToken,
  computePkceS256Challenge,
  type IUserRepository,
  type ISessionRepository,
  type IOidcTransactionRepository,
  type IAuditRepository,
  type IProjectRepository,
  type IFindingRepository,
  type ITaskRepository,
  type UserProfileEntity,
  type UserSessionEntity,
  type OidcTransactionEntity,
  type AuditEventEntity,
} from '../../src/index.js';
import {
  createTestAuthService,
  createTestAdminActor,
  createTestDeveloperActor,
  type RepositoryContainer,
} from '../../src/testing/index.js';
import {
  ConcurrencyConflictError,
  DomainValidationError,
  ForbiddenError,
  SecureFlowError,
  UnauthorizedError,
} from '@secureflow/shared';

describe('Sub-Gate 4B.1 — AuthService, Session Lifecycle, Least-Privilege Provisioning & Bootstrap (Unit Tests)', () => {
  const ADMIN_ID = '00000000-0000-0000-0000-000000000001';
  const DEV_ID = '00000000-0000-0000-0000-000000000003';
  const PROJECT_ID = '00000000-0000-0000-0000-000000000010';
  const BASE_NOW = new Date('2026-11-11T12:00:00.000Z');

  let usersById: Map<string, UserProfileEntity>;
  let sessionsById: Map<string, UserSessionEntity>;
  let oidcTxnsByHash: Map<string, OidcTransactionEntity>;
  let auditEvents: AuditEventEntity[];
  let nextUserSeq: number;
  let nextSessionSeq: number;
  let nextTxnSeq: number;
  let nextAuditSeq: number;

  let mockUserRepo: IUserRepository;
  let mockSessionRepo: ISessionRepository;
  let mockOidcTxnRepo: IOidcTransactionRepository;
  let mockAuditRepo: IAuditRepository;
  let mockRepos: RepositoryContainer;
  let authService: AuthService;

  beforeEach(() => {
    usersById = new Map();
    sessionsById = new Map();
    oidcTxnsByHash = new Map();
    auditEvents = [];
    nextUserSeq = 10;
    nextSessionSeq = 1;
    nextTxnSeq = 1;
    nextAuditSeq = 1;

    mockUserRepo = {
      findById: vi.fn(async (id: string) => {
        const u = usersById.get(id);
        return u ? { id: u.id, isActive: u.isActive, globalRole: u.globalRole } : null;
      }),
      findProfileById: vi.fn(async (id: string) => usersById.get(id) ?? null),
      findBySub: vi.fn(async (sub: string) => {
        for (const u of usersById.values()) {
          if (u.sub === sub) return u;
        }
        return null;
      }),
      findByEmail: vi.fn(async (email: string) => {
        const lower = email.toLowerCase();
        for (const u of usersById.values()) {
          if (u.email.toLowerCase() === lower) return u;
        }
        return null;
      }),
      findAuthoritativeUser: vi.fn(async (id: string) => {
        const u = usersById.get(id);
        if (!u) return null;
        return {
          id: u.id,
          isActive: u.isActive,
          globalRole: u.globalRole,
          memberships: [],
        };
      }),
      lockUser: vi.fn(async (id: string) => {
        const u = usersById.get(id);
        return u ? { id: u.id, isActive: u.isActive, globalRole: u.globalRole } : null;
      }),
      lockUserBySub: vi.fn(async (sub: string) => {
        for (const u of usersById.values()) {
          if (u.sub === sub) return u;
        }
        return null;
      }),
      lockUserByEmail: vi.fn(async (email: string) => {
        const lower = email.toLowerCase();
        for (const u of usersById.values()) {
          if (u.email.toLowerCase() === lower) return u;
        }
        return null;
      }),
      lockUsers: vi.fn(async (ids: string[]) => {
        const sorted = [...new Set(ids)].sort();
        const map = new Map();
        for (const id of sorted) {
          const u = usersById.get(id);
          if (u) {
            map.set(id, { id: u.id, isActive: u.isActive, globalRole: u.globalRole });
          }
        }
        return map;
      }),
      createUser: vi.fn(async (data) => {
        const id = `00000000-0000-0000-0000-0000000000${String(nextUserSeq++).padStart(2, '0')}`;
        const entity: UserProfileEntity = {
          id,
          sub: data.sub,
          email: data.email,
          displayName: data.displayName,
          globalRole: data.globalRole,
          isActive: data.isActive ?? true,
          createdAt: BASE_NOW,
          updatedAt: BASE_NOW,
        };
        usersById.set(id, entity);
        return entity;
      }),
      updateDisplayName: vi.fn(async (id: string, displayName: string) => {
        const existing = usersById.get(id)!;
        const updated = { ...existing, displayName, updatedAt: BASE_NOW };
        usersById.set(id, updated);
        return updated;
      }),
      deactivateUser: vi.fn(async (id: string) => {
        const existing = usersById.get(id)!;
        const updated = { ...existing, isActive: false, updatedAt: BASE_NOW };
        usersById.set(id, updated);
        return { id: updated.id, isActive: updated.isActive, globalRole: updated.globalRole };
      }),
      updateGlobalRole: vi.fn(async (id: string, role) => {
        const existing = usersById.get(id)!;
        const updated = { ...existing, globalRole: role, updatedAt: BASE_NOW };
        usersById.set(id, updated);
        return { id: updated.id, isActive: updated.isActive, globalRole: updated.globalRole };
      }),
      acquireBootstrapAdvisoryLock: vi.fn(async () => undefined),
      acquireIdentityProvisioningLocks: vi.fn(async () => undefined),
      countActiveAdmins: vi.fn(async () => {
        let count = 0;
        for (const u of usersById.values()) {
          if (u.globalRole === 'ADMIN' && u.isActive) count++;
        }
        return count;
      }),
    };

    mockSessionRepo = {
      create: vi.fn(async (data) => {
        const id = `10000000-0000-0000-0000-0000000000${String(nextSessionSeq++).padStart(2, '0')}`;
        const entity: UserSessionEntity = {
          id,
          userId: data.userId,
          tokenHash: data.tokenHash,
          csrfToken: data.csrfToken ?? 'csrf-token-fixture',
          oidcSid: data.oidcSid ?? null,
          ipAddress: data.ipAddress ?? null,
          userAgent: data.userAgent ?? null,
          createdAt: data.lastActivityAt,
          lastActivityAt: data.lastActivityAt,
          idleExpiresAt: data.idleExpiresAt,
          expiresAt: data.expiresAt,
          revokedAt: null,
          revocationReason: null,
        };
        sessionsById.set(id, entity);
        return entity;
      }),
      findByTokenHash: vi.fn(async (tokenHash: string) => {
        for (const s of sessionsById.values()) {
          if (s.tokenHash === tokenHash) return s;
        }
        return null;
      }),
      findById: vi.fn(async (id: string) => sessionsById.get(id) ?? null),
      listActiveByUserId: vi.fn(async (userId: string, now: Date = BASE_NOW) => {
        return [...sessionsById.values()]
          .filter(
            (s) =>
              s.userId === userId &&
              s.revokedAt === null &&
              s.expiresAt > now &&
              s.idleExpiresAt > now,
          )
          .sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime());
      }),
      touchActivity: vi.fn(async (id: string, lastActivityAt: Date, idleExpiresAt: Date) => {
        const existing = sessionsById.get(id)!;
        const updated = { ...existing, lastActivityAt, idleExpiresAt };
        sessionsById.set(id, updated);
        return updated;
      }),
      revokeById: vi.fn(async (id: string, reason: string, revokedAt: Date = BASE_NOW) => {
        const existing = sessionsById.get(id);
        if (!existing || existing.revokedAt !== null) return false;
        sessionsById.set(id, { ...existing, revokedAt, revocationReason: reason });
        return true;
      }),
      revokeByTokenHash: vi.fn(async (tokenHash: string, reason: string, revokedAt: Date = BASE_NOW) => {
        for (const [id, s] of sessionsById.entries()) {
          if (s.tokenHash === tokenHash) {
            if (s.revokedAt !== null) return s;
            const updated = { ...s, revokedAt, revocationReason: reason };
            sessionsById.set(id, updated);
            return updated;
          }
        }
        return null;
      }),
      revokeAllActiveForUser: vi.fn(async (userId: string, reason: string, revokedAt: Date = BASE_NOW) => {
        let count = 0;
        for (const [id, s] of sessionsById.entries()) {
          if (s.userId === userId && s.revokedAt === null) {
            sessionsById.set(id, { ...s, revokedAt, revocationReason: reason });
            count++;
          }
        }
        return count;
      }),
      revokeActiveByOidcSid: vi.fn(async (oidcSid: string, reason: string, revokedAt: Date = BASE_NOW) => {
        let count = 0;
        for (const [id, s] of sessionsById.entries()) {
          if (s.oidcSid === oidcSid && s.revokedAt === null) {
            sessionsById.set(id, { ...s, revokedAt, revocationReason: reason });
            count++;
          }
        }
        return count;
      }),
    };

    mockOidcTxnRepo = {
      create: vi.fn(async (data) => {
        const id = `20000000-0000-0000-0000-0000000000${String(nextTxnSeq++).padStart(2, '0')}`;
        const entity: OidcTransactionEntity = {
          id,
          txnTokenHash: data.txnTokenHash,
          stateHash: data.stateHash,
          nonce: data.nonce,
          codeVerifier: data.codeVerifier,
          returnTo: data.returnTo,
          createdAt: BASE_NOW,
          expiresAt: data.expiresAt,
          consumedAt: null,
        };
        oidcTxnsByHash.set(data.txnTokenHash, entity);
        return entity;
      }),
      findByTokenHash: vi.fn(async (txnTokenHash: string) => oidcTxnsByHash.get(txnTokenHash) ?? null),
      consumeAtomically: vi.fn(async (txnTokenHash: string, now: Date = BASE_NOW) => {
        const existing = oidcTxnsByHash.get(txnTokenHash);
        if (!existing || existing.consumedAt !== null || existing.expiresAt <= now) {
          return null;
        }
        const consumed = { ...existing, consumedAt: now };
        oidcTxnsByHash.set(txnTokenHash, consumed);
        return consumed;
      }),
      deleteExpired: vi.fn(async () => 0),
    };

    mockAuditRepo = {
      append: vi.fn(async (data) => {
        const event: AuditEventEntity = {
          id: `30000000-0000-0000-0000-0000000000${String(nextAuditSeq++).padStart(2, '0')}`,
          actorId: data.actorId ?? null,
          eventCategory: data.eventCategory,
          eventType: data.eventType,
          resourceId: data.resourceId ?? null,
          resourceType: data.resourceType ?? null,
          beforeState: data.beforeState ?? null,
          afterState: data.afterState ?? null,
          ipAddress: data.ipAddress ?? null,
          userAgent: data.userAgent ?? null,
          createdAt: BASE_NOW,
        };
        auditEvents.push(event);
        return event;
      }),
      query: vi.fn(),
    };

    mockRepos = {
      projectRepo: {} as IProjectRepository,
      findingRepo: {} as IFindingRepository,
      taskRepo: {} as ITaskRepository,
      auditRepo: mockAuditRepo,
      userRepo: mockUserRepo,
      sessionRepo: mockSessionRepo,
      oidcTransactionRepo: mockOidcTxnRepo,
    };

    authService = createTestAuthService(mockRepos);
  });

  describe('1. Cryptographic Primitives & Initialization Boundaries', () => {
    it('hashOpaqueToken computes deterministic 64-char lowercase hex SHA-256 digests', () => {
      const token = generateOpaqueToken(32);
      const hash1 = hashOpaqueToken(token);
      const hash2 = hashOpaqueToken(token);

      expect(hash1).toBe(hash2);
      expect(hash1).toMatch(/^[0-9a-f]{64}$/);
      expect(hash1).not.toBe(token);
    });

    it('computePkceS256Challenge computes RFC 7636 S256 base64url challenge', () => {
      // RFC 7636 Appendix B test vector
      const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
      const expectedChallenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
      expect(computePkceS256Challenge(verifier)).toBe(expectedChallenge);
    });

    it('AuthService rejects direct unauthorized repository injection outside @secureflow/domain/testing', () => {
      expect(() => new AuthService(null as never)).toThrow(SecureFlowError);
      expect(() => new AuthService({ repositories: mockRepos } as never)).toThrow(
        /Direct repository injection is prohibited/,
      );
    });
  });

  describe('2. Single-Use OIDC Transactions & State Validation', () => {
    it('creates OIDC transaction storing only SHA-256 hashes of rawTxnToken and state', async () => {
      const created = await authService.createOidcTransaction(
        { returnTo: '/projects/123', ttlSeconds: 300 },
        BASE_NOW,
      );

      expect(created.rawTxnToken.length).toBeGreaterThanOrEqual(40);
      expect(created.state.length).toBeGreaterThanOrEqual(40);
      expect(created.codeChallengeMethod).toBe('S256');
      expect(created.codeChallenge).toBe(computePkceS256Challenge(created.codeVerifier));

      const stored = oidcTxnsByHash.get(hashOpaqueToken(created.rawTxnToken));
      expect(stored).toBeDefined();
      expect(stored!.txnTokenHash).toBe(hashOpaqueToken(created.rawTxnToken));
      expect(stored!.stateHash).toBe(hashOpaqueToken(created.state));
      expect(stored!.txnTokenHash).not.toBe(created.rawTxnToken);
      expect(stored!.stateHash).not.toBe(created.state);
    });

    it('rejects open-redirect returnTo values (absolute URLs, protocol-relative //, backslashes)', async () => {
      await expect(
        authService.createOidcTransaction({ returnTo: 'https://evil.example/phish' }),
      ).rejects.toThrow(DomainValidationError);

      await expect(
        authService.createOidcTransaction({ returnTo: '//evil.example/phish' }),
      ).rejects.toThrow(DomainValidationError);

      await expect(
        authService.createOidcTransaction({ returnTo: '/\\evil.example' }),
      ).rejects.toThrow(DomainValidationError);
    });

    it('consumes OIDC transaction once and rejects replay attempts with 401 and auth.login_failed', async () => {
      const created = await authService.createOidcTransaction({ returnTo: '/dashboard' }, BASE_NOW);

      const consumed = await authService.consumeOidcTransaction(
        {
          rawTxnToken: created.rawTxnToken,
          state: created.state,
          ipAddress: '127.0.0.1',
          userAgent: 'Vitest',
        },
        BASE_NOW,
      );

      expect(consumed.id).toBe(created.id);
      expect(consumed.nonce).toBe(created.nonce);
      expect(consumed.codeVerifier).toBe(created.codeVerifier);
      expect(consumed.returnTo).toBe('/dashboard');

      // Replay attempt with the exact same rawTxnToken and state must fail with 401
      await expect(
        authService.consumeOidcTransaction(
          {
            rawTxnToken: created.rawTxnToken,
            state: created.state,
            ipAddress: '127.0.0.1',
            userAgent: 'Vitest',
          },
          BASE_NOW,
        ),
      ).rejects.toThrow(UnauthorizedError);

      expect(auditEvents).toHaveLength(1);
      expect(auditEvents[0]?.eventType).toBe('auth.login_failed');
      expect(auditEvents[0]?.actorId).toBeNull();
      expect(auditEvents[0]?.afterState).toMatchObject({
        outcome: 'FAILURE',
        reason: 'MISSING_OR_EXPIRED_OIDC_TRANSACTION',
      });
    });

    it('burns OIDC transaction on state mismatch and records auth.login_failed', async () => {
      const created = await authService.createOidcTransaction({ returnTo: '/' }, BASE_NOW);

      await expect(
        authService.consumeOidcTransaction(
          {
            rawTxnToken: created.rawTxnToken,
            state: generateOpaqueToken(32), // mismatched state
          },
          BASE_NOW,
        ),
      ).rejects.toThrow(UnauthorizedError);

      // Even if retried with the original valid state, the transaction was already consumed/burned
      await expect(
        authService.consumeOidcTransaction(
          {
            rawTxnToken: created.rawTxnToken,
            state: created.state,
          },
          BASE_NOW,
        ),
      ).rejects.toThrow(UnauthorizedError);

      expect(auditEvents).toHaveLength(2);
      expect(auditEvents[0]?.afterState).toMatchObject({ reason: 'OIDC_STATE_MISMATCH' });
      expect(auditEvents[1]?.afterState).toMatchObject({
        reason: 'MISSING_OR_EXPIRED_OIDC_TRANSACTION',
      });
    });
  });

  describe('3. Strict Least-Privilege JIT Provisioning & Account Conflict Protection', () => {
    it('provisions unknown verified user strictly as DEVELOPER with 0 memberships even when Keycloak sends ADMIN/ANALYST realmRoles', async () => {
      const established = await authService.establishAuthenticatedSession(
        {
          sub: 'kc-sub-new-user-1',
          email: 'NewDev@Example.com',
          emailVerified: true,
          displayName: 'New Developer',
          oidcSid: 'kc-sid-1',
          realmRoles: ['ADMIN', 'ANALYST', 'SUPERUSER'],
          ipAddress: '10.0.0.5',
          userAgent: 'Mozilla/5.0',
        },
        BASE_NOW,
      );

      expect(established.jitProvisioned).toBe(true);
      expect(established.user.globalRole).toBe('DEVELOPER');
      expect(established.user.email).toBe('newdev@example.com');
      expect(established.actor.globalRole).toBe('DEVELOPER');
      expect(established.actor.isAdmin()).toBe(false);
      expect(established.actor.memberships.size).toBe(0);

      // Verify raw token is NOT stored in session table
      expect(established.session.tokenHash).toBe(hashOpaqueToken(established.rawSessionToken));
      expect(established.session.tokenHash).not.toBe(established.rawSessionToken);

      // Verify audit trail
      expect(auditEvents.map((e) => e.eventType)).toEqual([
        'auth.user_jit_provisioned',
        'auth.login_succeeded',
      ]);
      expect(auditEvents[0]?.afterState).toMatchObject({
        globalRole: 'DEVELOPER',
        projectMembershipsCount: 0,
        ignoredIdpRoleClaimsCount: 3,
      });
    });

    it('rejects unverified email claims with 403 Forbidden and records auth.login_failed with actorId: null', async () => {
      await expect(
        authService.establishAuthenticatedSession(
          {
            sub: 'kc-sub-unverified',
            email: 'unverified@example.com',
            emailVerified: false,
          },
          BASE_NOW,
        ),
      ).rejects.toThrow(ForbiddenError);

      expect(usersById.size).toBe(0);
      expect(sessionsById.size).toBe(0);
      expect(auditEvents).toHaveLength(1);
      expect(auditEvents[0]?.eventType).toBe('auth.login_failed');
      expect(auditEvents[0]?.actorId).toBeNull();
      expect(auditEvents[0]?.afterState).toMatchObject({
        reason: 'EMAIL_NOT_VERIFIED',
      });
    });

    it('rejects email-to-sub account conflicts without auto-linking and records auth.login_failed with actorId: null', async () => {
      // Seed existing user with sub 'kc-original-sub' and email 'alice@example.com'
      usersById.set(DEV_ID, {
        id: DEV_ID,
        sub: 'kc-original-sub',
        email: 'alice@example.com',
        displayName: 'Alice',
        globalRole: 'ANALYST',
        isActive: true,
        createdAt: BASE_NOW,
        updatedAt: BASE_NOW,
      });

      // Another OIDC subject claims 'alice@example.com'
      await expect(
        authService.establishAuthenticatedSession(
          {
            sub: 'kc-different-sub',
            email: 'alice@example.com',
            emailVerified: true,
          },
          BASE_NOW,
        ),
      ).rejects.toThrow(ForbiddenError);

      expect(sessionsById.size).toBe(0);
      expect(auditEvents).toHaveLength(1);
      expect(auditEvents[0]?.eventType).toBe('auth.login_failed');
      expect(auditEvents[0]?.actorId).toBeNull();
      expect(auditEvents[0]?.resourceId).toBe(DEV_ID);
      expect(auditEvents[0]?.afterState).toMatchObject({
        reason: 'EMAIL_SUB_CONFLICT',
      });
    });

    it('rejects deactivated user accounts with 403 Forbidden and records auth.login_failed with actorId set to the existing user ID', async () => {
      usersById.set(DEV_ID, {
        id: DEV_ID,
        sub: 'kc-deactivated-sub',
        email: 'inactive@example.com',
        displayName: 'Inactive Dev',
        globalRole: 'DEVELOPER',
        isActive: false,
        createdAt: BASE_NOW,
        updatedAt: BASE_NOW,
      });

      await expect(
        authService.establishAuthenticatedSession(
          {
            sub: 'kc-deactivated-sub',
            email: 'inactive@example.com',
            emailVerified: true,
          },
          BASE_NOW,
        ),
      ).rejects.toThrow(ForbiddenError);

      expect(sessionsById.size).toBe(0);
      expect(auditEvents).toHaveLength(1);
      expect(auditEvents[0]?.eventType).toBe('auth.login_failed');
      expect(auditEvents[0]?.actorId).toBe(DEV_ID);
      expect(auditEvents[0]?.resourceId).toBe(DEV_ID);
      expect(auditEvents[0]?.afterState).toMatchObject({
        reason: 'USER_DEACTIVATED',
      });
    });
  });

  describe('4. Audit-Failure Resilience & Secret Sanitization (Sections 6 & 7)', () => {
    it('fails closed if auth.login_succeeded audit append throws, preventing unauthorized session issuance', async () => {
      vi.spyOn(mockAuditRepo, 'append').mockRejectedValueOnce(new Error('Simulated DB audit failure'));

      await expect(
        authService.establishAuthenticatedSession(
          {
            sub: 'kc-sub-1',
            email: 'user@example.com',
            emailVerified: true,
          },
          BASE_NOW,
        ),
      ).rejects.toThrow(/Simulated DB audit failure/);
    });

    it('still rejects failed login even if recordAuthenticationFailure audit append throws', async () => {
      vi.spyOn(mockAuditRepo, 'append').mockRejectedValue(new Error('Audit table unavailable'));

      await expect(
        authService.establishAuthenticatedSession(
          {
            sub: 'kc-sub-unverified',
            email: 'unverified@example.com',
            emailVerified: false,
          },
          BASE_NOW,
        ),
      ).rejects.toThrow(ForbiddenError);
    });

    it('strips any secret, token, code, verifier, or cookie fields from failure audit metadata', async () => {
      const event = await authService.recordAuthenticationFailure({
        reason: 'OIDC_TOKEN_EXCHANGE_FAILED',
        actorId: null,
        resourceUserId: null,
        ipAddress: '127.0.0.1',
        userAgent: 'TestAgent',
        metadata: {
          errorCode: 'invalid_grant',
          code: 'secret-auth-code',
          codeVerifier: 'secret-pkce-verifier',
          rawSessionToken: 'secret-session-token',
          rawTxnToken: 'secret-txn-token',
          accessToken: 'secret-access-token',
          idToken: 'secret-id-token',
          cookie: '__Host-sf_session=secret',
          clientSecret: 'super-secret',
        },
      });

      expect(event).not.toBeNull();
      const serialized = JSON.stringify(event!.afterState);
      expect(serialized).toContain('invalid_grant');
      expect(serialized).not.toContain('secret-auth-code');
      expect(serialized).not.toContain('secret-pkce-verifier');
      expect(serialized).not.toContain('secret-session-token');
      expect(serialized).not.toContain('secret-txn-token');
      expect(serialized).not.toContain('secret-access-token');
      expect(serialized).not.toContain('secret-id-token');
      expect(serialized).not.toContain('__Host-sf_session');
      expect(serialized).not.toContain('super-secret');
    });
  });

  describe('5. Session Resolution, Sliding Idle Expiry, Absolute Expiry & Revocation', () => {
    it('resolves valid session token to fresh ActorContext and updates sliding idle window after >= 60s', async () => {
      const established = await authService.establishAuthenticatedSession(
        {
          sub: 'kc-session-user',
          email: 'session@example.com',
          emailVerified: true,
          idleTimeoutSeconds: 1800,
          absoluteTimeoutSeconds: 28800,
        },
        BASE_NOW,
      );

      // 30 seconds later (< 60s threshold): no touchActivity call
      const tPlus30s = new Date(BASE_NOW.getTime() + 30_000);
      const resolved1 = await authService.resolveSessionActor(
        { rawSessionToken: established.rawSessionToken },
        tPlus30s,
      );
      expect(resolved1.actor.id).toBe(established.user.id);
      expect(mockSessionRepo.touchActivity).not.toHaveBeenCalled();

      // 120 seconds later (>= 60s threshold): touchActivity advances idleExpiresAt
      const tPlus120s = new Date(BASE_NOW.getTime() + 120_000);
      const resolved2 = await authService.resolveSessionActor(
        { rawSessionToken: established.rawSessionToken },
        tPlus120s,
      );
      expect(mockSessionRepo.touchActivity).toHaveBeenCalledTimes(1);
      expect(resolved2.session.lastActivityAt.getTime()).toBe(tPlus120s.getTime());
      expect(resolved2.session.idleExpiresAt.getTime()).toBe(tPlus120s.getTime() + 1800_000);
    });

    it('rejects session after idle timeout or absolute timeout and revokes the expired session', async () => {
      const established = await authService.establishAuthenticatedSession(
        {
          sub: 'kc-expiry-user',
          email: 'expiry@example.com',
          emailVerified: true,
          idleTimeoutSeconds: 600,
          absoluteTimeoutSeconds: 3600,
        },
        BASE_NOW,
      );

      const afterIdle = new Date(BASE_NOW.getTime() + 601_000);
      await expect(
        authService.resolveSessionActor(
          { rawSessionToken: established.rawSessionToken },
          afterIdle,
        ),
      ).rejects.toThrow(UnauthorizedError);

      const stored = sessionsById.get(established.session.id)!;
      expect(stored.revokedAt).toEqual(afterIdle);
      expect(stored.revocationReason).toBe('IDLE_TIMEOUT_EXPIRED');
    });

    it('revokes session on logout and rejects subsequent resolveSessionActor calls', async () => {
      const established = await authService.establishAuthenticatedSession(
        {
          sub: 'kc-logout-user',
          email: 'logout@example.com',
          emailVerified: true,
        },
        BASE_NOW,
      );

      const revoked = await authService.revokeSession(
        { rawSessionToken: established.rawSessionToken, reason: 'USER_LOGOUT' },
        BASE_NOW,
      );
      expect(revoked).toBe(true);

      await expect(
        authService.resolveSessionActor(
          { rawSessionToken: established.rawSessionToken },
          BASE_NOW,
        ),
      ).rejects.toThrow(UnauthorizedError);
    });
  });

  describe('6. Concurrent-Safe Initial Admin Bootstrap & Role/Deactivation Session Revocation', () => {
    it('bootstraps initial Admin under advisory lock when countActiveAdmins() === 0 and rejects subsequent bootstrap with 409', async () => {
      const adminProfile = await authService.bootstrapInitialAdmin(
        {
          issuer: 'http://localhost:8080/realms/secureflow',
          expectedIssuer: 'http://localhost:8080/realms/secureflow',
          sub: 'kc-bootstrap-admin-sub',
          expectedSub: 'kc-bootstrap-admin-sub',
          email: 'admin@secureflow.local',
          displayName: 'Initial Admin',
        },
        BASE_NOW,
      );

      expect(mockUserRepo.acquireBootstrapAdvisoryLock).toHaveBeenCalledTimes(1);
      expect(adminProfile.globalRole).toBe('ADMIN');
      expect(adminProfile.isActive).toBe(true);

      // Second bootstrap attempt must fail with 409 ConcurrencyConflictError
      await expect(
        authService.bootstrapInitialAdmin(
          {
            issuer: 'http://localhost:8080/realms/secureflow',
            expectedIssuer: 'http://localhost:8080/realms/secureflow',
            sub: 'kc-bootstrap-admin-sub',
            expectedSub: 'kc-bootstrap-admin-sub',
            email: 'admin@secureflow.local',
          },
          BASE_NOW,
        ),
      ).rejects.toThrow(ConcurrencyConflictError);
    });

    it('rejects bootstrap when issuer or sub does not match expected configuration', async () => {
      await expect(
        authService.bootstrapInitialAdmin(
          {
            issuer: 'http://evil-idp.example/realms/secureflow',
            expectedIssuer: 'http://localhost:8080/realms/secureflow',
            sub: 'kc-bootstrap-admin-sub',
            expectedSub: 'kc-bootstrap-admin-sub',
            email: 'admin@secureflow.local',
          },
          BASE_NOW,
        ),
      ).rejects.toThrow(ForbiddenError);

      expect(usersById.size).toBe(0);
      expect(auditEvents.at(-1)?.afterState).toMatchObject({
        reason: 'INVALID_BOOTSTRAP_CREDENTIALS',
      });
    });

    it('revokes all active sessions immediately when a user global role is updated or account is deactivated', async () => {
      // Seed Admin and Developer
      usersById.set(ADMIN_ID, {
        id: ADMIN_ID,
        sub: 'kc-admin-1',
        email: 'admin@example.com',
        displayName: 'Admin',
        globalRole: 'ADMIN',
        isActive: true,
        createdAt: BASE_NOW,
        updatedAt: BASE_NOW,
      });

      const established = await authService.establishAuthenticatedSession(
        {
          sub: 'kc-dev-1',
          email: 'dev@example.com',
          emailVerified: true,
        },
        BASE_NOW,
      );

      const adminActor = createTestAdminActor({ id: ADMIN_ID });

      // Update role from DEVELOPER to ANALYST -> revokes active session
      const updatedRole = await authService.updateUserGlobalRole(
        adminActor,
        established.user.id,
        {
          globalRole: 'ANALYST',
          justification: 'Promoted to security analyst team',
        },
        BASE_NOW,
      );
      expect(updatedRole.globalRole).toBe('ANALYST');

      await expect(
        authService.resolveSessionActor(
          { rawSessionToken: established.rawSessionToken },
          BASE_NOW,
        ),
      ).rejects.toThrow(UnauthorizedError);

      // Re-login and then deactivate user -> revokes new session
      const relogin = await authService.establishAuthenticatedSession(
        {
          sub: 'kc-dev-1',
          email: 'dev@example.com',
          emailVerified: true,
        },
        BASE_NOW,
      );
      expect(relogin.actor.globalRole).toBe('ANALYST');

      await authService.deactivateUser(
        adminActor,
        established.user.id,
        {
          justification: 'Employee offboarded from organization',
        },
        BASE_NOW,
      );

      await expect(
        authService.resolveSessionActor(
          { rawSessionToken: relogin.rawSessionToken },
          BASE_NOW,
        ),
      ).rejects.toThrow(UnauthorizedError);

      // Prevent deactivating the last active Global Admin
      await expect(
        authService.deactivateUser(
          createTestDeveloperActor(PROJECT_ID, { id: established.user.id }),
          ADMIN_ID,
          { justification: 'Unauthorized attempt' },
          BASE_NOW,
        ),
      ).rejects.toThrow(ForbiddenError);

      await expect(
        authService.deactivateUser(
          adminActor,
          ADMIN_ID,
          { justification: 'Attempt to deactivate last active admin' },
          BASE_NOW,
        ),
      ).rejects.toThrow(DomainValidationError);
    });
  });

  describe('Concurrent JIT Provisioning Serialization & Unique-Constraint Defense in Depth', () => {
    it('acquires canonical (email, sub) advisory locks with lowercase email prior to FOR UPDATE lookups', async () => {
      await authService.establishAuthenticatedSession(
        {
          sub: 'kc-lock-user',
          email: 'MixedCase.User@Example.COM',
          emailVerified: true,
        },
        BASE_NOW,
      );

      const lockMock = mockUserRepo.acquireIdentityProvisioningLocks as ReturnType<typeof vi.fn>;
      const lockSubMock = mockUserRepo.lockUserBySub as ReturnType<typeof vi.fn>;
      const lockEmailMock = mockUserRepo.lockUserByEmail as ReturnType<typeof vi.fn>;

      expect(lockMock).toHaveBeenCalledTimes(1);
      expect(lockMock).toHaveBeenCalledWith('kc-lock-user', 'mixedcase.user@example.com');
      const advisoryOrder = lockMock.mock.invocationCallOrder[0]!;
      expect(advisoryOrder).toBeLessThan(lockSubMock.mock.invocationCallOrder[0]!);
      expect(advisoryOrder).toBeLessThan(lockEmailMock.mock.invocationCallOrder[0]!);
    });

    it('recovers idempotently from a defense-in-depth P2002 race for the same OIDC sub', async () => {
      const winnerUser: UserProfileEntity = {
        id: '00000000-0000-0000-0000-000000000098',
        sub: 'kc-race-same-sub',
        email: 'same-sub@example.com',
        displayName: 'Same Sub User',
        globalRole: 'DEVELOPER',
        isActive: true,
        createdAt: BASE_NOW,
        updatedAt: BASE_NOW,
      };

      const createUserMock = mockUserRepo.createUser as ReturnType<typeof vi.fn>;
      createUserMock.mockImplementationOnce(async () => {
        usersById.set(winnerUser.id, winnerUser);
        throw Object.assign(new Error('Unique constraint failed on index users_sub_key'), {
          code: 'P2002',
          meta: { target: ['sub'] },
        });
      });

      const result = await authService.establishAuthenticatedSession(
        {
          sub: 'kc-race-same-sub',
          email: 'SAME-SUB@Example.COM',
          emailVerified: true,
        },
        BASE_NOW,
      );

      expect(result.jitProvisioned).toBe(false);
      expect(result.user.id).toBe(winnerUser.id);
      expect(result.actor.globalRole).toBe('DEVELOPER');
      expect(sessionsById.size).toBe(1);
    });

    it('NEGATIVE: converts defense-in-depth email unique-constraint race across different subs into generic 403 and persisted auth.login_failed without leaking DB details', async () => {
      usersById.set(DEV_ID, {
        id: DEV_ID,
        sub: 'kc-existing-email-owner',
        email: 'shared-race@example.com',
        displayName: 'Existing Owner',
        globalRole: 'DEVELOPER',
        isActive: true,
        createdAt: BASE_NOW,
        updatedAt: BASE_NOW,
      });

      const lockEmailMock = mockUserRepo.lockUserByEmail as ReturnType<typeof vi.fn>;
      lockEmailMock.mockResolvedValueOnce(null);

      const createUserMock = mockUserRepo.createUser as ReturnType<typeof vi.fn>;
      createUserMock.mockRejectedValueOnce(
        Object.assign(
          new Error('duplicate key value violates unique constraint "users_email_lower_key"'),
          { code: '23505' },
        ),
      );

      let caught: unknown;
      try {
        await authService.establishAuthenticatedSession(
          {
            sub: 'kc-raced-other-sub',
            email: 'SHARED-RACE@Example.COM',
            emailVerified: true,
            ipAddress: '198.51.100.77',
            userAgent: 'RaceTestAgent/1.0',
          },
          BASE_NOW,
        );
      } catch (err: unknown) {
        caught = err;
      }

      expect(caught).toBeInstanceOf(ForbiddenError);
      const forbidden = caught as ForbiddenError;
      expect(forbidden.statusCode).toBe(403);
      expect(forbidden.message).not.toMatch(/users_email|23505|unique constraint|duplicate key/i);
      expect(forbidden.details).toBeUndefined();
      expect(sessionsById.size).toBe(0);

      const failedEvent = auditEvents.find(
        (ev) =>
          ev.eventType === 'auth.login_failed' &&
          ev.resourceId === DEV_ID,
      );
      expect(failedEvent).toBeDefined();
      expect(failedEvent?.actorId).toBeNull();
      expect(failedEvent?.afterState).toMatchObject({ reason: 'EMAIL_SUB_CONFLICT' });
    });
  });

  describe('7. Session Concurrency Eviction & Short Idle Window Preservation (Gate 4B.4)', () => {
    it('preserves configured idleTimeoutSeconds shorter than 30 minutes across sliding activity touches', async () => {
      const loginTime = BASE_NOW;
      const established = await authService.establishAuthenticatedSession(
        {
          sub: 'kc-short-idle-sub',
          email: 'short-idle@example.com',
          emailVerified: true,
          idleTimeoutSeconds: 300, // 5 minutes (< 30m default floor)
          absoluteTimeoutSeconds: 3600,
        },
        loginTime,
      );

      // Activity after 90 seconds (>= 60s threshold) extends idleExpiresAt by 300s (to t=390s), not 1800s
      const tPlus90s = new Date(loginTime.getTime() + 90_000);
      const touched = await authService.resolveSessionActor(
        { rawSessionToken: established.rawSessionToken },
        tPlus90s,
      );
      expect(touched.session.idleExpiresAt.getTime()).toBe(tPlus90s.getTime() + 300_000);

      // Next request after another 299s (at t=389s < 390s) succeeds and slides by 300s again (to t=689s)
      const tPlus389s = new Date(loginTime.getTime() + 389_000);
      const touchedAgain = await authService.resolveSessionActor(
        { rawSessionToken: established.rawSessionToken },
        tPlus389s,
      );
      expect(touchedAgain.session.idleExpiresAt.getTime()).toBe(tPlus389s.getTime() + 300_000);

      // Expired at t = 690s (well under the erroneous 1800s floor!) -> rejected and revoked as IDLE_TIMEOUT_EXPIRED
      const tPlus690s = new Date(loginTime.getTime() + 690_000);
      await expect(
        authService.resolveSessionActor({ rawSessionToken: established.rawSessionToken }, tPlus690s),
      ).rejects.toThrow(UnauthorizedError);
      expect(sessionsById.get(established.session.id)?.revocationReason).toBe('IDLE_TIMEOUT_EXPIRED');
    });

    it('evicts the oldest active sessions with MAX_CONCURRENT_SESSIONS_EXCEEDED when exceeding 5 concurrent sessions per user', async () => {
      const issuedSessions: Array<{ id: string; rawToken: string }> = [];

      for (let i = 0; i < 6; i++) {
        const res = await authService.establishAuthenticatedSession(
          {
            sub: 'kc-concurrent-limit-sub',
            email: 'concurrent@example.com',
            emailVerified: true,
          },
          new Date(BASE_NOW.getTime() + i * 1000),
        );
        issuedSessions.push({ id: res.session.id, rawToken: res.rawSessionToken });
      }

      // Oldest session (index 0) must be evicted
      const evicted = sessionsById.get(issuedSessions[0]!.id);
      expect(evicted?.revokedAt).not.toBeNull();
      expect(evicted?.revocationReason).toBe('MAX_CONCURRENT_SESSIONS_EXCEEDED');

      await expect(
        authService.resolveSessionActor(
          { rawSessionToken: issuedSessions[0]!.rawToken },
          new Date(BASE_NOW.getTime() + 10_000),
        ),
      ).rejects.toThrow(UnauthorizedError);

      // Sessions 1..5 remain active (5 active total)
      for (let i = 1; i < 6; i++) {
        const active = await authService.resolveSessionActor(
          { rawSessionToken: issuedSessions[i]!.rawToken },
          new Date(BASE_NOW.getTime() + 10_000),
        );
        expect(active.session.id).toBe(issuedSessions[i]!.id);
      }
    });
  });
});
