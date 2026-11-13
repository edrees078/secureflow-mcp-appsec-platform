import { describe, it, expect, vi, beforeEach } from 'vitest';
import request from 'supertest';
import { createApp } from '../../src/app.js';
import type { DomainServices, IAuthService } from '@secureflow/domain';
import type { IOidcClient, VerifiedOidcTokenIdentity } from '../../src/auth/oidc-client.js';
import type { AuthRuntimeConfig } from '../../src/config/auth.js';
import { createMockDomainServices } from '../helpers/mock-services.js';
import {
  COOKIE_NAME_DEV_SESSION,
  COOKIE_NAME_DEV_OIDC_TXN,
  COOKIE_NAME_PRODUCTION_SESSION,
  COOKIE_NAME_PRODUCTION_OIDC_TXN,
} from '../../src/auth/cookies.js';

const ISSUER_URL = 'http://127.0.0.1:8080/realms/secureflow';
const CLIENT_ID = 'secureflow-bff';
const REDIRECT_URI = 'http://127.0.0.1:3000/api/v1/auth/callback';
const ALLOWED_ORIGIN = 'http://localhost:5173';

function createDevAuthConfig(): AuthRuntimeConfig {
  return {
    mode: 'development',
    authEnabled: true,
    oidc: {
      issuerUrl: ISSUER_URL,
      clientId: CLIENT_ID,
      clientSecret: 'dev_secret_bff_client_1234567890',
      clientAuthMethod: 'client_secret_basic',
      redirectUri: REDIRECT_URI,
      allowedRedirectUris: [REDIRECT_URI],
      postLogoutRedirectUri: `${ALLOWED_ORIGIN}/login`,
      allowedPostLogoutRedirectUris: [`${ALLOWED_ORIGIN}/login`],
      scopes: 'openid email profile',
      clockToleranceSeconds: 30,
      allowInsecureHttp: true,
      requestTimeoutSeconds: 5,
    },
    session: {
      idleTimeoutSeconds: 1800,
      absoluteTimeoutSeconds: 28800,
      oidcTxnTtlSeconds: 300,
    },
    cookies: {
      mode: 'development',
      sessionCookieName: COOKIE_NAME_DEV_SESSION,
      oidcTxnCookieName: COOKIE_NAME_DEV_OIDC_TXN,
      secure: false,
      httpOnly: true,
      sameSite: 'Lax',
      path: '/',
    },
    allowedOrigins: [ALLOWED_ORIGIN],
  };
}

describe('Gate 4B.3 Integrated BFF Authentication Routes & Session/CSRF Wiring', () => {
  let mockServices: DomainServices;
  let mockAuthService: IAuthService;
  let mockOidcClient: IOidcClient;
  let authConfig: AuthRuntimeConfig;
  let app: ReturnType<typeof createApp>;

  const fixedNow = new Date('2026-11-12T12:00:00.000Z');
  const validCsrfToken = 'csrf_token_bound_secret_1234567890';
  const rawSessionToken = 'raw_session_token_dev_fixture_1234567890';
  const rawTxnToken = 'raw_txn_token_dev_fixture_1234567890';
  const stateFixture = 'state_fixture_1234567890';
  const nonceFixture = 'nonce_fixture_1234567890';

  const verifiedIdentity: VerifiedOidcTokenIdentity = {
    issuer: ISSUER_URL,
    sub: 'idp-sub-developer-alice',
    email: 'alice@secureflow.example',
    emailVerified: true,
    displayName: 'Alice Developer',
    oidcSid: 'idp-sid-session-123',
    audience: CLIENT_ID,
  };

  beforeEach(() => {
    mockServices = createMockDomainServices();
    authConfig = createDevAuthConfig();

    mockAuthService = {
      createOidcTransaction: vi.fn().mockResolvedValue({
        id: '11111111-1111-4111-8111-111111111111',
        rawTxnToken,
        state: stateFixture,
        nonce: nonceFixture,
        codeVerifier: 'code_verifier_dev_fixture_12345',
        codeChallenge: 'code_challenge_dev_fixture_12345',
        codeChallengeMethod: 'S256',
        returnTo: '/projects/00000000-0000-0000-0000-000000000001',
        expiresAt: new Date(fixedNow.getTime() + 300_000),
      }),
      consumeOidcTransaction: vi.fn().mockResolvedValue({
        id: '11111111-1111-4111-8111-111111111111',
        nonce: nonceFixture,
        codeVerifier: 'code_verifier_dev_fixture_12345',
        returnTo: '/projects/00000000-0000-0000-0000-000000000001',
        consumedAt: fixedNow,
      }),
      establishAuthenticatedSession: vi.fn().mockResolvedValue({
        rawSessionToken,
        jitProvisioned: false,
        session: {
          id: '22222222-2222-4222-8222-222222222222',
          userId: '33333333-3333-4333-8333-333333333333',
          sessionTokenHash: 'c'.repeat(64),
          csrfToken: validCsrfToken,
          oidcSid: 'idp-sid-session-123',
          ipAddress: '127.0.0.1',
          userAgent: 'Vitest',
          createdAt: fixedNow,
          lastActiveAt: fixedNow,
          idleExpiresAt: new Date(fixedNow.getTime() + 1_800_000),
          expiresAt: new Date(fixedNow.getTime() + 28_800_000),
          revokedAt: null,
          revocationReason: null,
        },
        user: {
          id: '33333333-3333-4333-8333-333333333333',
          email: 'alice@secureflow.example',
          displayName: 'Alice Developer',
          globalRole: 'USER',
          isActive: true,
          oidcSubject: 'idp-sub-developer-alice',
          createdAt: fixedNow,
        },
        actor: {
          id: '33333333-3333-4333-8333-333333333333',
          globalRole: 'USER',
          isActive: true,
          projectMemberships: new Map([['00000000-0000-0000-0000-000000000001', 'DEVELOPER']]),
        },
      }),
      resolveSessionActor: vi.fn().mockResolvedValue({
        actor: {
          id: '33333333-3333-4333-8333-333333333333',
          globalRole: 'USER',
          isActive: true,
          projectMemberships: new Map([['00000000-0000-0000-0000-000000000001', 'DEVELOPER']]),
        },
        session: {
          id: '22222222-2222-4222-8222-222222222222',
          userId: '33333333-3333-4333-8333-333333333333',
          sessionTokenHash: 'c'.repeat(64),
          csrfToken: validCsrfToken,
          oidcSid: 'idp-sid-session-123',
          ipAddress: '127.0.0.1',
          userAgent: 'Vitest',
          createdAt: fixedNow,
          lastActiveAt: fixedNow,
          idleExpiresAt: new Date(fixedNow.getTime() + 1_800_000),
          expiresAt: new Date(fixedNow.getTime() + 28_800_000),
          revokedAt: null,
          revocationReason: null,
        },
      }),
      revokeSession: vi.fn().mockResolvedValue(true),
      recordAuthenticationFailure: vi.fn().mockResolvedValue({
        id: '44444444-4444-4444-4444-444444444444',
        eventTimestamp: fixedNow,
        reason: 'OIDC_TOKEN_EXCHANGE_FAILED',
        actorId: null,
        resourceUserId: null,
        ipAddress: '127.0.0.1',
        userAgent: 'Vitest',
        metadata: {},
      }),
      cleanupExpired: vi.fn(),
      bootstrapInitialAdmin: vi.fn(),
    } as unknown as IAuthService;

    mockServices.projectService.listProjects = vi.fn().mockResolvedValue({
      items: [],
      total: 0,
      page: 1,
      limit: 20,
      totalPages: 0,
    });
    mockServices.projectService.createProject = vi.fn().mockResolvedValue({
      id: '00000000-0000-0000-0000-000000000001',
      name: 'Valid Project',
      description: null,
      status: 'ACTIVE',
      createdAt: fixedNow,
      updatedAt: fixedNow,
    });

    mockServices.authService = mockAuthService;

    mockOidcClient = {
      discover: vi.fn().mockResolvedValue({
        issuer: ISSUER_URL,
        authorizationEndpoint: `${ISSUER_URL}/protocol/openid-connect/auth`,
        tokenEndpoint: `${ISSUER_URL}/protocol/openid-connect/token`,
        jwksUri: `${ISSUER_URL}/protocol/openid-connect/certs`,
        supportsPkceS256: true,
      }),
      buildAuthorizationUrl: vi.fn().mockResolvedValue(
        new URL(`${ISSUER_URL}/protocol/openid-connect/auth?response_type=code&client_id=${CLIENT_ID}&state=${stateFixture}&code_challenge=challenge&code_challenge_method=S256`)
      ),
      buildEndSessionUrl: vi.fn().mockResolvedValue(
        new URL(`${ISSUER_URL}/protocol/openid-connect/logout?client_id=${CLIENT_ID}&post_logout_redirect_uri=${encodeURIComponent(`${ALLOWED_ORIGIN}/login`)}`),
      ),
      exchangeAuthorizationCode: vi.fn().mockResolvedValue(verifiedIdentity),
      clearCache: vi.fn(),
    };

    app = createApp(mockServices, { authConfig, oidcClient: mockOidcClient });
  });

  it('GET /api/v1/auth/login initiates flow, sets OIDC txn cookie, and redirects to IdP', async () => {
    const res = await request(app)
      .get('/api/v1/auth/login')
      .query({ returnTo: '/projects/00000000-0000-0000-0000-000000000001' });

    expect(res.status).toBe(302);
    expect(res.header['location']).toContain('response_type=code');
    expect(res.header['location']).toContain(ISSUER_URL);

    const setCookies = res.header['set-cookie'] as unknown as string[];
    expect(setCookies).toBeDefined();
    const txnCookieHeader = setCookies.find((c) => c.startsWith(`${COOKIE_NAME_DEV_OIDC_TXN}=`));
    expect(txnCookieHeader).toBeDefined();
    expect(txnCookieHeader).toContain(rawTxnToken);
    expect(txnCookieHeader).toContain('HttpOnly');
    expect(txnCookieHeader).toContain('SameSite=Lax');
  });

  it('GET /api/v1/auth/callback fails with HTTP 401 and clears cookie when txn cookie is missing', async () => {
    const res = await request(app)
      .get('/api/v1/auth/callback')
      .query({ code: 'auth_code_123', state: stateFixture });

    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('UNAUTHORIZED');

    const setCookies = res.header['set-cookie'] as unknown as string[];
    expect(setCookies).toBeDefined();
    const clearedCookie = setCookies.find((c) => c.startsWith(`${COOKIE_NAME_DEV_OIDC_TXN}=`));
    expect(clearedCookie).toContain('Max-Age=0');
    expect(mockAuthService.establishAuthenticatedSession).not.toHaveBeenCalled();
  });

  it('GET /api/v1/auth/callback completes exchange, sets session cookie, clears txn cookie, and returns JSON session data', async () => {
    const res = await request(app)
      .get('/api/v1/auth/callback')
      .set('Cookie', `${COOKIE_NAME_DEV_OIDC_TXN}=${rawTxnToken}`)
      .set('Accept', 'application/json')
      .query({ code: 'auth_code_123', state: stateFixture });

    expect(res.status).toBe(200);
    expect(res.body.data.sessionId).toBe('22222222-2222-4222-8222-222222222222');
    expect(res.body.data.csrfToken).toBe(validCsrfToken);
    expect(res.body.data.user.email).toBe('alice@secureflow.example');

    const setCookies = res.header['set-cookie'] as unknown as string[];
    const sessionCookie = setCookies.find((c) => c.startsWith(`${COOKIE_NAME_DEV_SESSION}=`));
    const clearTxn = setCookies.find((c) => c.startsWith(`${COOKIE_NAME_DEV_OIDC_TXN}=`));

    expect(sessionCookie).toBeDefined();
    expect(sessionCookie).toContain(rawSessionToken);
    expect(sessionCookie).toContain('HttpOnly');
    expect(clearTxn).toBeDefined();
    expect(clearTxn).toContain('Max-Age=0');
  });

  it('GET /api/v1/auth/me returns authenticated identity and session CSRF token with valid session cookie', async () => {
    const res = await request(app)
      .get('/api/v1/auth/me')
      .set('Cookie', `${COOKIE_NAME_DEV_SESSION}=${rawSessionToken}`);

    expect(res.status).toBe(200);
    expect(res.body.data.actor.id).toBe('33333333-3333-4333-8333-333333333333');
    expect(res.body.data.actor.globalRole).toBe('USER');
    expect(res.body.data.sessionId).toBe('22222222-2222-4222-8222-222222222222');
    expect(res.body.data.csrfToken).toBe(validCsrfToken);
  });

  it('GET /api/v1/auth/me rejects unauthenticated callers with HTTP 401', async () => {
    const res = await request(app).get('/api/v1/auth/me');
    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('UNAUTHORIZED');
  });

  it('POST /api/v1/auth/logout requires session authentication and anti-CSRF token, revokes session, and clears cookies', async () => {
    // 1. Missing CSRF token -> 403 Forbidden
    const noCsrfRes = await request(app)
      .post('/api/v1/auth/logout')
      .set('Cookie', `${COOKIE_NAME_DEV_SESSION}=${rawSessionToken}`)
      .set('Origin', ALLOWED_ORIGIN);

    expect(noCsrfRes.status).toBe(403);
    expect(noCsrfRes.body.error.code).toBe('FORBIDDEN');
    expect(mockAuthService.revokeSession).not.toHaveBeenCalled();

    // 2. Valid session and valid CSRF token -> 200 OK
    const validRes = await request(app)
      .post('/api/v1/auth/logout')
      .set('Cookie', `${COOKIE_NAME_DEV_SESSION}=${rawSessionToken}`)
      .set('Origin', ALLOWED_ORIGIN)
      .set('X-CSRF-Token', validCsrfToken);

    expect(validRes.status).toBe(200);
    expect(validRes.body.data.loggedOut).toBe(true);
    expect(validRes.body.data.endSessionUrl).toContain(`${ISSUER_URL}/protocol/openid-connect/logout`);
    expect(validRes.body.data.endSessionUrl).toContain(`client_id=${CLIENT_ID}`);
    expect(validRes.body.data.endSessionUrl).not.toContain('dev_secret_bff_client_1234567890');
    expect(validRes.body.data.endSessionUrl).not.toContain('id_token_hint');
    expect(mockAuthService.revokeSession).toHaveBeenCalledWith(
      expect.objectContaining({
        rawSessionToken,
        reason: 'USER_LOGOUT',
      }),
      expect.any(Date),
    );

    const setCookies = validRes.header['set-cookie'] as unknown as string[];
    const clearedSession = setCookies.find((c) => c.startsWith(`${COOKIE_NAME_DEV_SESSION}=`));
    const clearedTxn = setCookies.find((c) => c.startsWith(`${COOKIE_NAME_DEV_OIDC_TXN}=`));
    expect(clearedSession).toContain('Max-Age=0');
    expect(clearedTxn).toContain('Max-Age=0');

    // 3. Rejects unallowlisted postLogoutRedirectUri with 400 without revoking session
    vi.mocked(mockAuthService.revokeSession).mockClear();
    const badRedirectRes = await request(app)
      .post('/api/v1/auth/logout')
      .set('Cookie', `${COOKIE_NAME_DEV_SESSION}=${rawSessionToken}`)
      .set('Origin', ALLOWED_ORIGIN)
      .set('X-CSRF-Token', validCsrfToken)
      .send({ postLogoutRedirectUri: 'https://evil.example/redirect' });

    expect(badRedirectRes.status).toBe(400);
    expect(mockAuthService.revokeSession).not.toHaveBeenCalled();

    // 4. Local PostgreSQL revocation and cookie clearing still succeed when IdP end_session discovery fails transiently
    vi.mocked(mockOidcClient.buildEndSessionUrl).mockRejectedValueOnce(new Error('IdP unreachable'));
    const resilientRes = await request(app)
      .post('/api/v1/auth/logout')
      .set('Cookie', `${COOKIE_NAME_DEV_SESSION}=${rawSessionToken}`)
      .set('Origin', ALLOWED_ORIGIN)
      .set('X-CSRF-Token', validCsrfToken);

    expect(resilientRes.status).toBe(200);
    expect(resilientRes.body.data).toEqual({
      loggedOut: true,
      endSessionUrl: null,
    });
    expect(mockAuthService.revokeSession).toHaveBeenCalledTimes(1);
  });

  it('protects operational REST endpoints with session authentication and enforces CSRF on mutations', async () => {
    // 1. Unauthenticated GET /api/v1/projects -> 401
    const unauthRes = await request(app).get('/api/v1/projects');
    expect(unauthRes.status).toBe(401);
    expect(mockServices.projectService.listProjects).not.toHaveBeenCalled();

    // 2. Authenticated GET /api/v1/projects -> succeeds without CSRF header (safe read)
    const authReadRes = await request(app)
      .get('/api/v1/projects')
      .set('Cookie', `${COOKIE_NAME_DEV_SESSION}=${rawSessionToken}`);
    expect(authReadRes.status).toBe(200);
    expect(mockServices.projectService.listProjects).toHaveBeenCalledWith(
      expect.objectContaining({ id: '33333333-3333-4333-8333-333333333333' }),
      expect.any(Object),
    );

    // 3. Authenticated mutation POST /api/v1/projects WITHOUT CSRF token -> 403 Forbidden
    const noCsrfMutation = await request(app)
      .post('/api/v1/projects')
      .set('Cookie', `${COOKIE_NAME_DEV_SESSION}=${rawSessionToken}`)
      .set('Origin', ALLOWED_ORIGIN)
      .send({ name: 'CSRF Blocked Project' });
    expect(noCsrfMutation.status).toBe(403);
    expect(noCsrfMutation.body.error.code).toBe('FORBIDDEN');
    expect(mockServices.projectService.createProject).not.toHaveBeenCalled();

    // 4. Authenticated mutation POST /api/v1/projects WITH CSRF token -> 201 Created
    const validMutation = await request(app)
      .post('/api/v1/projects')
      .set('Cookie', `${COOKIE_NAME_DEV_SESSION}=${rawSessionToken}`)
      .set('Origin', ALLOWED_ORIGIN)
      .set('X-CSRF-Token', validCsrfToken)
      .send({ name: 'Valid Project' });
    expect(validMutation.status).toBe(201);
    expect(mockServices.projectService.createProject).toHaveBeenCalledWith(
      expect.objectContaining({ id: '33333333-3333-4333-8333-333333333333' }),
      expect.objectContaining({ name: 'Valid Project' }),
    );
  });

  it('rejects client-supplied spoofing headers and verifies identity strictly from session cookie', async () => {
    const spoofRes = await request(app)
      .get('/api/v1/projects')
      .set('x-user-id', '00000000-0000-0000-0000-000000000001')
      .set('x-actor-role', 'ADMIN')
      .set('Authorization', 'Bearer fake-jwt-token');

    expect(spoofRes.status).toBe(401);
    expect(spoofRes.body.error.code).toBe('UNAUTHORIZED');
    expect(mockServices.projectService.listProjects).not.toHaveBeenCalled();
  });

  it('fails closed on POST /api/v1/auth/logout before JSON body parsing when unauthenticated (401) or missing CSRF token (403)', async () => {
    const unauthMalformedRes = await request(app)
      .post('/api/v1/auth/logout')
      .set('Content-Type', 'application/json')
      .send('{broken-json');

    expect(unauthMalformedRes.status).toBe(401);
    expect(unauthMalformedRes.body.error.code).toBe('UNAUTHORIZED');
    expect(mockAuthService.revokeSession).not.toHaveBeenCalled();

    const noCsrfMalformedRes = await request(app)
      .post('/api/v1/auth/logout')
      .set('Cookie', `${COOKIE_NAME_DEV_SESSION}=${rawSessionToken}`)
      .set('Origin', ALLOWED_ORIGIN)
      .set('Content-Type', 'application/json')
      .send('{broken-json');

    expect(noCsrfMalformedRes.status).toBe(403);
    expect(noCsrfMalformedRes.body.error.code).toBe('FORBIDDEN');
    expect(mockAuthService.revokeSession).not.toHaveBeenCalled();
  });

  it('enforces __Host- cookies in production mode and rejects development cookie downgrade', async () => {
    const prodOrigin = 'https://app.secureflow.example';
    const prodConfig: AuthRuntimeConfig = {
      mode: 'production',
      authEnabled: true,
      oidc: {
        issuerUrl: 'https://idp.secureflow.example/realms/secureflow',
        clientId: CLIENT_ID,
        clientSecret: 'prod_secret_bff_client_value_over_32_characters',
        clientAuthMethod: 'client_secret_basic',
        redirectUri: 'https://api.secureflow.example/api/v1/auth/callback',
        allowedRedirectUris: ['https://api.secureflow.example/api/v1/auth/callback'],
        postLogoutRedirectUri: `${prodOrigin}/login`,
        allowedPostLogoutRedirectUris: [`${prodOrigin}/login`],
        scopes: 'openid email profile',
        clockToleranceSeconds: 30,
        allowInsecureHttp: false,
        requestTimeoutSeconds: 5,
      },
      session: {
        idleTimeoutSeconds: 1800,
        absoluteTimeoutSeconds: 28800,
        oidcTxnTtlSeconds: 300,
      },
      cookies: {
        mode: 'production',
        sessionCookieName: COOKIE_NAME_PRODUCTION_SESSION,
        oidcTxnCookieName: COOKIE_NAME_PRODUCTION_OIDC_TXN,
        secure: true,
        httpOnly: true,
        sameSite: 'Lax',
        path: '/',
      },
      allowedOrigins: [prodOrigin],
    };

    const prodApp = createApp(mockServices, { authConfig: prodConfig, oidcClient: mockOidcClient });

    // Downgraded dev cookie name must fail closed with 401 in production mode
    const downgradeRes = await request(prodApp)
      .get('/api/v1/auth/me')
      .set('Cookie', `${COOKIE_NAME_DEV_SESSION}=${rawSessionToken}`);
    expect(downgradeRes.status).toBe(401);

    // /login emits __Host-sf_oidc_txn with Secure; HttpOnly; SameSite=Lax; Path=/ and NO Domain
    const prodLoginRes = await request(prodApp).get('/api/v1/auth/login');
    expect(prodLoginRes.status).toBe(302);
    const loginSetCookies = prodLoginRes.header['set-cookie'] as unknown as string[];
    const prodTxnHeader = loginSetCookies.find((c) => c.startsWith(`${COOKIE_NAME_PRODUCTION_OIDC_TXN}=`));
    expect(prodTxnHeader).toBeDefined();
    expect(prodTxnHeader).toContain('Secure');
    expect(prodTxnHeader).toContain('HttpOnly');
    expect(prodTxnHeader).toContain('SameSite=Lax');
    expect(prodTxnHeader).toContain('Path=/');
    expect(prodTxnHeader).not.toMatch(/;\s*Domain=/i);

    // Valid __Host-sf_session succeeds on /me
    const validProdMe = await request(prodApp)
      .get('/api/v1/auth/me')
      .set('Cookie', `${COOKIE_NAME_PRODUCTION_SESSION}=${rawSessionToken}`);
    expect(validProdMe.status).toBe(200);
  });

  it('rejects duplicate session cookies with 401 and clears OIDC transaction cookie cleanly on callback URL or exchange error', async () => {
    const duplicateCookieRes = await request(app)
      .get('/api/v1/auth/me')
      .set('Cookie', `${COOKIE_NAME_DEV_SESSION}=${rawSessionToken}; ${COOKIE_NAME_DEV_SESSION}=second_token`);

    expect(duplicateCookieRes.status).toBe(401);
    expect(duplicateCookieRes.body.error.code).toBe('UNAUTHORIZED');

    // Malformed Host header during /callback clears txn cookie and fails with 400 (no 500 leak)
    const malformedHostRes = await request(app)
      .get('/api/v1/auth/callback')
      .set('Host', 'invalid host with spaces')
      .set('Cookie', `${COOKIE_NAME_DEV_OIDC_TXN}=${rawTxnToken}`)
      .query({ code: 'auth_code_123', state: stateFixture });

    expect(malformedHostRes.status).toBe(400);
    expect(malformedHostRes.body.error.code).toBe('VALIDATION_ERROR');
    const hostErrCookies = malformedHostRes.header['set-cookie'] as unknown as string[];
    const clearedTxn = hostErrCookies.find((c) => c.startsWith(`${COOKIE_NAME_DEV_OIDC_TXN}=`));
    expect(clearedTxn).toContain('Max-Age=0');
    expect(hostErrCookies.some((c) => c.startsWith(`${COOKIE_NAME_DEV_SESSION}=`))).toBe(false);
  });
});
