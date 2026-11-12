import path from 'node:path';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import request from 'supertest';
import type { Express } from 'express';
import {
  createDomainServices,
  type DomainServices,
  hashOpaqueToken,
  generateOpaqueToken,
} from '@secureflow/domain';
import {
  createTestDatabaseClient,
  validateTestDatabaseUrl,
  type TestDatabaseClient,
} from '@secureflow/domain/testing';
import { createApp } from '../../src/app.js';
import { OpenIdConnectClient } from '../../src/auth/oidc-client.js';
import type { AuthRuntimeConfig } from '../../src/config/auth.js';
import { COOKIE_NAME_DEV_SESSION, COOKIE_NAME_DEV_OIDC_TXN } from '../../src/auth/cookies.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
dotenv.config({ path: path.resolve(__dirname, '../../../../.env') });
dotenv.config({ path: path.resolve(__dirname, '../../../.env') });

function requireEnvVar(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) {
    throw new Error(
      `Required environment variable '${name}' must be set in gitignored local .env for Keycloak integration tests`,
    );
  }
  return value;
}

const KEYCLOAK_ISSUER = process.env['OIDC_ISSUER_URL']?.trim() || 'http://127.0.0.1:8080/realms/secureflow';
const CLIENT_ID = process.env['OIDC_CLIENT_ID']?.trim() || 'secureflow-bff';
const CLIENT_SECRET = requireEnvVar('OIDC_CLIENT_SECRET');
const DEV_DEVELOPER_PASSWORD = requireEnvVar('KEYCLOAK_DEV_DEVELOPER_PASSWORD');
const DEV_ANALYST_PASSWORD = requireEnvVar('KEYCLOAK_DEV_ANALYST_PASSWORD');
const REDIRECT_URI = 'http://127.0.0.1:3000/api/v1/auth/callback';
const POST_LOGOUT_REDIRECT_URI = 'http://127.0.0.1:5173/login';
const ALLOWED_ORIGIN = 'http://localhost:5173';

function createIntegrationAuthConfig(): AuthRuntimeConfig {
  return {
    mode: 'development',
    authEnabled: true,
    oidc: {
      issuerUrl: KEYCLOAK_ISSUER,
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      clientAuthMethod: 'client_secret_basic',
      redirectUri: REDIRECT_URI,
      allowedRedirectUris: [REDIRECT_URI],
      postLogoutRedirectUri: POST_LOGOUT_REDIRECT_URI,
      allowedPostLogoutRedirectUris: [POST_LOGOUT_REDIRECT_URI],
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
    allowedOrigins: [ALLOWED_ORIGIN, 'http://127.0.0.1:3000'],
  };
}

function updateCookieJar(jar: Map<string, string>, res: globalThis.Response): void {
  const setCookies = res.headers.getSetCookie
    ? res.headers.getSetCookie()
    : [res.headers.get('set-cookie') as string];
  for (const rawPair of setCookies.filter(Boolean)) {
    const kv = rawPair.split(';')[0] ?? '';
    const eqIdx = kv.indexOf('=');
    if (eqIdx <= 0) continue;
    const name = kv.slice(0, eqIdx).trim();
    const value = kv.slice(eqIdx + 1).trim();
    const lowerRaw = rawPair.toLowerCase();
    if (!value || lowerRaw.includes('max-age=0') || lowerRaw.includes('expires=thu, 01 jan 1970')) {
      jar.delete(name);
    } else {
      jar.set(name, value);
    }
  }
}

function serializeCookieJar(jar: Map<string, string>): string {
  return Array.from(jar.entries())
    .map(([k, v]) => `${k}=${v}`)
    .join('; ');
}

/**
 * Headless Keycloak HTML login helper.
 * Simulates browser user authentication against Keycloak's login form to obtain an authorization code.
 */
async function authenticateKeycloakUser(
  authUrlString: string,
  username: string,
  password: string,
): Promise<{
  locationUrl: URL;
  code: string;
  state: string;
  iss: string;
  sessionState: string;
  keycloakCookieJar: Map<string, string>;
}> {
  const cookieJar = new Map<string, string>();
  const pageRes = await fetch(authUrlString, { redirect: 'manual' });
  updateCookieJar(cookieJar, pageRes);

  const html = await pageRes.text();
  const match = html.match(/action="([^"]+)"/);
  if (!match) {
    throw new Error(`Failed to find login form in Keycloak response: ${html.slice(0, 300)}`);
  }
  const actionUrl = match[1].replace(/&amp;/g, '&');

  const loginBody = new URLSearchParams({ username, password });
  const loginRes = await fetch(actionUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Cookie': serializeCookieJar(cookieJar),
    },
    body: loginBody.toString(),
    redirect: 'manual',
  });

  updateCookieJar(cookieJar, loginRes);

  const location = loginRes.headers.get('location');
  if (!location) {
    throw new Error(`Keycloak login did not redirect; status: ${loginRes.status}`);
  }

  const locUrl = new URL(location);
  const code = locUrl.searchParams.get('code');
  const state = locUrl.searchParams.get('state');
  const iss = locUrl.searchParams.get('iss') ?? KEYCLOAK_ISSUER;
  const sessionState = locUrl.searchParams.get('session_state') ?? '';
  if (!code || !state) {
    throw new Error(`Missing code or state in Keycloak redirect: ${location}`);
  }
  return { locationUrl: locUrl, code, state, iss, sessionState, keycloakCookieJar: cookieJar };
}

describe('Gate 4B.3 Real Keycloak & Integrated BFF Authentication Integration Suite', () => {
  let domainServices: DomainServices;
  let testDbClient: TestDatabaseClient;
  let authConfig: AuthRuntimeConfig;
  let app: Express;

  const createdUserIds = new Set<string>();
  const createdSessionIds = new Set<string>();
  const createdOidcTxnIds = new Set<string>();
  const createdProjectIds = new Set<string>();
  const createdFindingIds = new Set<string>();

  let initialTableCounts: Record<string, number>;
  let initialMaxAuditCreatedAt: Date;

  beforeAll(async () => {
    const rawTestUrl = validateTestDatabaseUrl(process.env['TEST_DATABASE_URL']);
    testDbClient = await createTestDatabaseClient(rawTestUrl);
    domainServices = createDomainServices({
      connectionString: rawTestUrl,
      maxConnections: 5,
      connectionTimeoutMillis: 5000,
      statementTimeoutMillis: 10000,
    });

    authConfig = createIntegrationAuthConfig();
    app = createApp(domainServices, { authConfig });

    // Snapshot baseline counts before test execution
    const [
      users,
      userSessions,
      oidcTxns,
      projects,
      projectMembers,
      findings,
      tasks,
      findingEvents,
      auditEvents,
      maxAuditRes,
    ] = await Promise.all([
      testDbClient.query<{ count: string }>('SELECT COUNT(*) FROM public.users;'),
      testDbClient.query<{ count: string }>('SELECT COUNT(*) FROM public.user_sessions;'),
      testDbClient.query<{ count: string }>('SELECT COUNT(*) FROM public.oidc_transactions;'),
      testDbClient.query<{ count: string }>('SELECT COUNT(*) FROM public.projects;'),
      testDbClient.query<{ count: string }>('SELECT COUNT(*) FROM public.project_members;'),
      testDbClient.query<{ count: string }>('SELECT COUNT(*) FROM public.findings;'),
      testDbClient.query<{ count: string }>('SELECT COUNT(*) FROM public.remediation_tasks;'),
      testDbClient.query<{ count: string }>('SELECT COUNT(*) FROM public.finding_events;'),
      testDbClient.query<{ count: string }>('SELECT COUNT(*) FROM public.audit_events;'),
      testDbClient.query<{ max_created: Date | null }>('SELECT MAX(created_at) AS max_created FROM public.audit_events;'),
    ]);

    initialMaxAuditCreatedAt = maxAuditRes.rows[0]?.max_created ?? new Date(0);

    initialTableCounts = {
      users: parseInt(users.rows[0]?.count ?? '0', 10),
      user_sessions: parseInt(userSessions.rows[0]?.count ?? '0', 10),
      oidc_transactions: parseInt(oidcTxns.rows[0]?.count ?? '0', 10),
      projects: parseInt(projects.rows[0]?.count ?? '0', 10),
      project_members: parseInt(projectMembers.rows[0]?.count ?? '0', 10),
      findings: parseInt(findings.rows[0]?.count ?? '0', 10),
      remediation_tasks: parseInt(tasks.rows[0]?.count ?? '0', 10),
      finding_events: parseInt(findingEvents.rows[0]?.count ?? '0', 10),
      audit_events: parseInt(auditEvents.rows[0]?.count ?? '0', 10),
    };
  });

  afterAll(async () => {
    // Cleanup created test artifacts in strict dependency order:
    // 1. Projects and project members
    if (createdProjectIds.size > 0) {
      const ids = Array.from(createdProjectIds);
      await testDbClient.query('DELETE FROM public.project_members WHERE project_id = ANY($1)', [ids]);
      await testDbClient.query('DELETE FROM public.projects WHERE id = ANY($1)', [ids]);
    }

    // 2. Findings and finding events
    if (createdFindingIds.size > 0) {
      const ids = Array.from(createdFindingIds);
      await testDbClient.query('DELETE FROM public.finding_events WHERE finding_id = ANY($1)', [ids]);
      await testDbClient.query('DELETE FROM public.remediation_tasks WHERE finding_id = ANY($1)', [ids]);
      await testDbClient.query('DELETE FROM public.findings WHERE id = ANY($1)', [ids]);
    }

    // 3. User sessions
    if (createdSessionIds.size > 0) {
      await testDbClient.query('DELETE FROM public.user_sessions WHERE id = ANY($1)', [Array.from(createdSessionIds)]);
    }

    // 4. OIDC transactions
    if (createdOidcTxnIds.size > 0) {
      await testDbClient.query('DELETE FROM public.oidc_transactions WHERE id = ANY($1)', [Array.from(createdOidcTxnIds)]);
    }

    // 5. Audit events created during test run
    if (initialMaxAuditCreatedAt) {
      await testDbClient.query('DELETE FROM public.audit_events WHERE created_at > $1;', [initialMaxAuditCreatedAt]);
    }

    // 6. Users deleted AFTER all referencing audit events are gone
    if (createdUserIds.size > 0) {
      await testDbClient.query('DELETE FROM public.users WHERE id = ANY($1)', [Array.from(createdUserIds)]);
    }

    // Verify baseline fixture preservation
    const [
      users,
      userSessions,
      oidcTxns,
      projects,
      findings,
      tasks,
      auditEvents,
    ] = await Promise.all([
      testDbClient.query<{ count: string }>('SELECT COUNT(*) FROM public.users;'),
      testDbClient.query<{ count: string }>('SELECT COUNT(*) FROM public.user_sessions;'),
      testDbClient.query<{ count: string }>('SELECT COUNT(*) FROM public.oidc_transactions;'),
      testDbClient.query<{ count: string }>('SELECT COUNT(*) FROM public.projects;'),
      testDbClient.query<{ count: string }>('SELECT COUNT(*) FROM public.findings;'),
      testDbClient.query<{ count: string }>('SELECT COUNT(*) FROM public.remediation_tasks;'),
      testDbClient.query<{ count: string }>('SELECT COUNT(*) FROM public.audit_events;'),
    ]);

    expect(parseInt(users.rows[0]?.count ?? '0', 10)).toBe(initialTableCounts.users);
    expect(parseInt(userSessions.rows[0]?.count ?? '0', 10)).toBe(initialTableCounts.user_sessions);
    expect(parseInt(oidcTxns.rows[0]?.count ?? '0', 10)).toBe(initialTableCounts.oidc_transactions);
    expect(parseInt(projects.rows[0]?.count ?? '0', 10)).toBe(initialTableCounts.projects);
    expect(parseInt(findings.rows[0]?.count ?? '0', 10)).toBe(initialTableCounts.findings);
    expect(parseInt(tasks.rows[0]?.count ?? '0', 10)).toBe(initialTableCounts.remediation_tasks);
    expect(parseInt(auditEvents.rows[0]?.count ?? '0', 10)).toBe(initialTableCounts.audit_events);

    await domainServices.close();
    await testDbClient.close();
  });

  it('1. Live OIDC discovery: retrieves server metadata and validates PKCE S256 support', async () => {
    const oidcClient = new OpenIdConnectClient(authConfig.oidc);
    const summary = await oidcClient.discover();

    expect(summary.issuer).toBe(KEYCLOAK_ISSUER);
    expect(summary.authorizationEndpoint).toBe(`${KEYCLOAK_ISSUER}/protocol/openid-connect/auth`);
    expect(summary.tokenEndpoint).toBe(`${KEYCLOAK_ISSUER}/protocol/openid-connect/token`);
    expect(summary.jwksUri).toBe(`${KEYCLOAK_ISSUER}/protocol/openid-connect/certs`);
    expect(summary.supportsPkceS256).toBe(true);
  });

  let liveSessionCookie = '';
  let liveRawSessionToken = '';
  let liveSessionId = '';
  let liveCsrfToken = '';
  let liveUserId = '';
  let liveTxnToken = '';
  let liveCode = '';
  let liveState = '';
  let liveCallbackQuery = '';
  let liveKeycloakCookieJar = new Map<string, string>();

  it('2. End-to-end OIDC flow: initiates login, authenticates against Keycloak, and establishes session', async () => {
    // A. Initiate login on Express BFF
    const loginRes = await request(app)
      .get('/api/v1/auth/login')
      .query({ returnTo: '/projects' });

    expect(loginRes.status).toBe(302);
    const authUrlString = loginRes.header['location'] as string;
    expect(authUrlString).toContain(KEYCLOAK_ISSUER);
    expect(authUrlString).toContain('response_type=code');
    expect(authUrlString).toContain('code_challenge_method=S256');

    // Extract txn cookie
    const setCookies = loginRes.header['set-cookie'] as unknown as string[];
    const txnCookieHeader = setCookies.find((c) => c.startsWith(`${COOKIE_NAME_DEV_OIDC_TXN}=`));
    expect(txnCookieHeader).toBeDefined();
    liveTxnToken = txnCookieHeader!.split(';')[0]!.split('=')[1]!;
    expect(liveTxnToken.length).toBeGreaterThan(20);

    // Track created OIDC transaction in PostgreSQL for cleanup
    const hashedTxnToken = hashOpaqueToken(liveTxnToken);
    const txnRecord = await testDbClient.query<{ id: string }>(
      'SELECT id FROM public.oidc_transactions WHERE txn_token_hash = $1;',
      [hashedTxnToken],
    );
    expect(txnRecord.rows.length).toBe(1);
    createdOidcTxnIds.add(txnRecord.rows[0]!.id);

    // B. Authenticate against Keycloak via headless form post
    const authResult = await authenticateKeycloakUser(
      authUrlString,
      'dev@secureflow.example',
      DEV_DEVELOPER_PASSWORD,
    );
    liveCode = authResult.code;
    liveState = authResult.state;
    liveCallbackQuery = authResult.locationUrl.searchParams.toString();
    liveKeycloakCookieJar = authResult.keycloakCookieJar;
    expect(liveCode).toBeDefined();
    expect(liveState).toBeDefined();
    expect(liveKeycloakCookieJar.has('KEYCLOAK_IDENTITY')).toBe(true);
    expect(liveKeycloakCookieJar.has('KEYCLOAK_SESSION')).toBe(true);

    // C. Complete callback on Express BFF
    const callbackRes = await request(app)
      .get(`/api/v1/auth/callback?${liveCallbackQuery}`)
      .set('Host', '127.0.0.1:3000')
      .set('Cookie', `${COOKIE_NAME_DEV_OIDC_TXN}=${liveTxnToken}`)
      .set('Accept', 'application/json');

    expect(callbackRes.status).toBe(200);
    expect(callbackRes.body.data).toBeDefined();
    expect(callbackRes.body.data.sessionId).toBeDefined();
    expect(callbackRes.body.data.csrfToken).toBeDefined();
    expect(callbackRes.body.data.user.email).toBe('dev@secureflow.example');
    expect(callbackRes.body.data.user.globalRole).toBe('DEVELOPER');
    expect(callbackRes.body.data.returnTo).toBe('/projects');

    liveSessionId = callbackRes.body.data.sessionId;
    liveCsrfToken = callbackRes.body.data.csrfToken;
    liveUserId = callbackRes.body.data.user.id;
    createdSessionIds.add(liveSessionId);
    createdUserIds.add(liveUserId);

    // Check cookies: sf_session is set, sf_oidc_txn is cleared
    const callbackCookies = callbackRes.header['set-cookie'] as unknown as string[];
    const sessionCookieHeader = callbackCookies.find((c) => c.startsWith(`${COOKIE_NAME_DEV_SESSION}=`));
    const clearedTxnHeader = callbackCookies.find((c) => c.startsWith(`${COOKIE_NAME_DEV_OIDC_TXN}=`));

    expect(sessionCookieHeader).toBeDefined();
    expect(sessionCookieHeader).toContain('HttpOnly');
    expect(clearedTxnHeader).toBeDefined();
    expect(clearedTxnHeader).toContain('Max-Age=0');

    liveSessionCookie = sessionCookieHeader!.split(';')[0]!;
    liveRawSessionToken = liveSessionCookie.split('=')[1]!;

    // Verify PostgreSQL records
    const sessionRow = await testDbClient.query<{ id: string; user_id: string; csrf_token: string; revoked_at: Date | null }>(
      'SELECT id, user_id, csrf_token, revoked_at FROM public.user_sessions WHERE id = $1;',
      [liveSessionId],
    );
    expect(sessionRow.rows.length).toBe(1);
    expect(sessionRow.rows[0]!.user_id).toBe(liveUserId);
    expect(sessionRow.rows[0]!.csrf_token).toBe(liveCsrfToken);
    expect(sessionRow.rows[0]!.revoked_at).toBeNull();

    const userRow = await testDbClient.query<{ id: string; email: string; is_active: boolean; global_role: string }>(
      'SELECT id, email, is_active, global_role FROM public.users WHERE id = $1;',
      [liveUserId],
    );
    expect(userRow.rows.length).toBe(1);
    expect(userRow.rows[0]!.email.toLowerCase()).toBe('dev@secureflow.example');
    expect(userRow.rows[0]!.is_active).toBe(true);
  });

  it('3. Replay attack rejection: single-use transaction and authorization code cannot be reused', async () => {
    // Attempt callback replay with same transaction cookie and code -> 401
    const replayRes = await request(app)
      .get(`/api/v1/auth/callback?${liveCallbackQuery}`)
      .set('Host', '127.0.0.1:3000')
      .set('Cookie', `${COOKIE_NAME_DEV_OIDC_TXN}=${liveTxnToken}`)
      .set('Accept', 'application/json');

    expect(replayRes.status).toBe(401);
    expect(replayRes.body.error.code).toBe('UNAUTHORIZED');

    // Confirm that transaction record in PostgreSQL remains consumed
    const txnRecord = await testDbClient.query<{ consumed_at: Date | null }>(
      'SELECT consumed_at FROM public.oidc_transactions WHERE id = ANY($1);',
      [Array.from(createdOidcTxnIds)],
    );
    expect(txnRecord.rows[0]!.consumed_at).not.toBeNull();
  });

  it('4. State mismatch & missing transaction cookie rejection', async () => {
    // A. Mismatched state -> 401
    const mismatchedStateRes = await request(app)
      .get('/api/v1/auth/callback')
      .set('Host', '127.0.0.1:3000')
      .set('Cookie', `${COOKIE_NAME_DEV_OIDC_TXN}=${liveTxnToken}`)
      .query({ code: 'forged_code_123', state: 'forged_state_mismatch_456' });

    expect(mismatchedStateRes.status).toBe(401);
    expect(mismatchedStateRes.body.error.code).toBe('UNAUTHORIZED');

    // B. Missing transaction cookie -> 401
    const noCookieRes = await request(app)
      .get('/api/v1/auth/callback')
      .set('Host', '127.0.0.1:3000')
      .query({ code: 'some_code', state: 'some_state' });

    expect(noCookieRes.status).toBe(401);
    expect(noCookieRes.body.error.code).toBe('UNAUTHORIZED');
  });

  it('5. GET /api/v1/auth/me returns identity, role, and CSRF token when authenticated', async () => {
    // Unauthenticated call -> 401
    const unauthRes = await request(app).get('/api/v1/auth/me');
    expect(unauthRes.status).toBe(401);
    expect(unauthRes.body.error.code).toBe('UNAUTHORIZED');

    // Authenticated call with session cookie -> 200
    const authRes = await request(app)
      .get('/api/v1/auth/me')
      .set('Cookie', liveSessionCookie);

    expect(authRes.status).toBe(200);
    expect(authRes.body.data.actor.id).toBe(liveUserId);
    expect(authRes.body.data.actor.globalRole).toBe('DEVELOPER');
    expect(authRes.body.data.sessionId).toBe(liveSessionId);
    expect(authRes.body.data.csrfToken).toBe(liveCsrfToken);
  });

  it('6. Operational REST mutation with CSRF protection: POST /api/v1/projects requires session and CSRF token', async () => {
    const projectName = `Gate 4B.3 Project ${Date.now()}`;
    const adminUserId = '59c69e57-4a9f-42fd-8e6b-40a357ca9cb5';
    const adminRawToken = generateOpaqueToken(32);
    const adminTokenHash = hashOpaqueToken(adminRawToken);
    const adminSessionId = '11111111-2222-3333-4444-555555555555';
    const adminCsrfToken = 'admin_csrf_token_for_projects';

    await testDbClient.query(
      `INSERT INTO public.user_sessions (
        id, user_id, session_token_hash, csrf_token, ip_address, user_agent,
        created_at, last_active_at, idle_expires_at, expires_at
      ) VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW(), NOW() + INTERVAL '30 minutes', NOW() + INTERVAL '8 hours');`,
      [adminSessionId, adminUserId, adminTokenHash, adminCsrfToken, '127.0.0.1', 'Vitest'],
    );
    createdSessionIds.add(adminSessionId);

    // A. Missing CSRF header -> 403 Forbidden
    const noCsrfRes = await request(app)
      .post('/api/v1/projects')
      .set('Cookie', `${COOKIE_NAME_DEV_SESSION}=${adminRawToken}`)
      .set('Origin', ALLOWED_ORIGIN)
      .send({ name: projectName });

    expect(noCsrfRes.status).toBe(403);
    expect(noCsrfRes.body.error.code).toBe('FORBIDDEN');

    // B. Invalid / forged CSRF header -> 403 Forbidden
    const invalidCsrfRes = await request(app)
      .post('/api/v1/projects')
      .set('Cookie', `${COOKIE_NAME_DEV_SESSION}=${adminRawToken}`)
      .set('Origin', ALLOWED_ORIGIN)
      .set('X-CSRF-Token', 'forged_invalid_csrf_token_value')
      .send({ name: projectName });

    expect(invalidCsrfRes.status).toBe(403);
    expect(invalidCsrfRes.body.error.code).toBe('FORBIDDEN');

    // C. Untrusted origin -> 403 Forbidden (CORS)
    const badOriginRes = await request(app)
      .post('/api/v1/projects')
      .set('Cookie', `${COOKIE_NAME_DEV_SESSION}=${adminRawToken}`)
      .set('Origin', 'http://malicious-attacker.example.com')
      .set('X-CSRF-Token', adminCsrfToken)
      .send({ name: projectName });

    expect(badOriginRes.status).toBe(403);

    // D. Valid session, valid CSRF token, and allowed origin -> 201 Created
    const validRes = await request(app)
      .post('/api/v1/projects')
      .set('Cookie', `${COOKIE_NAME_DEV_SESSION}=${adminRawToken}`)
      .set('Origin', ALLOWED_ORIGIN)
      .set('X-CSRF-Token', adminCsrfToken)
      .send({ name: projectName, description: 'Created in Gate 4B.3 real Keycloak test' });

    expect(validRes.status).toBe(201);
    expect(validRes.body.data.name).toBe(projectName);
    createdProjectIds.add(validRes.body.data.id);
  });

  it('7. Session revocation / Logout: POST /api/v1/auth/logout revokes BFF session, completes Keycloak SSO logout (with confirmation), and terminates silent SSO', async () => {
    async function initiateTrackedAuthorization(returnTo: string): Promise<URL> {
      const loginRes = await request(app).get('/api/v1/auth/login').query({ returnTo });
      expect(loginRes.status).toBe(302);
      const setCookies = (loginRes.header['set-cookie'] as unknown as string[] | undefined) ?? [];
      const txnCookieHeader = setCookies.find((c) => c.startsWith(`${COOKIE_NAME_DEV_OIDC_TXN}=`));
      expect(txnCookieHeader).toBeDefined();
      const rawTxnToken = txnCookieHeader!.split(';')[0]!.split('=')[1]!;
      const txnRow = await testDbClient.query<{ id: string }>(
        'SELECT id FROM public.oidc_transactions WHERE txn_token_hash = $1;',
        [hashOpaqueToken(rawTxnToken)],
      );
      expect(txnRow.rows.length).toBe(1);
      createdOidcTxnIds.add(txnRow.rows[0]!.id);
      return new URL(loginRes.header['location'] as string);
    }

    // A. Baseline proof BEFORE logout: preserved browser Keycloak SSO cookies silently authenticate (prompt=none -> 302 ?code=...)
    const preLogoutAuthUrl = await initiateTrackedAuthorization('/pre-logout-sso-check');
    const preLogoutSilentUrl = new URL(preLogoutAuthUrl.toString());
    preLogoutSilentUrl.searchParams.set('prompt', 'none');
    const preLogoutSsoRes = await fetch(preLogoutSilentUrl.toString(), {
      method: 'GET',
      headers: { Cookie: serializeCookieJar(liveKeycloakCookieJar) },
      redirect: 'manual',
    });
    expect(preLogoutSsoRes.status).toBe(302);
    const preLogoutLoc = new URL(preLogoutSsoRes.headers.get('location') as string);
    expect(preLogoutLoc.searchParams.get('error')).toBeNull();
    expect(preLogoutLoc.searchParams.get('code')).toBeTruthy();

    const preLogoutKeycloakCookieHeader = serializeCookieJar(liveKeycloakCookieJar);

    // B. Logout without CSRF token -> 403
    const noCsrfLogout = await request(app)
      .post('/api/v1/auth/logout')
      .set('Cookie', liveSessionCookie)
      .set('Origin', ALLOWED_ORIGIN);

    expect(noCsrfLogout.status).toBe(403);

    // C. Unallowlisted postLogoutRedirectUri -> 400 without revoking active session
    const evilLogoutRes = await request(app)
      .post('/api/v1/auth/logout')
      .set('Cookie', liveSessionCookie)
      .set('Origin', ALLOWED_ORIGIN)
      .set('X-CSRF-Token', liveCsrfToken)
      .send({ postLogoutRedirectUri: 'https://evil.example/logout' });

    expect(evilLogoutRes.status).toBe(400);

    // D. Logout with valid session and CSRF token -> 200 OK with allowlisted RP-initiated endSessionUrl
    const validLogout = await request(app)
      .post('/api/v1/auth/logout')
      .set('Cookie', liveSessionCookie)
      .set('Origin', ALLOWED_ORIGIN)
      .set('X-CSRF-Token', liveCsrfToken);

    expect(validLogout.status).toBe(200);
    expect(validLogout.body.data.loggedOut).toBe(true);
    expect(typeof validLogout.body.data.endSessionUrl).toBe('string');

    const parsedEndSession = new URL(validLogout.body.data.endSessionUrl as string);
    expect(`${parsedEndSession.origin}${parsedEndSession.pathname}`).toBe(
      `${KEYCLOAK_ISSUER}/protocol/openid-connect/logout`,
    );
    expect(parsedEndSession.searchParams.get('client_id')).toBe(CLIENT_ID);
    expect(parsedEndSession.searchParams.get('post_logout_redirect_uri')).toBe(
      POST_LOGOUT_REDIRECT_URI,
    );
    expect(authConfig.oidc.allowedPostLogoutRedirectUris).toContain(
      parsedEndSession.searchParams.get('post_logout_redirect_uri'),
    );
    expect(parsedEndSession.searchParams.has('id_token_hint')).toBe(false);

    // Ensure zero secrets, tokens, or session cookies appear in response body or URL
    for (const sensitive of [CLIENT_SECRET, DEV_DEVELOPER_PASSWORD, liveRawSessionToken, liveCsrfToken, 'access_token', 'refresh_token', 'id_token']) {
      expect(parsedEndSession.toString()).not.toContain(sensitive);
      expect(validLogout.text).not.toContain(sensitive);
    }

    // Verify Set-Cookie header clears session cookie immediately without echoing session token
    const setCookies = validLogout.header['set-cookie'] as unknown as string[];
    const clearedSession = setCookies.find((c) => c.startsWith(`${COOKIE_NAME_DEV_SESSION}=`));
    expect(clearedSession).toBeDefined();
    expect(clearedSession).toContain('Max-Age=0');
    expect(clearedSession).not.toContain(liveRawSessionToken);

    // Verify in PostgreSQL that BFF session is marked revoked
    const sessionRow = await testDbClient.query<{ revoked_at: Date | null; revoke_reason: string | null }>(
      'SELECT revoked_at, revoke_reason FROM public.user_sessions WHERE id = $1;',
      [liveSessionId],
    );
    expect(sessionRow.rows.length).toBe(1);
    expect(sessionRow.rows[0]!.revoked_at).not.toBeNull();
    expect(sessionRow.rows[0]!.revoke_reason).toBe('USER_LOGOUT');

    // E. Follow returned Keycloak endSessionUrl using same browser cookie jar and complete logout confirmation
    // Because SecureFlow intentionally omits id_token_hint, Keycloak 26.8.2 renders a logout confirmation form (HTTP 200)
    // before terminating the SSO session and redirecting to post_logout_redirect_uri.
    const kcLogoutRes = await fetch(parsedEndSession.toString(), {
      method: 'GET',
      headers: { Cookie: serializeCookieJar(liveKeycloakCookieJar) },
      redirect: 'manual',
    });
    updateCookieJar(liveKeycloakCookieJar, kcLogoutRes);
    expect(kcLogoutRes.status).toBe(200);

    const confirmHtml = await kcLogoutRes.text();
    const confirmActionMatch = confirmHtml.match(/action="([^"]+)"/);
    expect(confirmActionMatch).not.toBeNull();
    const confirmActionUrl = new URL(
      confirmActionMatch![1]!.replace(/&amp;/g, '&'),
      parsedEndSession.toString(),
    ).toString();

    const confirmFormBody = new URLSearchParams();
    for (const inputMatch of confirmHtml.matchAll(/<input[^>]+>/g)) {
      const tag = inputMatch[0];
      const name = tag.match(/name="([^"]+)"/)?.[1];
      const value = tag.match(/value="([^"]*)"/)?.[1] ?? '';
      const type = tag.match(/type="([^"]+)"/)?.[1];
      if (name && (type === 'hidden' || type === 'submit')) {
        confirmFormBody.set(name, value);
      }
    }
    expect(confirmFormBody.get('session_code')).toBeTruthy();

    const kcConfirmRes = await fetch(confirmActionUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Cookie: serializeCookieJar(liveKeycloakCookieJar),
      },
      body: confirmFormBody.toString(),
      redirect: 'manual',
    });
    updateCookieJar(liveKeycloakCookieJar, kcConfirmRes);

    expect(kcConfirmRes.status).toBe(302);
    const postLogoutLocation = kcConfirmRes.headers.get('location');
    expect(postLogoutLocation).toBe(POST_LOGOUT_REDIRECT_URI);
    expect(liveKeycloakCookieJar.has('KEYCLOAK_IDENTITY')).toBe(false);
    expect(liveKeycloakCookieJar.has('KEYCLOAK_SESSION')).toBe(false);
    for (const sensitive of [CLIENT_SECRET, DEV_DEVELOPER_PASSWORD, liveRawSessionToken, 'access_token', 'refresh_token', 'id_token']) {
      expect(postLogoutLocation).not.toContain(sensitive);
    }

    // F. Verify previous Keycloak SSO session can NO LONGER silently authenticate (neither with updated jar nor stale cookie replay)
    const postLogoutAuthUrl = await initiateTrackedAuthorization('/post-logout-sso-check');
    const postLogoutSilentUrl = new URL(postLogoutAuthUrl.toString());
    postLogoutSilentUrl.searchParams.set('prompt', 'none');

    const postLogoutJarRes = await fetch(postLogoutSilentUrl.toString(), {
      method: 'GET',
      headers: { Cookie: serializeCookieJar(liveKeycloakCookieJar) },
      redirect: 'manual',
    });
    expect(postLogoutJarRes.status).toBe(302);
    const postLogoutJarLoc = new URL(postLogoutJarRes.headers.get('location') as string);
    expect(postLogoutJarLoc.searchParams.get('error')).toBe('login_required');
    expect(postLogoutJarLoc.searchParams.has('code')).toBe(false);

    const staleReplayAuthUrl = await initiateTrackedAuthorization('/post-logout-stale-cookie-check');
    const staleReplaySilentUrl = new URL(staleReplayAuthUrl.toString());
    staleReplaySilentUrl.searchParams.set('prompt', 'none');
    const staleReplayRes = await fetch(staleReplaySilentUrl.toString(), {
      method: 'GET',
      headers: { Cookie: preLogoutKeycloakCookieHeader },
      redirect: 'manual',
    });
    expect(staleReplayRes.status).toBe(302);
    const staleReplayLoc = new URL(staleReplayRes.headers.get('location') as string);
    expect(staleReplayLoc.searchParams.get('error')).toBe('login_required');
    expect(staleReplayLoc.searchParams.has('code')).toBe(false);

    const interactivePromptUrl = await initiateTrackedAuthorization('/post-logout-login-prompt');
    const interactivePromptRes = await fetch(interactivePromptUrl.toString(), {
      method: 'GET',
      headers: { Cookie: serializeCookieJar(liveKeycloakCookieJar) },
      redirect: 'manual',
    });
    expect(interactivePromptRes.status).toBe(200);
    expect(await interactivePromptRes.text()).toContain('<form');

    // G. Subsequent BFF requests with revoked SecureFlow session cookie remain rejected (401 Unauthorized)
    const postLogoutMe = await request(app)
      .get('/api/v1/auth/me')
      .set('Cookie', liveSessionCookie);
    expect(postLogoutMe.status).toBe(401);
    expect(postLogoutMe.body.error.code).toBe('UNAUTHORIZED');

    const postLogoutProjects = await request(app)
      .get('/api/v1/projects')
      .set('Cookie', liveSessionCookie);
    expect(postLogoutProjects.status).toBe(401);
    expect(postLogoutProjects.body.error.code).toBe('UNAUTHORIZED');
  });

  it('8. Session expiration defense: rejects idle and absolutely expired sessions', async () => {
    const rawExpiredToken = generateOpaqueToken(32);
    const expiredTokenHash = hashOpaqueToken(rawExpiredToken);
    const expiredSessionId = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';

    // Insert an idle-expired session into PostgreSQL
    await testDbClient.query(
      `INSERT INTO public.user_sessions (
        id, user_id, session_token_hash, csrf_token, ip_address, user_agent,
        created_at, last_active_at, idle_expires_at, expires_at
      ) VALUES ($1, $2, $3, $4, $5, $6, NOW() - INTERVAL '2 hours', NOW() - INTERVAL '2 hours', NOW() - INTERVAL '1 hour', NOW() + INTERVAL '6 hours');`,
      [expiredSessionId, liveUserId, expiredTokenHash, 'expired_csrf_1', '127.0.0.1', 'Vitest'],
    );
    createdSessionIds.add(expiredSessionId);

    const idleExpiredRes = await request(app)
      .get('/api/v1/auth/me')
      .set('Cookie', `${COOKIE_NAME_DEV_SESSION}=${rawExpiredToken}`);

    expect(idleExpiredRes.status).toBe(401);
    expect(idleExpiredRes.body.error.code).toBe('UNAUTHORIZED');

    // Update session to be absolutely expired
    await testDbClient.query(
      `UPDATE public.user_sessions
       SET idle_expires_at = NOW() + INTERVAL '1 hour', expires_at = NOW() - INTERVAL '1 minute'
       WHERE id = $1;`,
      [expiredSessionId],
    );

    const absExpiredRes = await request(app)
      .get('/api/v1/auth/me')
      .set('Cookie', `${COOKIE_NAME_DEV_SESSION}=${rawExpiredToken}`);

    expect(absExpiredRes.status).toBe(401);
    expect(absExpiredRes.body.error.code).toBe('UNAUTHORIZED');
  });

  it('9. Deactivated user defense: rejects requests from deactivated user accounts with HTTP 403', async () => {
    const rawToken = generateOpaqueToken(32);
    const tokenHash = hashOpaqueToken(rawToken);
    const testSessionId = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';

    await testDbClient.query(
      `INSERT INTO public.user_sessions (
        id, user_id, session_token_hash, csrf_token, ip_address, user_agent,
        created_at, last_active_at, idle_expires_at, expires_at
      ) VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW(), NOW() + INTERVAL '30 minutes', NOW() + INTERVAL '8 hours');`,
      [testSessionId, liveUserId, tokenHash, 'deact_csrf_1', '127.0.0.1', 'Vitest'],
    );
    createdSessionIds.add(testSessionId);

    // Deactivate user in PostgreSQL
    await testDbClient.query('UPDATE public.users SET is_active = false WHERE id = $1;', [liveUserId]);

    try {
      const deactRes = await request(app)
        .get('/api/v1/auth/me')
        .set('Cookie', `${COOKIE_NAME_DEV_SESSION}=${rawToken}`);

      expect(deactRes.status).toBe(403);
      expect(deactRes.body.error.code).toBe('FORBIDDEN');
      expect(deactRes.body.error.message).toContain('deactivated');
    } finally {
      // Restore user active state
      await testDbClient.query('UPDATE public.users SET is_active = true WHERE id = $1;', [liveUserId]);
    }
  });

  it('10. Client identity header spoofing defense: strictly ignores spoofed headers and resolves actor from DB', async () => {
    // Call without session cookie but with forged admin headers -> 401
    const spoofUnauthRes = await request(app)
      .get('/api/v1/projects')
      .set('x-user-id', '59c69e57-4a9f-42fd-8e6b-40a357ca9cb5')
      .set('x-actor-role', 'ADMIN');

    expect(spoofUnauthRes.status).toBe(401);
    expect(spoofUnauthRes.body.error.code).toBe('UNAUTHORIZED');

    // Create a valid active session for a regular user
    const rawToken = generateOpaqueToken(32);
    const tokenHash = hashOpaqueToken(rawToken);
    const testSessionId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';

    await testDbClient.query(
      `INSERT INTO public.user_sessions (
        id, user_id, session_token_hash, csrf_token, ip_address, user_agent,
        created_at, last_active_at, idle_expires_at, expires_at
      ) VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW(), NOW() + INTERVAL '30 minutes', NOW() + INTERVAL '8 hours');`,
      [testSessionId, liveUserId, tokenHash, 'spoof_csrf_1', '127.0.0.1', 'Vitest'],
    );
    createdSessionIds.add(testSessionId);

    // Call with valid session cookie AND forged x-actor-role: ADMIN
    const spoofAuthRes = await request(app)
      .get('/api/v1/auth/me')
      .set('Cookie', `${COOKIE_NAME_DEV_SESSION}=${rawToken}`)
      .set('x-actor-role', 'ADMIN');

    expect(spoofAuthRes.status).toBe(200);
    // Role MUST remain DEVELOPER as resolved from the database, not ADMIN!
    expect(spoofAuthRes.body.data.actor.globalRole).toBe('DEVELOPER');
  });

  it('11. F-13 Separation of Duties: Global Admin cannot create ordinary findings', async () => {
    // Create an active session for the pre-existing fixture Admin user
    const adminUserId = '59c69e57-4a9f-42fd-8e6b-40a357ca9cb5';
    const adminRawToken = generateOpaqueToken(32);
    const adminTokenHash = hashOpaqueToken(adminRawToken);
    const adminSessionId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
    const adminCsrfToken = 'admin_csrf_token_123';

    await testDbClient.query(
      `INSERT INTO public.user_sessions (
        id, user_id, session_token_hash, csrf_token, ip_address, user_agent,
        created_at, last_active_at, idle_expires_at, expires_at
      ) VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW(), NOW() + INTERVAL '30 minutes', NOW() + INTERVAL '8 hours');`,
      [adminSessionId, adminUserId, adminTokenHash, adminCsrfToken, '127.0.0.1', 'Vitest'],
    );
    createdSessionIds.add(adminSessionId);

    // Admin attempts to create an ordinary finding in a project
    const f13Res = await request(app)
      .post('/api/v1/findings')
      .set('Cookie', `${COOKIE_NAME_DEV_SESSION}=${adminRawToken}`)
      .set('Origin', ALLOWED_ORIGIN)
      .set('X-CSRF-Token', adminCsrfToken)
      .send({
        projectId: '00000000-0000-0000-0000-000000000001',
        title: 'Admin Created Finding Should Fail F-13',
        description: 'Global Admin attempting ordinary finding creation',
        severity: 'LOW',
        category: 'OTHER',
      });

    // Global Admin MUST receive HTTP 403 FORBIDDEN
    expect(f13Res.status).toBe(403);
    expect(f13Res.body.error.code).toBe('FORBIDDEN');
  });

  it('12. Cross-project existence hiding: accessing findings in non-member projects returns 404', async () => {
    // User liveUserId is NOT a member of project 11111111-1111-4111-8111-111111111111
    // (finding 2fbdc83c-440f-4890-bc89-016980656696 belongs to project 11111111-1111-4111-8111-111111111111)
    const rawToken = generateOpaqueToken(32);
    const tokenHash = hashOpaqueToken(rawToken);
    const userSessionId = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';

    await testDbClient.query(
      `INSERT INTO public.user_sessions (
        id, user_id, session_token_hash, csrf_token, ip_address, user_agent,
        created_at, last_active_at, idle_expires_at, expires_at
      ) VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW(), NOW() + INTERVAL '30 minutes', NOW() + INTERVAL '8 hours');`,
      [userSessionId, liveUserId, tokenHash, 'csrf_hide_1', '127.0.0.1', 'Vitest'],
    );
    createdSessionIds.add(userSessionId);

    const hiddenRes = await request(app)
      .get('/api/v1/findings/2fbdc83c-440f-4890-bc89-016980656696')
      .set('Cookie', `${COOKIE_NAME_DEV_SESSION}=${rawToken}`);

    // Must return 404 NOT_FOUND to hide existence from non-members
    expect(hiddenRes.status).toBe(404);
    expect(hiddenRes.body.error.code).toBe('NOT_FOUND');
  });

  it('13. Route inventory verification: all 23 operational routes fail closed (401) without session', async () => {
    const dummyId = '00000000-0000-0000-0000-000000000001';
    const dummyUserId = '00000000-0000-0000-0000-000000000002';

    const operationalEndpoints: Array<{ method: 'get' | 'post' | 'patch' | 'delete'; path: string }> = [
      // Projects (8)
      { method: 'post', path: '/api/v1/projects' },
      { method: 'get', path: '/api/v1/projects' },
      { method: 'get', path: `/api/v1/projects/${dummyId}` },
      { method: 'patch', path: `/api/v1/projects/${dummyId}` },
      { method: 'delete', path: `/api/v1/projects/${dummyId}` },
      { method: 'get', path: `/api/v1/projects/${dummyId}/members` },
      { method: 'post', path: `/api/v1/projects/${dummyId}/members` },
      { method: 'delete', path: `/api/v1/projects/${dummyId}/members/${dummyUserId}` },
      // Findings (12) - confirming exact /submit-remediation route
      { method: 'post', path: '/api/v1/findings' },
      { method: 'get', path: '/api/v1/findings' },
      { method: 'get', path: `/api/v1/findings/${dummyId}` },
      { method: 'patch', path: `/api/v1/findings/${dummyId}` },
      { method: 'post', path: `/api/v1/findings/${dummyId}/triage` },
      { method: 'post', path: `/api/v1/findings/${dummyId}/assign` },
      { method: 'post', path: `/api/v1/findings/${dummyId}/submit-remediation` },
      { method: 'post', path: `/api/v1/findings/${dummyId}/verify` },
      { method: 'post', path: `/api/v1/findings/${dummyId}/close` },
      { method: 'delete', path: `/api/v1/findings/${dummyId}` },
      { method: 'post', path: `/api/v1/findings/${dummyId}/force-close` },
      { method: 'post', path: `/api/v1/findings/${dummyId}/force-reopen` },
      // Tasks (2)
      { method: 'get', path: `/api/v1/tasks/${dummyId}` },
      { method: 'patch', path: `/api/v1/tasks/${dummyId}/notes` },
      // Audit (1)
      { method: 'get', path: '/api/v1/audit-events' },
    ];

    expect(operationalEndpoints.length).toBe(23);

    for (const endpoint of operationalEndpoints) {
      const res = await request(app)[endpoint.method](endpoint.path);
      expect(res.status).toBe(401);
      expect(res.body.error.code).toBe('UNAUTHORIZED');
    }

    // Health endpoint remains public and unauthenticated
    const healthRes = await request(app).get('/health/ready');
    expect(healthRes.status).toBe(200);
  });

  it('14. Log & Audit redaction verification: zero tokens, codes, or secrets leaked into DB audit records', async () => {
    // Check all audit records created during this run
    const auditRows = await testDbClient.query<{
      event_type: string;
      before_state: Record<string, unknown> | null;
      after_state: Record<string, unknown> | null;
    }>(
      `SELECT event_type, before_state, after_state FROM public.audit_events
       WHERE event_type LIKE 'auth.%' OR event_category = 'AUTH'
       ORDER BY created_at DESC LIMIT 20;`,
    );

    for (const row of auditRows.rows) {
      const beforeStr = JSON.stringify(row.before_state ?? {});
      const afterStr = JSON.stringify(row.after_state ?? {});
      for (const str of [beforeStr, afterStr]) {
        expect(str).not.toContain(CLIENT_SECRET);
        expect(str).not.toContain(DEV_DEVELOPER_PASSWORD);
        expect(str).not.toContain(DEV_ANALYST_PASSWORD);
        expect(str).not.toContain(liveTxnToken);
        expect(str).not.toContain(liveCode);
        expect(str).not.toContain(liveRawSessionToken);
        expect(str).not.toContain(liveCsrfToken);
      }
    }
  });
});
