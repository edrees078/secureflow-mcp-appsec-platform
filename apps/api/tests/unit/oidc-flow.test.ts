import { describe, it, expect, vi, beforeEach } from 'vitest';
import { OidcAuthFlowCoordinator } from '../../src/auth/oidc-flow.js';
import { OidcProtocolError, type IOidcClient, type VerifiedOidcTokenIdentity } from '../../src/auth/oidc-client.js';
import type { IAuthService, EstablishedSessionResult, OidcTransactionEntity } from '@secureflow/domain';
import type { AuthRuntimeConfig } from '../../src/config/auth.js';
import { UnauthorizedError } from '@secureflow/shared';

const ISSUER_URL = 'https://keycloak.example.com/realms/secureflow';
const CLIENT_ID = 'secureflow-api-client';
const REDIRECT_URI = 'https://app.secureflow.example/api/v1/auth/callback';

function createTestAuthConfig(): AuthRuntimeConfig {
  return {
    mode: 'production',
    authEnabled: true,
    oidc: {
      issuerUrl: ISSUER_URL,
      clientId: CLIENT_ID,
      clientSecret: 'super-secret-client-credential-min-16-chars',
      clientAuthMethod: 'client_secret_basic',
      redirectUri: REDIRECT_URI,
      allowedRedirectUris: [REDIRECT_URI],
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
      sessionCookieName: '__Host-sf_session',
      oidcTxnCookieName: '__Host-sf_oidc_txn',
      secure: true,
      httpOnly: true,
      sameSite: 'Lax',
      path: '/',
    },
    allowedOrigins: ['https://app.secureflow.example'],
  };
}

describe('Gate 4B.2 OIDC Flow Coordinator', () => {
  let authConfig: AuthRuntimeConfig;
  let mockAuthService: IAuthService;
  let mockOidcClient: IOidcClient;
  let coordinator: OidcAuthFlowCoordinator;

  const fixedNow = new Date('2026-11-12T12:00:00.000Z');

  const txnFixture: OidcTransactionEntity = {
    id: '11111111-1111-4111-8111-111111111111',
    rawTxnToken: 'raw_txn_token_fixture_abc123456789',
    state: 'state_fixture_1234567890abcdef',
    nonce: 'nonce_fixture_1234567890abcdef',
    codeVerifier: 'verifier_fixture_1234567890abcdef_secret',
    codeChallenge: 'challenge_fixture_1234567890abcdef',
    codeChallengeMethod: 'S256',
    returnTo: '/projects/00000000-0000-0000-0000-000000000001',
    expiresAt: new Date(fixedNow.getTime() + 300_000),
  };

  const verifiedIdentityFixture: VerifiedOidcTokenIdentity = {
    issuer: ISSUER_URL,
    sub: 'idp-sub-user-001',
    email: 'dev@secureflow.example',
    emailVerified: true,
    displayName: 'Developer Alice',
    oidcSid: 'idp-sid-session-123',
    audience: CLIENT_ID,
  };

  const establishedSessionFixture: EstablishedSessionResult = {
    rawSessionToken: 'raw_session_token_fixture_secret_xyz',
    jitProvisioned: false,
    session: {
      id: '22222222-2222-4222-8222-222222222222',
      userId: '33333333-3333-4333-8333-333333333333',
      sessionTokenHash: 'b'.repeat(64),
      csrfToken: 'csrf_bound_token_secret_xyz123',
      oidcSid: 'idp-sid-session-123',
      ipAddress: '203.0.113.10',
      userAgent: 'Vitest/2.0',
      createdAt: fixedNow,
      lastActiveAt: fixedNow,
      idleExpiresAt: new Date(fixedNow.getTime() + 1_800_000),
      expiresAt: new Date(fixedNow.getTime() + 28_800_000),
      revokedAt: null,
      revocationReason: null,
    },
    user: {
      id: '33333333-3333-4333-8333-333333333333',
      email: 'dev@secureflow.example',
      displayName: 'Developer Alice',
      globalRole: 'USER',
      isActive: true,
      oidcSubject: 'idp-sub-user-001',
      createdAt: fixedNow,
    },
    actor: {
      id: '33333333-3333-4333-8333-333333333333',
      globalRole: 'USER',
      isActive: true,
      projectMemberships: new Map(),
    },
  };

  beforeEach(() => {
    authConfig = createTestAuthConfig();

    mockAuthService = {
      createOidcTransaction: vi.fn().mockResolvedValue(txnFixture),
      consumeOidcTransaction: vi.fn().mockResolvedValue({
        id: txnFixture.id,
        nonce: txnFixture.nonce,
        codeVerifier: txnFixture.codeVerifier,
        returnTo: txnFixture.returnTo,
        consumedAt: fixedNow,
      }),
      establishAuthenticatedSession: vi.fn().mockResolvedValue(establishedSessionFixture),
      recordAuthenticationFailure: vi.fn().mockResolvedValue({
        id: '44444444-4444-4444-4444-444444444444',
        eventTimestamp: fixedNow,
        reason: 'OIDC_TOKEN_EXCHANGE_FAILED',
        actorId: null,
        resourceUserId: null,
        ipAddress: '203.0.113.10',
        userAgent: 'Vitest/2.0',
        metadata: {},
      }),
      resolveSessionActor: vi.fn(),
      revokeSession: vi.fn(),
      cleanupExpired: vi.fn(),
      bootstrapInitialAdmin: vi.fn(),
    } as unknown as IAuthService;

    mockOidcClient = {
      discover: vi.fn().mockResolvedValue({
        issuer: ISSUER_URL,
        authorizationEndpoint: `${ISSUER_URL}/protocol/openid-connect/auth`,
        tokenEndpoint: `${ISSUER_URL}/protocol/openid-connect/token`,
        jwksUri: `${ISSUER_URL}/protocol/openid-connect/certs`,
        supportsPkceS256: true,
      }),
      buildAuthorizationUrl: vi.fn().mockImplementation((params) => {
        const url = new URL(`${ISSUER_URL}/protocol/openid-connect/auth`);
        url.searchParams.set('response_type', 'code');
        url.searchParams.set('client_id', CLIENT_ID);
        url.searchParams.set('redirect_uri', params.redirectUri);
        url.searchParams.set('state', params.state);
        url.searchParams.set('nonce', params.nonce);
        url.searchParams.set('code_challenge', params.codeChallenge);
        url.searchParams.set('code_challenge_method', params.codeChallengeMethod);
        url.searchParams.set('scope', params.scope ?? authConfig.oidc.scopes);
        return Promise.resolve(url);
      }),
      exchangeAuthorizationCode: vi.fn().mockResolvedValue(verifiedIdentityFixture),
      clearCache: vi.fn(),
    };

    coordinator = new OidcAuthFlowCoordinator(mockAuthService, mockOidcClient, authConfig);
  });

  it('initiates valid authorization flow with OIDC transaction and PKCE S256 state binding', async () => {
    const started = await coordinator.startAuthorizationFlow(
      { returnTo: '/projects/00000000-0000-0000-0000-000000000001' },
      fixedNow,
    );

    expect(mockAuthService.createOidcTransaction).toHaveBeenCalledWith(
      {
        returnTo: '/projects/00000000-0000-0000-0000-000000000001',
        ttlSeconds: authConfig.session.oidcTxnTtlSeconds,
      },
      fixedNow,
    );

    expect(mockOidcClient.buildAuthorizationUrl).toHaveBeenCalledWith({
      redirectUri: REDIRECT_URI,
      state: txnFixture.state,
      nonce: txnFixture.nonce,
      codeChallenge: txnFixture.codeChallenge,
      codeChallengeMethod: 'S256',
      scope: 'openid email profile',
    });

    expect(started.rawTxnToken).toBe(txnFixture.rawTxnToken);
    expect(started.expiresAt).toEqual(txnFixture.expiresAt);
    expect(started.authorizationUrl.searchParams.get('state')).toBe(txnFixture.state);
    expect(started.authorizationUrl.searchParams.get('code_challenge')).toBe(txnFixture.codeChallenge);
  });

  it('consumes callback atomically, verifies token identity, and creates authenticated user session', async () => {
    const cbUrl = new URL(REDIRECT_URI);
    cbUrl.searchParams.set('code', 'auth_code_secret_xyz123');
    cbUrl.searchParams.set('state', txnFixture.state);
    cbUrl.searchParams.set('iss', ISSUER_URL);

    const completed = await coordinator.completeAuthorizationCallback(
      {
        callbackUrl: cbUrl,
        rawTxnToken: txnFixture.rawTxnToken,
        ipAddress: '203.0.113.10',
        userAgent: 'Vitest/2.0',
      },
      fixedNow,
    );

    // 1. Transaction consumed first with state and raw token
    expect(mockAuthService.consumeOidcTransaction).toHaveBeenCalledWith(
      {
        rawTxnToken: txnFixture.rawTxnToken,
        state: txnFixture.state,
        ipAddress: '203.0.113.10',
        userAgent: 'Vitest/2.0',
      },
      fixedNow,
    );

    // 2. Token exchanged using unhashed nonce and code verifier from consumed transaction
    expect(mockOidcClient.exchangeAuthorizationCode).toHaveBeenCalledWith({
      callbackUrl: cbUrl,
      expectedRedirectUri: REDIRECT_URI,
      expectedState: txnFixture.state,
      expectedNonce: txnFixture.nonce,
      pkceCodeVerifier: txnFixture.codeVerifier,
    });

    // 3. User session established with verified claims and session timeouts
    expect(mockAuthService.establishAuthenticatedSession).toHaveBeenCalledWith(
      {
        sub: verifiedIdentityFixture.sub,
        email: verifiedIdentityFixture.email,
        emailVerified: verifiedIdentityFixture.emailVerified,
        displayName: verifiedIdentityFixture.displayName,
        oidcSid: verifiedIdentityFixture.oidcSid,
        ipAddress: '203.0.113.10',
        userAgent: 'Vitest/2.0',
        idleTimeoutSeconds: 1800,
        absoluteTimeoutSeconds: 28800,
      },
      fixedNow,
    );

    // 4. Returns session tokens and CSRF binding
    expect(completed.rawSessionToken).toBe('raw_session_token_fixture_secret_xyz');
    expect(completed.csrfToken).toBe('csrf_bound_token_secret_xyz123');
    expect(completed.sessionId).toBe('22222222-2222-4222-8222-222222222222');
    expect(completed.returnTo).toBe(txnFixture.returnTo);
    expect(completed.user.email).toBe('dev@secureflow.example');
  });

  it('rejects callback with missing state parameter and records failure audit before transaction consumption', async () => {
    const cbUrlNoState = new URL(REDIRECT_URI);
    cbUrlNoState.searchParams.set('code', 'auth_code_secret_xyz123');
    cbUrlNoState.searchParams.set('iss', ISSUER_URL);

    await expect(
      coordinator.completeAuthorizationCallback({
        callbackUrl: cbUrlNoState,
        rawTxnToken: txnFixture.rawTxnToken,
        ipAddress: '203.0.113.10',
        userAgent: 'Vitest/2.0',
      }),
    ).rejects.toMatchObject({
      protocolCode: 'OIDC_STATE_MISMATCH',
      statusCode: 401,
    });

    expect(mockAuthService.recordAuthenticationFailure).toHaveBeenCalledWith(
      expect.objectContaining({
        reason: 'OIDC_STATE_MISMATCH',
        metadata: { stage: 'callback_state_presence' },
      }),
    );
    expect(mockAuthService.consumeOidcTransaction).not.toHaveBeenCalled();
    expect(mockOidcClient.exchangeAuthorizationCode).not.toHaveBeenCalled();
    expect(mockAuthService.establishAuthenticatedSession).not.toHaveBeenCalled();
  });

  it('rejects replayed or expired transaction when consumeOidcTransaction fails closed', async () => {
    vi.mocked(mockAuthService.consumeOidcTransaction).mockRejectedValueOnce(
      new UnauthorizedError('OIDC transaction expired or already consumed'),
    );

    const cbUrl = new URL(REDIRECT_URI);
    cbUrl.searchParams.set('code', 'auth_code_secret_xyz123');
    cbUrl.searchParams.set('state', txnFixture.state);
    cbUrl.searchParams.set('iss', ISSUER_URL);

    await expect(
      coordinator.completeAuthorizationCallback({
        callbackUrl: cbUrl,
        rawTxnToken: txnFixture.rawTxnToken,
      }),
    ).rejects.toBeInstanceOf(UnauthorizedError);

    expect(mockOidcClient.exchangeAuthorizationCode).not.toHaveBeenCalled();
    expect(mockAuthService.establishAuthenticatedSession).not.toHaveBeenCalled();
  });

  it('handles failed token exchange, logs failure audit, and prevents partial session creation', async () => {
    vi.mocked(mockOidcClient.exchangeAuthorizationCode).mockRejectedValueOnce(
      new OidcProtocolError('Token endpoint rejected code exchange', 'OIDC_TOKEN_EXCHANGE_FAILED', 401),
    );

    const cbUrl = new URL(REDIRECT_URI);
    cbUrl.searchParams.set('code', 'invalid_or_expired_code');
    cbUrl.searchParams.set('state', txnFixture.state);
    cbUrl.searchParams.set('iss', ISSUER_URL);

    await expect(
      coordinator.completeAuthorizationCallback({
        callbackUrl: cbUrl,
        rawTxnToken: txnFixture.rawTxnToken,
        ipAddress: '203.0.113.10',
        userAgent: 'Vitest/2.0',
      }),
    ).rejects.toMatchObject({
      protocolCode: 'OIDC_TOKEN_EXCHANGE_FAILED',
      statusCode: 401,
    });

    expect(mockAuthService.recordAuthenticationFailure).toHaveBeenCalledWith(
      expect.objectContaining({
        reason: 'OIDC_TOKEN_EXCHANGE_FAILED',
        metadata: { protocolCode: 'OIDC_TOKEN_EXCHANGE_FAILED' },
      }),
    );
    expect(mockAuthService.establishAuthenticatedSession).not.toHaveBeenCalled();
  });

  it('records OIDC_NONCE_MISMATCH audit reason when exchange fails on ID token nonce tampering', async () => {
    vi.mocked(mockOidcClient.exchangeAuthorizationCode).mockRejectedValueOnce(
      new OidcProtocolError('ID token nonce mismatch', 'OIDC_NONCE_MISMATCH', 401),
    );

    const cbUrl = new URL(REDIRECT_URI);
    cbUrl.searchParams.set('code', 'auth_code_secret_xyz123');
    cbUrl.searchParams.set('state', txnFixture.state);
    cbUrl.searchParams.set('iss', ISSUER_URL);

    await expect(
      coordinator.completeAuthorizationCallback({
        callbackUrl: cbUrl,
        rawTxnToken: txnFixture.rawTxnToken,
      }),
    ).rejects.toMatchObject({
      protocolCode: 'OIDC_NONCE_MISMATCH',
      statusCode: 401,
    });

    expect(mockAuthService.recordAuthenticationFailure).toHaveBeenCalledWith(
      expect.objectContaining({
        reason: 'OIDC_NONCE_MISMATCH',
        metadata: { protocolCode: 'OIDC_NONCE_MISMATCH' },
      }),
    );
    expect(mockAuthService.establishAuthenticatedSession).not.toHaveBeenCalled();
  });

  it('never leaks authorization code, PKCE verifier, or raw tokens in failure audit metadata', async () => {
    const sensitiveCode = 'extremely_confidential_auth_code_123456';
    const sensitiveVerifier = txnFixture.codeVerifier;
    const sensitiveRawTxn = txnFixture.rawTxnToken;

    vi.mocked(mockOidcClient.exchangeAuthorizationCode).mockRejectedValueOnce(
      new OidcProtocolError(
        `Failed exchange with code ${sensitiveCode} and verifier ${sensitiveVerifier}`,
        'OIDC_TOKEN_EXCHANGE_FAILED',
        401,
      ),
    );

    const cbUrl = new URL(REDIRECT_URI);
    cbUrl.searchParams.set('code', sensitiveCode);
    cbUrl.searchParams.set('state', txnFixture.state);
    cbUrl.searchParams.set('iss', ISSUER_URL);

    await expect(
      coordinator.completeAuthorizationCallback({
        callbackUrl: cbUrl,
        rawTxnToken: sensitiveRawTxn,
      }),
    ).rejects.toBeInstanceOf(OidcProtocolError);

    const auditCall = vi.mocked(mockAuthService.recordAuthenticationFailure).mock.calls[0];
    expect(auditCall).toBeDefined();
    const auditRecord = auditCall![0];
    const auditJson = JSON.stringify(auditRecord);

    expect(auditJson).not.toContain(sensitiveCode);
    expect(auditJson).not.toContain(sensitiveVerifier);
    expect(auditJson).not.toContain(sensitiveRawTxn);
    expect(auditRecord.metadata).toEqual({ protocolCode: 'OIDC_TOKEN_EXCHANGE_FAILED' });
  });
});
