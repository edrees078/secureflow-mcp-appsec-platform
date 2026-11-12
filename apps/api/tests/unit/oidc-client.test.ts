import {
  createHash,
  createSign,
  generateKeyPairSync,
  type KeyObject,
} from 'node:crypto';
import { describe, it, expect, vi, afterEach } from 'vitest';
import type { IAuthService } from '@secureflow/domain';
import { loadAuthConfig } from '../../src/config/auth.js';
import {
  OpenIdConnectClient,
  OidcProtocolError,
} from '../../src/auth/oidc-client.js';
import { OidcAuthFlowCoordinator } from '../../src/auth/oidc-flow.js';

interface EphemeralSigningKey {
  readonly kid: string;
  readonly privateKey: KeyObject;
  readonly publicJwk: Record<string, unknown>;
}

function createEphemeralRsaKey(kid: string): EphemeralSigningKey {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
  });
  const exported = publicKey.export({ format: 'jwk' }) as Record<string, unknown>;
  return {
    kid,
    privateKey,
    publicJwk: {
      ...exported,
      kid,
      use: 'sig',
      alg: 'RS256',
    },
  };
}

function signJwt(
  payload: Record<string, unknown>,
  key: EphemeralSigningKey,
  options?: { readonly alg?: string },
): string {
  const alg = options?.alg ?? 'RS256';
  const header = {
    alg,
    typ: 'JWT',
    ...(alg === 'none' ? {} : { kid: key.kid }),
  };

  const encodedHeader = Buffer.from(JSON.stringify(header), 'utf8').toString('base64url');
  const encodedPayload = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  const signingInput = `${encodedHeader}.${encodedPayload}`;

  if (alg === 'none') {
    return `${signingInput}.`;
  }

  const signer = createSign('RSA-SHA256');
  signer.update(signingInput);
  signer.end();
  const signature = signer.sign(key.privateKey).toString('base64url');
  return `${signingInput}.${signature}`;
}

function sha256Base64Url(input: string): string {
  return createHash('sha256').update(input, 'ascii').digest('base64url');
}

function createAuthServiceMock(): IAuthService {
  const fixedNow = new Date();
  return {
    createOidcTransaction: vi.fn().mockResolvedValue({
      id: '11111111-1111-4111-8111-111111111111',
      rawTxnToken: 'raw_txn_token_fixture_1234567890',
      state: 'state_fixture_abcdef1234567890',
      nonce: 'nonce_fixture_abcdef1234567890',
      codeVerifier: 'verifier_fixture_abcdef1234567890_secret_pkce',
      codeChallenge: sha256Base64Url('verifier_fixture_abcdef1234567890_secret_pkce'),
      codeChallengeMethod: 'S256',
      returnTo: '/projects/123',
      expiresAt: new Date(fixedNow.getTime() + 300_000),
    }),
    consumeOidcTransaction: vi.fn().mockResolvedValue({
      id: '11111111-1111-4111-8111-111111111111',
      nonce: 'nonce_fixture_abcdef1234567890',
      codeVerifier: 'verifier_fixture_abcdef1234567890_secret_pkce',
      returnTo: '/projects/123',
      consumedAt: fixedNow,
    }),
    establishAuthenticatedSession: vi.fn().mockResolvedValue({
      rawSessionToken: 'raw_session_token_fixture_1234567890',
      session: {
        id: '22222222-2222-4222-8222-222222222222',
        userId: '33333333-3333-4333-8333-333333333333',
        sessionTokenHash: 'a'.repeat(64),
        csrfToken: 'csrf_bound_token_fixture_1234567890',
        oidcSid: 'idp-sid-1',
        ipAddress: '203.0.113.10',
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
        email: 'dev@secureflow.example',
        displayName: 'Dev User',
        globalRole: 'USER',
        isActive: true,
        oidcSubject: 'idp-sub-001',
        createdAt: fixedNow,
      },
      actor: {
        id: '33333333-3333-4333-8333-333333333333',
        globalRole: 'USER',
        isActive: true,
      },
      jitProvisioned: true,
    }),
    resolveSessionActor: vi.fn(),
    revokeSession: vi.fn(),
    revokeAllUserSessions: vi.fn(),
    revokeSessionsByOidcSid: vi.fn(),
    bootstrapInitialAdmin: vi.fn(),
    updateUserGlobalRole: vi.fn(),
    deactivateUser: vi.fn(),
    recordAuthenticationFailure: vi.fn().mockResolvedValue(null),
  };
}

describe('Gate 4B.2 OIDC Client, Protocol Validation & Flow Coordination', () => {
  const ISSUER_URL = 'https://idp.secureflow.example/realms/secureflow';
  const CLIENT_ID = 'secureflow-bff';
  const CLIENT_SECRET = 'synth-oidc-client-secret-fixture-123456';
  const REDIRECT_URI = 'https://app.secureflow.example/api/v1/auth/callback';

  function createTestAuthConfig() {
    return loadAuthConfig({
      NODE_ENV: 'production',
      CORS_ORIGIN: 'https://app.secureflow.example',
      OIDC_ISSUER_URL: ISSUER_URL,
      OIDC_CLIENT_ID: CLIENT_ID,
      OIDC_CLIENT_SECRET: CLIENT_SECRET,
      OIDC_REDIRECT_URI: REDIRECT_URI,
      OIDC_ALLOWED_REDIRECT_URIS: REDIRECT_URI,
    });
  }

  afterEach(() => {
    vi.useRealTimers();
  });

  function createMockIdpTransport() {
    const primaryKey = createEphemeralRsaKey('kid-primary-1');
    const rotatedKey = createEphemeralRsaKey('kid-rotated-2');
    const rogueKey = createEphemeralRsaKey('kid-primary-1'); // Same kid, wrong private key

    let discoveryIssuerOverride: string | undefined;
    let activeJwksKeys: Record<string, unknown>[] = [primaryKey.publicJwk];
    let activeSigningKey: EphemeralSigningKey = primaryKey;
    let expectedPkceChallenge: string | undefined;
    let jwksFetchCount = 0;
    let tokenPayloadOverride:
      | ((base: Record<string, unknown>) => Record<string, unknown>)
      | undefined;
    let idTokenAlgOverride: string | undefined;
    let tokenHttpError: { status: number; body: Record<string, unknown> } | undefined;
    let includeEndSessionEndpoint = true;
    let issParamSupported = true;

    const customFetch = async (url: string, init?: RequestInit): Promise<Response> => {
      if (url === `${ISSUER_URL}/.well-known/openid-configuration`) {
        return new Response(
          JSON.stringify({
            issuer: discoveryIssuerOverride ?? ISSUER_URL,
            authorization_endpoint: `${ISSUER_URL}/protocol/openid-connect/auth`,
            token_endpoint: `${ISSUER_URL}/protocol/openid-connect/token`,
            jwks_uri: `${ISSUER_URL}/protocol/openid-connect/certs`,
            ...(includeEndSessionEndpoint
              ? { end_session_endpoint: `${ISSUER_URL}/protocol/openid-connect/logout` }
              : {}),
            response_types_supported: ['code'],
            subject_types_supported: ['public'],
            id_token_signing_alg_values_supported: ['RS256'],
            code_challenge_methods_supported: ['S256'],
            token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
            authorization_response_iss_parameter_supported: issParamSupported,
          }),
          {
            status: 200,
            headers: { 'content-type': 'application/json' },
          },
        );
      }

      if (url === `${ISSUER_URL}/protocol/openid-connect/certs`) {
        jwksFetchCount += 1;
        return new Response(JSON.stringify({ keys: activeJwksKeys }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }

      if (url === `${ISSUER_URL}/protocol/openid-connect/token`) {
        if (tokenHttpError) {
          return new Response(JSON.stringify(tokenHttpError.body), {
            status: tokenHttpError.status,
            headers: { 'content-type': 'application/json' },
          });
        }

        const bodyText =
          typeof init?.body === 'string'
            ? init.body
            : init?.body instanceof URLSearchParams
              ? init.body.toString()
              : '';
        const params = new URLSearchParams(bodyText);
        const codeVerifier = params.get('code_verifier');

        if (
          expectedPkceChallenge &&
          (!codeVerifier || sha256Base64Url(codeVerifier) !== expectedPkceChallenge)
        ) {
          return new Response(
            JSON.stringify({ error: 'invalid_grant', error_description: 'PKCE verification failed' }),
            { status: 400, headers: { 'content-type': 'application/json' } },
          );
        }

        const nowSec = Math.floor(Date.now() / 1000);
        const baseClaims: Record<string, unknown> = {
          iss: ISSUER_URL,
          sub: 'idp-sub-001',
          aud: CLIENT_ID,
          nonce: 'nonce_fixture_abcdef1234567890',
          iat: nowSec,
          exp: nowSec + 300,
          email: 'dev@secureflow.example',
          email_verified: true,
          name: 'Dev User',
          sid: 'idp-sid-1',
        };
        const finalClaims = tokenPayloadOverride ? tokenPayloadOverride(baseClaims) : baseClaims;
        const idToken = signJwt(
          finalClaims,
          activeSigningKey,
          idTokenAlgOverride ? { alg: idTokenAlgOverride } : undefined,
        );

        return new Response(
          JSON.stringify({
            access_token: 'synth_idp_access_token_value',
            refresh_token: 'synth_idp_refresh_token_value',
            token_type: 'Bearer',
            expires_in: 300,
            id_token: idToken,
          }),
          {
            status: 200,
            headers: { 'content-type': 'application/json' },
          },
        );
      }

      return new Response('Not Found', { status: 404 });
    };

    return {
      customFetch,
      primaryKey,
      rotatedKey,
      rogueKey,
      setDiscoveryIssuer: (iss: string) => {
        discoveryIssuerOverride = iss;
      },
      setExpectedPkceChallenge: (challenge: string) => {
        expectedPkceChallenge = challenge;
      },
      setActiveSigningKey: (key: EphemeralSigningKey) => {
        activeSigningKey = key;
      },
      setActiveJwks: (keys: Record<string, unknown>[]) => {
        activeJwksKeys = keys;
      },
      setTokenPayloadOverride: (
        fn: ((base: Record<string, unknown>) => Record<string, unknown>) | undefined,
      ) => {
        tokenPayloadOverride = fn;
      },
      setIdTokenAlgOverride: (alg: string | undefined) => {
        idTokenAlgOverride = alg;
      },
      setTokenHttpError: (err: { status: number; body: Record<string, unknown> } | undefined) => {
        tokenHttpError = err;
      },
      setIncludeEndSessionEndpoint: (include: boolean) => {
        includeEndSessionEndpoint = include;
      },
      setIssParamSupported: (supported: boolean) => {
        issParamSupported = supported;
      },
      getJwksFetchCount: () => jwksFetchCount,
    };
  }

  it('performs trusted issuer discovery, rejects mismatched discovery issuer, and enforces redirect allowlisting', async () => {
    const authCfg = createTestAuthConfig();
    const idp = createMockIdpTransport();
    const oidc = new OpenIdConnectClient(authCfg.oidc, { customFetch: idp.customFetch });

    const summary = await oidc.discover();
    expect(summary.issuer).toBe(ISSUER_URL);
    expect(summary.supportsPkceS256).toBe(true);

    const authUrl = await oidc.buildAuthorizationUrl({
      redirectUri: REDIRECT_URI,
      state: 'state_fixture_abcdef1234567890',
      nonce: 'nonce_fixture_abcdef1234567890',
      codeChallenge: sha256Base64Url('verifier_fixture_abcdef1234567890_secret_pkce'),
      codeChallengeMethod: 'S256',
    });
    expect(authUrl.searchParams.get('response_type')).toBe('code');
    expect(authUrl.searchParams.get('code_challenge_method')).toBe('S256');
    expect(authUrl.searchParams.get('redirect_uri')).toBe(REDIRECT_URI);

    await expect(
      oidc.buildAuthorizationUrl({
        redirectUri: 'https://evil.example/callback',
        state: 'state_fixture_abcdef1234567890',
        nonce: 'nonce_fixture_abcdef1234567890',
        codeChallenge: 'challenge1234567890',
        codeChallengeMethod: 'S256',
      }),
    ).rejects.toMatchObject({ protocolCode: 'OIDC_REDIRECT_URI_NOT_ALLOWED' });

    const badDiscoveryTransport = createMockIdpTransport();
    badDiscoveryTransport.setDiscoveryIssuer('https://rogue-issuer.example/realms/other');
    const badOidc = new OpenIdConnectClient(authCfg.oidc, {
      customFetch: badDiscoveryTransport.customFetch,
    });
    await expect(badOidc.discover()).rejects.toMatchObject({
      protocolCode: 'OIDC_ISSUER_MISMATCH',
    });
  });

  it('completes Authorization Code + PKCE S256 grant end-to-end with AuthService coordination', async () => {
    const authCfg = createTestAuthConfig();
    const idp = createMockIdpTransport();
    const authService = createAuthServiceMock();
    const oidc = new OpenIdConnectClient(authCfg.oidc, { customFetch: idp.customFetch });
    const flow = new OidcAuthFlowCoordinator(authService, oidc, authCfg);

    const started = await flow.startAuthorizationFlow({ returnTo: '/projects/123' });
    const expectedChallenge = started.authorizationUrl.searchParams.get('code_challenge')!;
    const state = started.authorizationUrl.searchParams.get('state')!;
    idp.setExpectedPkceChallenge(expectedChallenge);

    const callbackUrl = new URL(REDIRECT_URI);
    callbackUrl.searchParams.set('code', 'auth_code_secret_xyz987');
    callbackUrl.searchParams.set('state', state);
    callbackUrl.searchParams.set('iss', ISSUER_URL);

    const completed = await flow.completeAuthorizationCallback({
      callbackUrl,
      rawTxnToken: started.rawTxnToken,
      ipAddress: '203.0.113.10',
      userAgent: 'Vitest',
    });

    expect(completed.rawSessionToken).toBe('raw_session_token_fixture_1234567890');
    expect(completed.csrfToken).toBe('csrf_bound_token_fixture_1234567890');
    expect(completed.returnTo).toBe('/projects/123');
    expect(completed.actor.globalRole).toBe('USER');
    expect(authService.establishAuthenticatedSession).toHaveBeenCalledWith(
      expect.objectContaining({
        sub: 'idp-sub-001',
        email: 'dev@secureflow.example',
        emailVerified: true,
        oidcSid: 'idp-sid-1',
      }),
      undefined,
    );
  });

  it('rejects wrong authorization response iss/state, IdP error responses, and tampered callback redirect URL', async () => {
    const authCfg = createTestAuthConfig();
    const idp = createMockIdpTransport();
    const oidc = new OpenIdConnectClient(authCfg.oidc, { customFetch: idp.customFetch });

    // 1. Authorization response iss mismatch (RFC 9207)
    const wrongIssCb = new URL(REDIRECT_URI);
    wrongIssCb.searchParams.set('code', 'c1');
    wrongIssCb.searchParams.set('state', 'state_ok_1234567890');
    wrongIssCb.searchParams.set('iss', 'https://attacker-idp.example');
    await expect(
      oidc.exchangeAuthorizationCode({
        callbackUrl: wrongIssCb,
        expectedRedirectUri: REDIRECT_URI,
        expectedState: 'state_ok_1234567890',
        expectedNonce: 'nonce_fixture_abcdef1234567890',
        pkceCodeVerifier: 'verifier_fixture_abcdef1234567890_secret_pkce',
      }),
    ).rejects.toMatchObject({ protocolCode: 'OIDC_ISSUER_MISMATCH' });

    // 2. State mismatch
    const wrongStateCb = new URL(REDIRECT_URI);
    wrongStateCb.searchParams.set('code', 'c1');
    wrongStateCb.searchParams.set('state', 'wrong_state_value');
    wrongStateCb.searchParams.set('iss', ISSUER_URL);
    await expect(
      oidc.exchangeAuthorizationCode({
        callbackUrl: wrongStateCb,
        expectedRedirectUri: REDIRECT_URI,
        expectedState: 'state_ok_1234567890',
        expectedNonce: 'nonce_fixture_abcdef1234567890',
        pkceCodeVerifier: 'verifier_fixture_abcdef1234567890_secret_pkce',
      }),
    ).rejects.toMatchObject({ protocolCode: 'OIDC_STATE_MISMATCH' });

    // 3. IdP authorization error parameter
    const errorCb = new URL(REDIRECT_URI);
    errorCb.searchParams.set('error', 'access_denied');
    errorCb.searchParams.set('state', 'state_ok_1234567890');
    errorCb.searchParams.set('iss', ISSUER_URL);
    await expect(
      oidc.exchangeAuthorizationCode({
        callbackUrl: errorCb,
        expectedRedirectUri: REDIRECT_URI,
        expectedState: 'state_ok_1234567890',
        expectedNonce: 'nonce_fixture_abcdef1234567890',
        pkceCodeVerifier: 'verifier_fixture_abcdef1234567890_secret_pkce',
      }),
    ).rejects.toMatchObject({ protocolCode: 'OIDC_AUTHORIZATION_ERROR' });

    // 4. Tampered callback host/path
    const wrongHostCb = new URL('https://evil.example/api/v1/auth/callback');
    wrongHostCb.searchParams.set('code', 'c1');
    wrongHostCb.searchParams.set('state', 'state_ok_1234567890');
    await expect(
      oidc.exchangeAuthorizationCode({
        callbackUrl: wrongHostCb,
        expectedRedirectUri: REDIRECT_URI,
        expectedState: 'state_ok_1234567890',
        expectedNonce: 'nonce_fixture_abcdef1234567890',
        pkceCodeVerifier: 'verifier_fixture_abcdef1234567890_secret_pkce',
      }),
    ).rejects.toMatchObject({ protocolCode: 'OIDC_REDIRECT_URI_NOT_ALLOWED' });
  });

  it('rejects ID token wrong issuer, wrong audience, wrong nonce, expired exp, invalid signature, and alg=none', async () => {
    const authCfg = createTestAuthConfig();
    const idp = createMockIdpTransport();
    const authService = createAuthServiceMock();
    const oidc = new OpenIdConnectClient(authCfg.oidc, { customFetch: idp.customFetch });
    const flow = new OidcAuthFlowCoordinator(authService, oidc, authCfg);

    const makeValidCb = () => {
      const cb = new URL(REDIRECT_URI);
      cb.searchParams.set('code', 'sensitive_auth_code_99999');
      cb.searchParams.set('state', 'state_fixture_abcdef1234567890');
      cb.searchParams.set('iss', ISSUER_URL);
      return cb;
    };

    // 1. Wrong issuer in ID Token
    idp.setTokenPayloadOverride((base) => ({ ...base, iss: 'https://rogue.example' }));
    await expect(
      oidc.exchangeAuthorizationCode({
        callbackUrl: makeValidCb(),
        expectedRedirectUri: REDIRECT_URI,
        expectedState: 'state_fixture_abcdef1234567890',
        expectedNonce: 'nonce_fixture_abcdef1234567890',
        pkceCodeVerifier: 'verifier_fixture_abcdef1234567890_secret_pkce',
      }),
    ).rejects.toMatchObject({ protocolCode: 'OIDC_ISSUER_MISMATCH' });

    // 2. Wrong audience in ID Token
    idp.setTokenPayloadOverride((base) => ({ ...base, aud: 'wrong-client-id' }));
    await expect(
      oidc.exchangeAuthorizationCode({
        callbackUrl: makeValidCb(),
        expectedRedirectUri: REDIRECT_URI,
        expectedState: 'state_fixture_abcdef1234567890',
        expectedNonce: 'nonce_fixture_abcdef1234567890',
        pkceCodeVerifier: 'verifier_fixture_abcdef1234567890_secret_pkce',
      }),
    ).rejects.toMatchObject({ protocolCode: 'OIDC_ID_TOKEN_AUDIENCE_MISMATCH' });

    // 3. Wrong nonce in ID Token (also verified via OidcAuthFlowCoordinator failure audit!)
    idp.setTokenPayloadOverride((base) => ({ ...base, nonce: 'attacker_replayed_nonce' }));
    await expect(
      flow.completeAuthorizationCallback({
        callbackUrl: makeValidCb(),
        rawTxnToken: 'raw_txn_token_fixture_1234567890',
      }),
    ).rejects.toMatchObject({ protocolCode: 'OIDC_NONCE_MISMATCH' });
    expect(authService.recordAuthenticationFailure).toHaveBeenCalledWith(
      expect.objectContaining({
        reason: 'OIDC_NONCE_MISMATCH',
      }),
    );

    // 4. Expired ID token beyond 30s clock tolerance
    const nowSec = Math.floor(Date.now() / 1000);
    idp.setTokenPayloadOverride((base) => ({ ...base, exp: nowSec - 120 }));
    await expect(
      oidc.exchangeAuthorizationCode({
        callbackUrl: makeValidCb(),
        expectedRedirectUri: REDIRECT_URI,
        expectedState: 'state_fixture_abcdef1234567890',
        expectedNonce: 'nonce_fixture_abcdef1234567890',
        pkceCodeVerifier: 'verifier_fixture_abcdef1234567890_secret_pkce',
      }),
    ).rejects.toMatchObject({ protocolCode: 'OIDC_ID_TOKEN_EXPIRED' });

    // 5. Invalid JWS signature (signed by untrusted private key with matching kid)
    idp.setTokenPayloadOverride(undefined);
    idp.setActiveSigningKey(idp.rogueKey);
    await expect(
      oidc.exchangeAuthorizationCode({
        callbackUrl: makeValidCb(),
        expectedRedirectUri: REDIRECT_URI,
        expectedState: 'state_fixture_abcdef1234567890',
        expectedNonce: 'nonce_fixture_abcdef1234567890',
        pkceCodeVerifier: 'verifier_fixture_abcdef1234567890_secret_pkce',
      }),
    ).rejects.toMatchObject({ protocolCode: 'OIDC_ID_TOKEN_INVALID_SIGNATURE' });

    // 6. Unsigned alg=none rejected
    idp.setIdTokenAlgOverride('none');
    await expect(
      oidc.exchangeAuthorizationCode({
        callbackUrl: makeValidCb(),
        expectedRedirectUri: REDIRECT_URI,
        expectedState: 'state_fixture_abcdef1234567890',
        expectedNonce: 'nonce_fixture_abcdef1234567890',
        pkceCodeVerifier: 'verifier_fixture_abcdef1234567890_secret_pkce',
      }),
    ).rejects.toBeInstanceOf(OidcProtocolError);
  });

  it('supports JWKS rotation after cooldown window while protecting against immediate unknown-kid refetch abuse', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-11-12T12:00:00Z'));

    const authCfg = createTestAuthConfig();
    const idp = createMockIdpTransport();
    const oidc = new OpenIdConnectClient(authCfg.oidc, { customFetch: idp.customFetch });

    const makeCb = () => {
      const cb = new URL(REDIRECT_URI);
      cb.searchParams.set('code', 'auth_code_rotation_1');
      cb.searchParams.set('state', 'state_fixture_abcdef1234567890');
      cb.searchParams.set('iss', ISSUER_URL);
      return cb;
    };

    // 1. Initial authentication caches JWKS containing kid-primary-1
    const first = await oidc.exchangeAuthorizationCode({
      callbackUrl: makeCb(),
      expectedRedirectUri: REDIRECT_URI,
      expectedState: 'state_fixture_abcdef1234567890',
      expectedNonce: 'nonce_fixture_abcdef1234567890',
      pkceCodeVerifier: 'verifier_fixture_abcdef1234567890_secret_pkce',
    });
    expect(first.sub).toBe('idp-sub-001');
    expect(idp.getJwksFetchCount()).toBe(1);

    // 2. IdP rotates keys immediately to kid-rotated-2
    idp.setActiveSigningKey(idp.rotatedKey);
    idp.setActiveJwks([idp.rotatedKey.publicJwk]);

    // Within 60s JWKS cooldown window: rejects without flooding /certs
    await expect(
      oidc.exchangeAuthorizationCode({
        callbackUrl: makeCb(),
        expectedRedirectUri: REDIRECT_URI,
        expectedState: 'state_fixture_abcdef1234567890',
        expectedNonce: 'nonce_fixture_abcdef1234567890',
        pkceCodeVerifier: 'verifier_fixture_abcdef1234567890_secret_pkce',
      }),
    ).rejects.toMatchObject({ protocolCode: 'OIDC_ID_TOKEN_INVALID_SIGNATURE' });
    expect(idp.getJwksFetchCount()).toBe(1);

    // 3. Advance past 60s cooldown: automatic JWKS refetch succeeds with rotated key!
    vi.advanceTimersByTime(65_000);
    const second = await oidc.exchangeAuthorizationCode({
      callbackUrl: makeCb(),
      expectedRedirectUri: REDIRECT_URI,
      expectedState: 'state_fixture_abcdef1234567890',
      expectedNonce: 'nonce_fixture_abcdef1234567890',
      pkceCodeVerifier: 'verifier_fixture_abcdef1234567890_secret_pkce',
    });
    expect(second.sub).toBe('idp-sub-001');
    expect(idp.getJwksFetchCount()).toBe(2);
  });

  it('never leaks authorization codes, PKCE verifiers, client secrets, or raw tokens in protocol failure errors or audit metadata', async () => {
    const authCfg = createTestAuthConfig();
    const idp = createMockIdpTransport();
    const authService = createAuthServiceMock();
    const oidc = new OpenIdConnectClient(authCfg.oidc, { customFetch: idp.customFetch });
    const flow = new OidcAuthFlowCoordinator(authService, oidc, authCfg);

    const sensitiveCode = 'very_sensitive_auth_code_999';
    const sensitiveVerifier = 'verifier_fixture_abcdef1234567890_secret_pkce';
    idp.setTokenHttpError({
      status: 400,
      body: {
        error: 'invalid_grant',
        error_description: `Code ${sensitiveCode} rejected with verifier ${sensitiveVerifier}`,
      },
    });

    const cb = new URL(REDIRECT_URI);
    cb.searchParams.set('code', sensitiveCode);
    cb.searchParams.set('state', 'state_fixture_abcdef1234567890');
    cb.searchParams.set('iss', ISSUER_URL);

    let capturedErrorText = '';
    try {
      await flow.completeAuthorizationCallback({
        callbackUrl: cb,
        rawTxnToken: 'raw_txn_token_fixture_1234567890',
      });
    } catch (err) {
      capturedErrorText = err instanceof Error ? `${err.message}\n${err.stack ?? ''}` : String(err);
    }

    expect(capturedErrorText).toContain('HTTP 400');
    expect(capturedErrorText).not.toContain(CLIENT_SECRET);
    expect(capturedErrorText).not.toContain(sensitiveCode);
    expect(capturedErrorText).not.toContain(sensitiveVerifier);
    expect(capturedErrorText).not.toContain('raw_txn_token_fixture_1234567890');

    expect(authService.recordAuthenticationFailure).toHaveBeenCalledWith(
      expect.objectContaining({
        reason: 'OIDC_TOKEN_EXCHANGE_FAILED',
        metadata: { protocolCode: 'OIDC_TOKEN_EXCHANGE_FAILED' },
      }),
    );
  });

  it('enforces RFC 9207 missing iss rejection when authorization_response_iss_parameter_supported is true and supports RP-initiated logout URL construction', async () => {
    const authCfg = createTestAuthConfig();
    const idp = createMockIdpTransport();
    const oidc = new OpenIdConnectClient(authCfg.oidc, { customFetch: idp.customFetch });

    // 1. Callback omitting `iss` when discovery advertises authorization_response_iss_parameter_supported: true MUST fail closed
    const missingIssCb = new URL(REDIRECT_URI);
    missingIssCb.searchParams.set('code', 'auth_code_missing_iss');
    missingIssCb.searchParams.set('state', 'state_fixture_abcdef1234567890');
    await expect(
      oidc.exchangeAuthorizationCode({
        callbackUrl: missingIssCb,
        expectedRedirectUri: REDIRECT_URI,
        expectedState: 'state_fixture_abcdef1234567890',
        expectedNonce: 'nonce_fixture_abcdef1234567890',
        pkceCodeVerifier: 'verifier_fixture_abcdef1234567890_secret_pkce',
      }),
    ).rejects.toMatchObject({ protocolCode: 'OIDC_ISSUER_MISMATCH' });

    // 2. When IdP does not advertise RFC 9207 iss support, discovery clearCache reloads metadata and callback without iss succeeds
    idp.setIssParamSupported(false);
    oidc.clearCache();
    const verifiedWithoutIss = await oidc.exchangeAuthorizationCode({
      callbackUrl: missingIssCb,
      expectedRedirectUri: REDIRECT_URI,
      expectedState: 'state_fixture_abcdef1234567890',
      expectedNonce: 'nonce_fixture_abcdef1234567890',
      pkceCodeVerifier: 'verifier_fixture_abcdef1234567890_secret_pkce',
    });
    expect(verifiedWithoutIss.issuer).toBe(ISSUER_URL);

    // 3. RP-initiated logout URL uses discovered end_session_endpoint + allowlisted post_logout_redirect_uri and no secrets/tokens
    const endSessionUrl = await oidc.buildEndSessionUrl();
    expect(endSessionUrl?.toString()).toContain(`${ISSUER_URL}/protocol/openid-connect/logout`);
    expect(endSessionUrl?.searchParams.get('client_id')).toBe(CLIENT_ID);
    expect(endSessionUrl?.searchParams.get('post_logout_redirect_uri')).toBe(
      authCfg.oidc.postLogoutRedirectUri,
    );
    expect(endSessionUrl?.searchParams.has('id_token_hint')).toBe(false);
    expect(endSessionUrl?.toString()).not.toContain(CLIENT_SECRET);

    // 4. Rejects unallowlisted postLogoutRedirectUri with OIDC_REDIRECT_URI_NOT_ALLOWED
    await expect(
      oidc.buildEndSessionUrl({ postLogoutRedirectUri: 'https://evil.example/phish' }),
    ).rejects.toMatchObject({ protocolCode: 'OIDC_REDIRECT_URI_NOT_ALLOWED' });

    // 5. Gracefully returns null if discovery metadata omits end_session_endpoint
    idp.setIncludeEndSessionEndpoint(false);
    oidc.clearCache();
    await expect(oidc.buildEndSessionUrl()).resolves.toBeNull();
  });
});
