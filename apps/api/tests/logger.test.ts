import { describe, it, expect } from 'vitest';
import express from 'express';
import request from 'supertest';
import { createLogger } from '../src/logger/logger.js';
import { createHttpLoggerMiddleware } from '../src/middleware/http-logger.js';

describe('Pino Sensitive Data Redaction', () => {
  it('redacts sensitive headers, tokens, passwords, and cookies from log output', async () => {
    let loggedData = '';
    const destination = {
      write(chunk: string) {
        loggedData += chunk;
      },
    };

    const testLogger = createLogger('info', destination);

    // Log payload with sensitive credentials and tokens
    testLogger.info({
      req: {
        method: 'POST',
        url: '/api/v1/auth/login',
        headers: {
          authorization: 'Bearer secret-jwt-token-12345',
          cookie: 'session_id=secure-cookie-abcde; Path=/',
          'set-cookie': 'refreshToken=refresh-secret-99999; HttpOnly',
          'content-type': 'application/json',
        },
      },
      user: {
        id: 'user-uuid-1',
        email: 'developer@secureflow.local',
        password: 'SuperSecretPassword123!',
        token: 'raw-access-token',
        accessToken: 'synthetic-access-token-value',
        refreshToken: 'synthetic-refresh-token-value',
        sessionSecret: 'synthetic-session-secret-value',
        clientSecret: 'synthetic-client-secret-value',
        databaseUrl: 'postgresql://user:pass@localhost:5433/db',
        connectionString: 'postgresql://user:pass@localhost:5433/db2',
        secret: 'api-client-secret-xyz',
      },
    });

    const parsedLog = JSON.parse(loggedData);

    // 1. Authorization header must be redacted
    expect(parsedLog.req.headers.authorization).toBe('[REDACTED]');
    expect(loggedData).not.toContain('secret-jwt-token-12345');

    // 2. Cookie headers must be redacted
    expect(parsedLog.req.headers.cookie).toBe('[REDACTED]');
    expect(loggedData).not.toContain('secure-cookie-abcde');

    // 3. Set-cookie must be redacted
    expect(parsedLog.req.headers['set-cookie']).toBe('[REDACTED]');
    expect(loggedData).not.toContain('refresh-secret-99999');

    // 4. Passwords, secrets, and raw tokens must be redacted
    expect(parsedLog.user.password).toBe('[REDACTED]');
    expect(loggedData).not.toContain('SuperSecretPassword123!');
    expect(parsedLog.user.token).toBe('[REDACTED]');
    expect(loggedData).not.toContain('raw-access-token');
    expect(parsedLog.user.accessToken).toBe('[REDACTED]');
    expect(loggedData).not.toContain('synthetic-access-token-value');
    expect(parsedLog.user.refreshToken).toBe('[REDACTED]');
    expect(loggedData).not.toContain('synthetic-refresh-token-value');
    expect(parsedLog.user.sessionSecret).toBe('[REDACTED]');
    expect(loggedData).not.toContain('synthetic-session-secret-value');
    expect(parsedLog.user.clientSecret).toBe('[REDACTED]');
    expect(loggedData).not.toContain('synthetic-client-secret-value');
    expect(parsedLog.user.databaseUrl).toBe('[REDACTED]');
    expect(loggedData).not.toContain('postgresql://user:pass@localhost:5433/db');
    expect(parsedLog.user.connectionString).toBe('[REDACTED]');
    expect(loggedData).not.toContain('postgresql://user:pass@localhost:5433/db2');
    expect(parsedLog.user.secret).toBe('[REDACTED]');
    expect(loggedData).not.toContain('api-client-secret-xyz');

    // 5. Non-sensitive properties remain intact
    expect(parsedLog.req.method).toBe('POST');
    expect(parsedLog.req.headers['content-type']).toBe('application/json');
    expect(parsedLog.user.id).toBe('user-uuid-1');
  });

  it('redacts arrays, case/separator variations, embedded credentials in nonsensitive fields, and structures beyond MAX_REDACTION_DEPTH without mutating inputs', () => {
    let loggedData = '';
    const destination = {
      write(chunk: string) {
        loggedData += chunk;
      },
    };

    const testLogger = createLogger('info', destination);

    // Construct a 12-level nested structure containing a secret beyond depth 10
    let deepNode: Record<string, unknown> = {
      hiddenDeepSecret: 'deep-unredacted-value-must-never-appear',
      password: 'deep-password-must-never-appear',
    };
    for (let d = 11; d >= 1; d--) {
      deepNode = { [`level_${d}`]: deepNode };
    }

    const originalPayload = {
      PASSWORD: 'root-uppercase-password',
      Access_Token: 'root-snake-access-token',
      'session-secret': 'root-kebab-session-secret',
      items: [
        {
          CLIENT_SECRET: 'array-client-secret-value',
          'database-url': 'postgresql://user:pass@localhost:5433/db_array',
          forensicNote: 'Preserved array forensic note',
        },
      ],
      notes:
        'Attempted connection to postgresql://user:pass@localhost:5433/db using Bearer synth_bearer_value_123',
      forensicStatus: 'VERIFIED',
      deepTree: deepNode,
    };

    testLogger.info(originalPayload);

    const parsedLog = JSON.parse(loggedData);

    // Case and separator variations redacted
    expect(parsedLog.PASSWORD).toBe('[REDACTED]');
    expect(parsedLog.Access_Token).toBe('[REDACTED]');
    expect(parsedLog['session-secret']).toBe('[REDACTED]');
    expect(parsedLog.items[0].CLIENT_SECRET).toBe('[REDACTED]');
    expect(parsedLog.items[0]['database-url']).toBe('[REDACTED]');

    // Embedded credential strings inside nonsensitive 'notes' field redacted
    expect(parsedLog.notes).toContain('postgresql://[REDACTED]');
    expect(parsedLog.notes).toContain('Bearer [REDACTED]');
    expect(loggedData).not.toContain('synth_bearer_value_123');
    expect(loggedData).not.toContain('postgresql://user:pass@localhost:5433/db');

    // Deep nesting beyond MAX_REDACTION_DEPTH = 10 replaced with [MAX_DEPTH_EXCEEDED]
    expect(loggedData).not.toContain('deep-unredacted-value-must-never-appear');
    expect(loggedData).not.toContain('deep-password-must-never-appear');
    expect(loggedData).toContain('[MAX_DEPTH_EXCEEDED]');

    // Legitimate forensic fields preserved
    expect(parsedLog.forensicStatus).toBe('VERIFIED');
    expect(parsedLog.items[0].forensicNote).toBe('Preserved array forensic note');

    // Original input object in memory not mutated
    expect(originalPayload.PASSWORD).toBe('root-uppercase-password');
    expect(originalPayload.items[0]?.CLIENT_SECRET).toBe('array-client-secret-value');
  });

  it('redacts Gate 4B.2 OIDC, PKCE, session, and anti-CSRF credentials in structured fields, headers, and error messages', () => {
    let loggedData = '';
    const destination = {
      write(chunk: string) {
        loggedData += chunk;
      },
    };

    const testLogger = createLogger('info', destination);

    testLogger.error({
      req: {
        headers: {
          cookie: '__Host-sf_session=synth-session-cookie-secret; __Host-sf_oidc_txn=synth-txn-cookie',
          'x-csrf-token': 'synth-csrf-header-value',
        },
      },
      authContext: {
        csrfToken: 'synth-csrf-field-value',
        codeVerifier: 'synth-pkce-verifier-value',
        pkceCodeVerifier: 'synth-pkce-code-verifier-2',
        authorizationCode: 'synth-auth-code-value',
        sessionId: 'synth-session-id-value',
        sessionToken: 'synth-session-token-value',
        rawSessionToken: 'synth-raw-session-token',
        rawTxnToken: 'synth-raw-txn-token',
        idToken: 'synth-id-token-value',
      },
      err: new Error(
        'Exchange failed with code_verifier=synth-url-verifier and client_secret=synth-url-secret and __Host-sf_session=synth-url-cookie',
      ),
    });

    const parsed = JSON.parse(loggedData);
    expect(parsed.req.headers.cookie).toBe('[REDACTED]');
    expect(parsed.req.headers['x-csrf-token']).toBe('[REDACTED]');
    expect(parsed.authContext.csrfToken).toBe('[REDACTED]');
    expect(parsed.authContext.codeVerifier).toBe('[REDACTED]');
    expect(parsed.authContext.pkceCodeVerifier).toBe('[REDACTED]');
    expect(parsed.authContext.authorizationCode).toBe('[REDACTED]');
    expect(parsed.authContext.sessionId).toBe('[REDACTED]');
    expect(parsed.authContext.sessionToken).toBe('[REDACTED]');
    expect(parsed.authContext.rawSessionToken).toBe('[REDACTED]');
    expect(parsed.authContext.rawTxnToken).toBe('[REDACTED]');
    expect(parsed.authContext.idToken).toBe('[REDACTED]');

    for (const leaked of [
      'synth-session-cookie-secret',
      'synth-txn-cookie',
      'synth-csrf-header-value',
      'synth-csrf-field-value',
      'synth-pkce-verifier-value',
      'synth-pkce-code-verifier-2',
      'synth-auth-code-value',
      'synth-session-id-value',
      'synth-session-token-value',
      'synth-raw-session-token',
      'synth-raw-txn-token',
      'synth-id-token-value',
      'synth-url-verifier',
      'synth-url-secret',
      'synth-url-cookie',
    ]) {
      expect(loggedData).not.toContain(leaked);
    }
  });

  it('redacts OIDC callback authorization codes, state, session_state, and id_token_hint query parameters from HTTP request logs', () => {
    let loggedData = '';
    const destination = {
      write(chunk: string) {
        loggedData += chunk;
      },
    };

    const testLogger = createLogger('info', destination);
    testLogger.info({
      req: {
        method: 'GET',
        url: '/api/v1/auth/callback?state=synth-oidc-state-secret-999&session_state=synth-kc-sess-888&iss=https%3A%2F%2Fidp.example%2Frealms%2Fsf&code=synth-auth-code-secret-777&id_token_hint=synth-id-hint-666',
        query: {
          state: 'synth-oidc-state-secret-999',
          session_state: 'synth-kc-sess-888',
          iss: 'https://idp.example/realms/sf',
          code: 'synth-auth-code-secret-777',
          id_token_hint: 'synth-id-hint-666',
        },
      },
      err: Object.assign(new Error('Callback failed cleanly'), { code: 'UNAUTHORIZED' }),
    });

    const parsed = JSON.parse(loggedData);
    expect(parsed.req.url).toContain('/api/v1/auth/callback?');
    expect(parsed.req.url).toContain('code=[REDACTED]');
    expect(parsed.req.url).toContain('state=[REDACTED]');
    expect(parsed.req.query.code).toBe('[REDACTED]');
    expect(parsed.req.query.state).toBe('[REDACTED]');
    expect(parsed.req.query.session_state).toBe('[REDACTED]');
    expect(parsed.req.query.id_token_hint).toBe('[REDACTED]');
    expect(parsed.req.query.iss).toBe('https://idp.example/realms/sf');
    expect(parsed.err.code).toBe('UNAUTHORIZED');
    for (const secret of [
      'synth-oidc-state-secret-999',
      'synth-kc-sess-888',
      'synth-auth-code-secret-777',
      'synth-id-hint-666',
    ]) {
      expect(loggedData).not.toContain(secret);
    }
  });

  it('scrubs OIDC callback code, state, and session_state end-to-end through createHttpLoggerMiddleware child logger bindings', async () => {
    let loggedData = '';
    const destination = {
      write(chunk: string) {
        loggedData += chunk;
      },
    };
    const testLogger = createLogger('info', destination);
    const app = express();
    app.use(createHttpLoggerMiddleware(testLogger));
    app.get('/api/v1/auth/callback', (_req, res) => {
      res.status(200).json({ ok: true });
    });

    const res = await request(app)
      .get('/api/v1/auth/callback')
      .query({
        state: 'synth-e2e-state-secret-111',
        session_state: 'synth-e2e-session-state-222',
        code: 'synth-e2e-auth-code-333',
        iss: 'https://idp.example/realms/secureflow',
      });

    expect(res.status).toBe(200);
    const parsed = JSON.parse(loggedData.trim().split('\n').pop()!);
    expect(parsed.res.statusCode).toBe(200);
    expect(parsed.req.url).toContain('code=[REDACTED]');
    expect(parsed.req.url).toContain('state=[REDACTED]');
    expect(parsed.req.query.code).toBe('[REDACTED]');
    expect(parsed.req.query.state).toBe('[REDACTED]');
    expect(parsed.req.query.session_state).toBe('[REDACTED]');
    expect(parsed.req.query.iss).toBe('https://idp.example/realms/secureflow');
    for (const secret of [
      'synth-e2e-state-secret-111',
      'synth-e2e-session-state-222',
      'synth-e2e-auth-code-333',
    ]) {
      expect(loggedData).not.toContain(secret);
    }
  });

  it('redacts OIDC state, nonce, and sensitive tokens from logged HTTP 302 Location headers while preserving the actual HTTP redirect response and safe diagnostics', async () => {
    let loggedData = '';
    const destination = {
      write(chunk: string) {
        loggedData += chunk;
      },
    };
    const testLogger = createLogger('info', destination);
    const app = express();
    app.use(createHttpLoggerMiddleware(testLogger));

    const rawState = 'synth-login-state-secret-84729';
    const rawNonce = 'synth-login-nonce-secret-95136';
    const rawTxnCookie = 'synth-oidc-txn-cookie-75319';
    const expectedRedirectUrl =
      'https://idp.example/realms/secureflow/protocol/openid-connect/auth' +
      '?redirect_uri=https%3A%2F%2Fapp.example%2Fapi%2Fv1%2Fauth%2Fcallback' +
      '&scope=openid+profile+email' +
      '&response_type=code' +
      '&code_challenge=public_pkce_challenge_digest' +
      '&code_challenge_method=S256' +
      `&state=${rawState}` +
      `&nonce=${rawNonce}` +
      '&client_id=secureflow-bff';

    app.get('/api/v1/auth/login', (_req, res) => {
      res.setHeader(
        'Set-Cookie',
        `__Host-sf_oidc_txn=${rawTxnCookie}; Path=/api/v1/auth; HttpOnly; Secure; SameSite=Lax`,
      );
      res.redirect(302, expectedRedirectUrl);
    });

    app.get('/projects', (_req, res) => {
      res.redirect(302, '/projects?tab=findings&status=OPEN');
    });

    const loginRes = await request(app)
      .get('/api/v1/auth/login?returnTo=%2Fprojects');

    // Browser receives the exact unmodified HTTP 302 redirect and cookie
    expect(loginRes.status).toBe(302);
    expect(loginRes.headers['location']).toBe(expectedRedirectUrl);
    expect(loginRes.headers['location']).toContain(rawState);
    expect(loginRes.headers['location']).toContain(rawNonce);

    const normalRes = await request(app).get('/projects');
    expect(normalRes.status).toBe(302);
    expect(normalRes.headers['location']).toBe('/projects?tab=findings&status=OPEN');

    interface HttpRedirectLogEntry {
      req: { method: string; url: string };
      res: { statusCode: number; headers: Record<string, string> };
    }

    const logLines = loggedData
      .trim()
      .split('\n')
      .map((line) => JSON.parse(line) as HttpRedirectLogEntry);
    expect(logLines).toHaveLength(2);

    const [loginLog, normalLog] = logLines as [HttpRedirectLogEntry, HttpRedirectLogEntry];
    expect(loginLog.req.method).toBe('GET');
    expect(loginLog.req.url).toBe('/api/v1/auth/login?returnTo=%2Fprojects');
    expect(loginLog.res.statusCode).toBe(302);
    expect(loginLog.res.headers['set-cookie']).toBe('[REDACTED]');
    expect(loginLog.res.headers.location).toContain(
      'https://idp.example/realms/secureflow/protocol/openid-connect/auth?',
    );
    expect(loginLog.res.headers.location).toContain('client_id=secureflow-bff');
    expect(loginLog.res.headers.location).toContain('response_type=code');
    expect(loginLog.res.headers.location).toContain('state=[REDACTED]');
    expect(loginLog.res.headers.location).toContain('nonce=[REDACTED]');

    // Non-OIDC redirect parameters remain intact for diagnostics
    expect(normalLog.res.statusCode).toBe(302);
    expect(normalLog.res.headers.location).toBe('/projects?tab=findings&status=OPEN');

    for (const secret of [rawState, rawNonce, rawTxnCookie]) {
      expect(loggedData).not.toContain(secret);
    }
  });

  it('redacts OAuth parameters in nested response header objects and Pino child logger bindings without dropping statusCode or error codes', () => {
    let loggedData = '';
    const destination = {
      write(chunk: string) {
        loggedData += chunk;
      },
    };
    const testLogger = createLogger('info', destination);

    const child = testLogger.child({
      res: {
        statusCode: 302,
        headers: {
          location:
            'https://app.example/logout-complete?state=synth-child-state-123&nonce=synth-child-nonce-456&id_token_hint=synth-child-hint-789&session_state=synth-child-sess-012&code=synth-child-code-345',
          nestedMeta: {
            redirectTarget:
              'https://web.example/cb#state=synth-frag-state-678&access_token=synth-frag-token-901',
          },
        },
      },
    });

    child.warn(
      {
        err: Object.assign(new Error('OIDC session mismatch'), {
          code: 'UNAUTHORIZED',
        }),
      },
      'redirect validation warning',
    );

    const parsed = JSON.parse(loggedData.trim());
    expect(parsed.res.statusCode).toBe(302);
    expect(parsed.err.code).toBe('UNAUTHORIZED');
    expect(parsed.res.headers.location).toContain('state=[REDACTED]');
    expect(parsed.res.headers.location).toContain('nonce=[REDACTED]');
    expect(parsed.res.headers.location).toContain('id_token_hint=[REDACTED]');
    expect(parsed.res.headers.location).toContain('session_state=[REDACTED]');
    expect(parsed.res.headers.location).toContain('code=[REDACTED]');
    expect(parsed.res.headers.nestedMeta.redirectTarget).toContain('state=[REDACTED]');
    expect(parsed.res.headers.nestedMeta.redirectTarget).toContain(
      'access_token=[REDACTED]',
    );

    for (const secret of [
      'synth-child-state-123',
      'synth-child-nonce-456',
      'synth-child-hint-789',
      'synth-child-sess-012',
      'synth-child-code-345',
      'synth-frag-state-678',
      'synth-frag-token-901',
    ]) {
      expect(loggedData).not.toContain(secret);
    }
  });
});
