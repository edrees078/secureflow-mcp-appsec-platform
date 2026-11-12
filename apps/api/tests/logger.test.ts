import { describe, it, expect } from 'vitest';
import { createLogger } from '../src/logger/logger.js';

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
});
