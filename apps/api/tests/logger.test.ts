import { describe, it, expect } from 'vitest';
import pino from 'pino';
import { SENSITIVE_REDACTION_PATHS } from '../src/logger/logger.js';

describe('Pino Sensitive Data Redaction', () => {
  it('redacts sensitive headers, tokens, passwords, and cookies from log output', async () => {
    let loggedData = '';
    const destination = {
      write(chunk: string) {
        loggedData += chunk;
      },
    };

    const testLogger = pino(
      {
        level: 'info',
        redact: {
          paths: SENSITIVE_REDACTION_PATHS,
          censor: '[REDACTED]',
        },
      },
      destination
    );

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
    expect(parsedLog.user.secret).toBe('[REDACTED]');
    expect(loggedData).not.toContain('api-client-secret-xyz');

    // 5. Non-sensitive properties remain intact
    expect(parsedLog.req.method).toBe('POST');
    expect(parsedLog.req.headers['content-type']).toBe('application/json');
    expect(parsedLog.user.id).toBe('user-uuid-1');
  });
});
