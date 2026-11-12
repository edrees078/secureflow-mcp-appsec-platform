import pino from 'pino';
import { env } from '../config/env.js';
import {
  sanitizeAuditStateValue,
  sanitizeStringCredentialPatterns,
} from '../routes/v1/audit-events.js';

export const SENSITIVE_REDACTION_PATHS = [
  'req.headers.authorization',
  'req.headers.cookie',
  'req.headers["set-cookie"]',
  'req.headers["x-csrf-token"]',
  'headers.authorization',
  'headers.cookie',
  'headers["set-cookie"]',
  'headers["x-csrf-token"]',
  'authorization',
  'cookie',
  'set-cookie',
  'password',
  '*.password',
  '*.*.password',
  'token',
  '*.token',
  '*.*.token',
  'secret',
  '*.secret',
  '*.*.secret',
  'idToken',
  '*.idToken',
  '*.*.idToken',
  'refreshToken',
  '*.refreshToken',
  '*.*.refreshToken',
  'accessToken',
  '*.accessToken',
  '*.*.accessToken',
  'authorizationCode',
  '*.authorizationCode',
  '*.*.authorizationCode',
  'codeVerifier',
  '*.codeVerifier',
  '*.*.codeVerifier',
  'pkceCodeVerifier',
  '*.pkceCodeVerifier',
  '*.*.pkceCodeVerifier',
  'sessionId',
  '*.sessionId',
  '*.*.sessionId',
  'sessionToken',
  '*.sessionToken',
  '*.*.sessionToken',
  'rawSessionToken',
  '*.rawSessionToken',
  '*.*.rawSessionToken',
  'rawTxnToken',
  '*.rawTxnToken',
  '*.*.rawTxnToken',
  'csrfToken',
  '*.csrfToken',
  '*.*.csrfToken',
  'sessionSecret',
  '*.sessionSecret',
  '*.*.sessionSecret',
  'clientSecret',
  '*.clientSecret',
  '*.*.clientSecret',
  'databaseUrl',
  '*.databaseUrl',
  '*.*.databaseUrl',
  'connectionString',
  '*.connectionString',
  '*.*.connectionString',
  'apiKey',
  '*.apiKey',
  '*.*.apiKey',
];

function sanitizeErrorInstance(origErr: Error): Error {
  const safeMsg = sanitizeStringCredentialPatterns(origErr.message);
  const safeStack = origErr.stack
    ? sanitizeStringCredentialPatterns(origErr.stack)
    : undefined;
  if (safeMsg === origErr.message && safeStack === origErr.stack) {
    return origErr;
  }
  const redactedErr = new Error(safeMsg);
  redactedErr.name = origErr.name;
  if (safeStack !== undefined) {
    redactedErr.stack = safeStack;
  }
  return redactedErr;
}

export function sanitizeLogPayload(
  payload: Record<string, unknown>,
): Record<string, unknown> {
  const sanitized = sanitizeAuditStateValue(payload, 0) as Record<
    string,
    unknown
  >;
  if (payload['err'] instanceof Error) {
    sanitized['err'] = sanitizeErrorInstance(payload['err']);
  }
  return sanitized;
}

export function createLogger(
  logLevel = env.LOG_LEVEL,
  destination?: pino.DestinationStream,
) {
  const options: pino.LoggerOptions = {
    level: logLevel,
    redact: {
      paths: SENSITIVE_REDACTION_PATHS,
      censor: '[REDACTED]',
    },
    hooks: {
      logMethod(inputArgs, method) {
        const sanitizedArgs = inputArgs.map((arg, index) => {
          if (typeof arg === 'string') {
            return sanitizeStringCredentialPatterns(arg);
          }
          if (
            index === 0 &&
            arg !== null &&
            typeof arg === 'object' &&
            !Array.isArray(arg) &&
            'err' in arg &&
            (arg as { err?: unknown }).err instanceof Error
          ) {
            return {
              ...(arg as Record<string, unknown>),
              err: sanitizeErrorInstance((arg as { err: Error }).err),
            };
          }
          return arg;
        });
        return method.apply(this, sanitizedArgs as Parameters<typeof method>);
      },
    },
    formatters: {
      level(label) {
        return { level: label };
      },
      log(object) {
        return sanitizeLogPayload(object);
      },
    },
    timestamp: pino.stdTimeFunctions.isoTime,
  };

  return destination ? pino(options, destination) : pino(options);
}

export const logger = createLogger();
