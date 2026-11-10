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
  'headers.authorization',
  'headers.cookie',
  'headers["set-cookie"]',
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
  'refreshToken',
  '*.refreshToken',
  '*.*.refreshToken',
  'accessToken',
  '*.accessToken',
  '*.*.accessToken',
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

export function sanitizeLogPayload(
  payload: Record<string, unknown>,
): Record<string, unknown> {
  const sanitized = sanitizeAuditStateValue(payload, 0) as Record<
    string,
    unknown
  >;
  if (payload['err'] instanceof Error) {
    const origErr = payload['err'];
    const safeMsg = sanitizeStringCredentialPatterns(origErr.message);
    if (safeMsg === origErr.message) {
      sanitized['err'] = origErr;
    } else {
      const redactedErr = new Error(safeMsg);
      redactedErr.name = origErr.name;
      if (origErr.stack) {
        redactedErr.stack = sanitizeStringCredentialPatterns(origErr.stack);
      }
      sanitized['err'] = redactedErr;
    }
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
