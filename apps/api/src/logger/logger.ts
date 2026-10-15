import pino from 'pino';
import { env } from '../config/env.js';

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
  'clientSecret',
  '*.clientSecret',
  '*.*.clientSecret',
];

export function createLogger(logLevel = env.LOG_LEVEL) {
  return pino({
    level: logLevel,
    redact: {
      paths: SENSITIVE_REDACTION_PATHS,
      censor: '[REDACTED]',
    },
    formatters: {
      level(label) {
        return { level: label };
      },
    },
    timestamp: pino.stdTimeFunctions.isoTime,
  });
}

export const logger = createLogger();
