import { z } from 'zod';
import dotenv from 'dotenv';
import {
  isPlaceholderCredentialValue,
  loadAuthConfig,
} from './auth.js';

// Load .env file into process.env if present
dotenv.config();

const DEV_DEFAULT_DATABASE_URL =
  'postgresql://secureflow:secureflow_dev_password_change_me@127.0.0.1:5433/secureflow_dev?schema=public';

const FORBIDDEN_PRODUCTION_DB_MARKERS = [
  'secureflow_dev_password_change_me',
  'ci_dummy_pass',
  'ci_dummy_user',
  '/ci_dummy_db',
  '/secureflow_dev',
  '/secureflow_test',
  ':5433/',
];

export const envSchema = z
  .object({
    NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
    PORT: z
      .string()
      .default('3000')
      .transform((val) => parseInt(val, 10))
      .pipe(z.number().int().min(1).max(65535)),
    LOG_LEVEL: z
      .enum(['trace', 'debug', 'info', 'warn', 'error', 'fatal'])
      .default('info'),
    CORS_ORIGIN: z.string().min(1).default('http://localhost:5173'),
    DATABASE_URL: z.string().trim().optional(),
    AUTH_ENABLED: z.enum(['true', 'false']).default('false'),
    OIDC_ISSUER_URL: z.string().trim().optional(),
    OIDC_CLIENT_ID: z.string().trim().optional(),
    OIDC_CLIENT_SECRET: z.string().trim().optional(),
    OIDC_CLIENT_AUTH_METHOD: z
      .enum(['client_secret_basic', 'client_secret_post'])
      .optional(),
    OIDC_REDIRECT_URI: z.string().trim().optional(),
    OIDC_ALLOWED_REDIRECT_URIS: z.string().trim().optional(),
    OIDC_SCOPES: z.string().trim().optional(),
    OIDC_CLOCK_TOLERANCE_SECONDS: z.string().trim().optional(),
    OIDC_ALLOW_INSECURE_HTTP: z.enum(['true', 'false']).optional(),
    OIDC_REQUEST_TIMEOUT_SECONDS: z.string().trim().optional(),
    SESSION_IDLE_TIMEOUT_SECONDS: z.string().trim().optional(),
    SESSION_ABSOLUTE_TIMEOUT_SECONDS: z.string().trim().optional(),
    OIDC_TXN_TTL_SECONDS: z.string().trim().optional(),
    SESSION_COOKIE_SECURE: z.enum(['true', 'false']).optional(),
    BOOTSTRAP_ADMIN_OIDC_SUB: z.string().trim().optional(),
  })
  .superRefine((data, ctx) => {
    if (data.NODE_ENV === 'production') {
      if (!data.DATABASE_URL || data.DATABASE_URL.length === 0) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['DATABASE_URL'],
          message: 'DATABASE_URL must be explicitly configured in production environment',
        });
        return;
      }

      for (const marker of FORBIDDEN_PRODUCTION_DB_MARKERS) {
        if (data.DATABASE_URL.includes(marker)) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: ['DATABASE_URL'],
            message:
              'Production environment must not fall back to or use development/test placeholder DATABASE_URL credentials',
          });
          break;
        }
      }

      if (data.OIDC_ALLOW_INSECURE_HTTP === 'true') {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['OIDC_ALLOW_INSECURE_HTTP'],
          message: 'OIDC_ALLOW_INSECURE_HTTP must not be enabled in production environment',
        });
      }

      if (data.SESSION_COOKIE_SECURE === 'false') {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['SESSION_COOKIE_SECURE'],
          message: 'SESSION_COOKIE_SECURE must not be false in production environment',
        });
      }

      if (
        data.OIDC_CLIENT_SECRET !== undefined &&
        (data.OIDC_CLIENT_SECRET.length < 16 || isPlaceholderCredentialValue(data.OIDC_CLIENT_SECRET))
      ) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['OIDC_CLIENT_SECRET'],
          message: 'Production OIDC_CLIENT_SECRET must not use placeholder or short values',
        });
      }

      if (
        data.BOOTSTRAP_ADMIN_OIDC_SUB !== undefined &&
        isPlaceholderCredentialValue(data.BOOTSTRAP_ADMIN_OIDC_SUB)
      ) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['BOOTSTRAP_ADMIN_OIDC_SUB'],
          message: 'Production BOOTSTRAP_ADMIN_OIDC_SUB must not use placeholder values',
        });
      }
    }

    const hasPartialOidcConfig = Boolean(
      data.AUTH_ENABLED === 'true' ||
      data.OIDC_ISSUER_URL ||
      data.OIDC_CLIENT_ID ||
      data.OIDC_CLIENT_SECRET ||
      data.OIDC_REDIRECT_URI,
    );

    if (hasPartialOidcConfig) {
      try {
        loadAuthConfig({
          NODE_ENV: data.NODE_ENV,
          AUTH_ENABLED: data.AUTH_ENABLED,
          CORS_ORIGIN: data.CORS_ORIGIN,
          OIDC_ISSUER_URL: data.OIDC_ISSUER_URL,
          OIDC_CLIENT_ID: data.OIDC_CLIENT_ID,
          OIDC_CLIENT_SECRET: data.OIDC_CLIENT_SECRET,
          OIDC_CLIENT_AUTH_METHOD: data.OIDC_CLIENT_AUTH_METHOD,
          OIDC_REDIRECT_URI: data.OIDC_REDIRECT_URI,
          OIDC_ALLOWED_REDIRECT_URIS: data.OIDC_ALLOWED_REDIRECT_URIS,
          OIDC_SCOPES: data.OIDC_SCOPES,
          OIDC_CLOCK_TOLERANCE_SECONDS: data.OIDC_CLOCK_TOLERANCE_SECONDS,
          OIDC_ALLOW_INSECURE_HTTP: data.OIDC_ALLOW_INSECURE_HTTP,
          OIDC_REQUEST_TIMEOUT_SECONDS: data.OIDC_REQUEST_TIMEOUT_SECONDS,
          SESSION_IDLE_TIMEOUT_SECONDS: data.SESSION_IDLE_TIMEOUT_SECONDS,
          SESSION_ABSOLUTE_TIMEOUT_SECONDS: data.SESSION_ABSOLUTE_TIMEOUT_SECONDS,
          OIDC_TXN_TTL_SECONDS: data.OIDC_TXN_TTL_SECONDS,
          SESSION_COOKIE_SECURE: data.SESSION_COOKIE_SECURE,
        });
      } catch (err) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['AUTH_ENABLED'],
          message:
            err instanceof Error
              ? err.message
              : 'Invalid OIDC/session security configuration',
        });
      }
    }
  })
  .transform((data) => ({
    ...data,
    AUTH_ENABLED: data.AUTH_ENABLED === 'true',
    DATABASE_URL:
      data.DATABASE_URL && data.DATABASE_URL.length > 0
        ? data.DATABASE_URL
        : DEV_DEFAULT_DATABASE_URL,
  }));

export type EnvConfig = z.output<typeof envSchema>;

export function loadEnv(
  override?: Partial<Record<string, string | undefined>>,
): EnvConfig {
  const source: Record<string, string | undefined> = {
    ...process.env,
    ...override,
  };

  const result = envSchema.safeParse(source);
  if (!result.success) {
    const safeIssues = result.error.issues.map((issue) => ({
      path: issue.path.join('.'),
      code: issue.code,
      message: issue.message,
    }));
    throw new Error(
      `Invalid environment configuration:\n${JSON.stringify(safeIssues, null, 2)}`,
    );
  }

  return result.data;
}

export const env = loadEnv();
