import { z } from 'zod';
import dotenv from 'dotenv';

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
    }
  })
  .transform((data) => ({
    ...data,
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
