import { z } from 'zod';
import dotenv from 'dotenv';

// Load .env file into process.env if present
dotenv.config();

export const envSchema = z.object({
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
});

export type EnvConfig = z.infer<typeof envSchema>;

export function loadEnv(override?: Partial<Record<string, string>>): EnvConfig {
  const source = {
    ...process.env,
    ...override,
  };

  const result = envSchema.safeParse(source);
  if (!result.success) {
    const formatted = result.error.format();
    throw new Error(
      `Invalid environment configuration:\n${JSON.stringify(formatted, null, 2)}`
    );
  }

  return result.data;
}

export const env = loadEnv();
