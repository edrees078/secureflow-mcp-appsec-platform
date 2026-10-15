import { describe, it, expect } from 'vitest';
import { loadEnv } from '../src/config/env.js';

describe('Environment Configuration & Validation', () => {
  it('loads valid default environment values', () => {
    const config = loadEnv({
      NODE_ENV: 'development',
      PORT: '3000',
      LOG_LEVEL: 'info',
      CORS_ORIGIN: 'http://localhost:5173',
    });

    expect(config.NODE_ENV).toBe('development');
    expect(config.PORT).toBe(3000);
    expect(config.LOG_LEVEL).toBe('info');
    expect(config.CORS_ORIGIN).toBe('http://localhost:5173');
  });

  it('rejects non-numeric PORT values', () => {
    expect(() =>
      loadEnv({
        PORT: 'not-a-number',
      })
    ).toThrow(/Invalid environment configuration/);
  });

  it('rejects out-of-range PORT values', () => {
    expect(() =>
      loadEnv({
        PORT: '70000',
      })
    ).toThrow(/Invalid environment configuration/);

    expect(() =>
      loadEnv({
        PORT: '0',
      })
    ).toThrow(/Invalid environment configuration/);
  });

  it('rejects invalid NODE_ENV values', () => {
    expect(() =>
      loadEnv({
        NODE_ENV: 'staging' as unknown as string,
      })
    ).toThrow(/Invalid environment configuration/);
  });

  it('rejects invalid LOG_LEVEL values', () => {
    expect(() =>
      loadEnv({
        LOG_LEVEL: 'verbose' as unknown as string,
      })
    ).toThrow(/Invalid environment configuration/);
  });
});
