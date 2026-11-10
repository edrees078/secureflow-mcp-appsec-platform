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

  it('rejects missing or empty DATABASE_URL in production environment', () => {
    expect(() =>
      loadEnv({
        NODE_ENV: 'production',
        DATABASE_URL: undefined,
      })
    ).toThrow(/DATABASE_URL must be explicitly configured in production environment/);

    expect(() =>
      loadEnv({
        NODE_ENV: 'production',
        DATABASE_URL: '   ',
      })
    ).toThrow(/DATABASE_URL must be explicitly configured in production environment/);
  });

  it('prevents production fallback to development default, CI dummy, or local test DATABASE_URL credentials', () => {
    // 1. Development placeholder password / database rejected
    expect(() =>
      loadEnv({
        NODE_ENV: 'production',
        DATABASE_URL:
          'postgresql://secureflow:secureflow_dev_password_change_me@127.0.0.1:5433/secureflow_dev?schema=public',
      })
    ).toThrow(
      /Production environment must not fall back to or use development\/test placeholder DATABASE_URL credentials/
    );

    // 2. CI dummy credentials rejected
    expect(() =>
      loadEnv({
        NODE_ENV: 'production',
        DATABASE_URL:
          'postgresql://ci_dummy_user:ci_dummy_pass@127.0.0.1:5432/ci_dummy_db?schema=public',
      })
    ).toThrow(
      /Production environment must not fall back to or use development\/test placeholder DATABASE_URL credentials/
    );

    // 3. Local test database (secureflow_test / port 5433) rejected in production
    expect(() =>
      loadEnv({
        NODE_ENV: 'production',
        DATABASE_URL:
          'postgresql://secureflow:pass@127.0.0.1:5433/secureflow_test?schema=public',
      })
    ).toThrow(
      /Production environment must not fall back to or use development\/test placeholder DATABASE_URL credentials/
    );

    // 4. Dedicated production configuration succeeds
    const prodConfig = loadEnv({
      NODE_ENV: 'production',
      DATABASE_URL:
        'postgresql://secureflow:synthetic_prod_fixture_placeholder@localhost:5432/secureflow_prod?schema=public',
    });
    expect(prodConfig.NODE_ENV).toBe('production');
  });

  it('does not print or echo sensitive DATABASE_URL values in configuration error messages', () => {
    const sensitiveCandidateUrl =
      'postgresql://secureflow:secureflow_dev_password_change_me@127.0.0.1:5433/secureflow_dev?schema=public';

    let thrownMessage = '';
    try {
      loadEnv({
        NODE_ENV: 'production',
        PORT: 'invalid-port',
        DATABASE_URL: sensitiveCandidateUrl,
      });
    } catch (err) {
      thrownMessage = err instanceof Error ? `${err.message}\n${err.stack ?? ''}` : String(err);
    }

    expect(thrownMessage).toContain('Invalid environment configuration');
    expect(thrownMessage).not.toContain('secureflow_dev_password_change_me');
    expect(thrownMessage).not.toContain(sensitiveCandidateUrl);
  });
});
