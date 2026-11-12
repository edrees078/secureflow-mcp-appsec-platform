import { describe, it, expect } from 'vitest';
import {
  loadAuthConfig,
  normalizeAndValidateRedirectUri,
} from '../../src/config/auth.js';
import { loadEnv } from '../../src/config/env.js';

const PROD_SYNTHETIC_DB_URL =
  'postgresql://secureflow:synthetic_prod_fixture_placeholder@localhost:5432/secureflow_prod?schema=public';

const PROD_VALID_AUTH_VARS = {
  NODE_ENV: 'production',
  DATABASE_URL: PROD_SYNTHETIC_DB_URL,
  AUTH_ENABLED: 'true',
  CORS_ORIGIN: 'https://app.secureflow.example',
  OIDC_ISSUER_URL: 'https://idp.secureflow.example/realms/secureflow',
  OIDC_CLIENT_ID: 'secureflow-bff-prod',
  OIDC_CLIENT_SECRET: 'synth-prod-client-secret-fixture-value-98765',
  OIDC_REDIRECT_URI: 'https://app.secureflow.example/api/v1/auth/callback',
  OIDC_ALLOWED_REDIRECT_URIS: 'https://app.secureflow.example/api/v1/auth/callback',
  OIDC_ALLOW_INSECURE_HTTP: 'false',
  SESSION_COOKIE_SECURE: 'true',
};

describe('Gate 4B.2 Authentication & Security Configuration Validation', () => {
  it('loads valid development HTTP auth config with unprefixed dev cookies cleanly separated from prod', () => {
    const cfg = loadAuthConfig({
      NODE_ENV: 'development',
      CORS_ORIGIN: 'http://localhost:5173',
      OIDC_ISSUER_URL: 'http://localhost:8080/realms/secureflow',
      OIDC_CLIENT_ID: 'secureflow-bff-dev',
      OIDC_CLIENT_SECRET: 'synth-dev-secret-value',
      OIDC_REDIRECT_URI: 'http://localhost:3000/api/v1/auth/callback',
      OIDC_ALLOW_INSECURE_HTTP: 'true',
    });

    expect(cfg.mode).toBe('development');
    expect(cfg.cookies.sessionCookieName).toBe('sf_session');
    expect(cfg.cookies.oidcTxnCookieName).toBe('sf_oidc_txn');
    expect(cfg.cookies.secure).toBe(false);
    expect(cfg.oidc.allowInsecureHttp).toBe(true);
    expect(cfg.allowedOrigins).toEqual(['http://localhost:5173']);
  });

  it('loads valid hardened production HTTPS auth config with __Host- cookies', () => {
    const cfg = loadAuthConfig(PROD_VALID_AUTH_VARS);

    expect(cfg.mode).toBe('production');
    expect(cfg.cookies.sessionCookieName).toBe('__Host-sf_session');
    expect(cfg.cookies.oidcTxnCookieName).toBe('__Host-sf_oidc_txn');
    expect(cfg.cookies.secure).toBe(true);
    expect(cfg.cookies.httpOnly).toBe(true);
    expect(cfg.cookies.sameSite).toBe('Lax');
    expect(cfg.cookies.path).toBe('/');
    expect(cfg.cookies.domain).toBeUndefined();
    expect(cfg.oidc.allowInsecureHttp).toBe(false);
  });

  it('rejects missing required OIDC fields cleanly', () => {
    for (const missingKey of [
      'OIDC_ISSUER_URL',
      'OIDC_CLIENT_ID',
      'OIDC_CLIENT_SECRET',
      'OIDC_REDIRECT_URI',
    ] as const) {
      const envCopy: Partial<Record<string, string | undefined>> = {
        ...PROD_VALID_AUTH_VARS,
        [missingKey]: undefined,
      };
      expect(() => loadAuthConfig(envCopy)).toThrow();
    }
  });

  it('rejects insecure HTTP, localhost, wildcard origins, and insecure cookie flags in production', () => {
    expect(() =>
      loadAuthConfig({
        ...PROD_VALID_AUTH_VARS,
        OIDC_ALLOW_INSECURE_HTTP: 'true',
      }),
    ).toThrow(/OIDC_ALLOW_INSECURE_HTTP/);

    expect(() =>
      loadAuthConfig({
        ...PROD_VALID_AUTH_VARS,
        SESSION_COOKIE_SECURE: 'false',
      }),
    ).toThrow(/SESSION_COOKIE_SECURE/);

    expect(() =>
      loadAuthConfig({
        ...PROD_VALID_AUTH_VARS,
        OIDC_ISSUER_URL: 'http://idp.secureflow.example/realms/secureflow',
      }),
    ).toThrow(/https/);

    expect(() =>
      loadAuthConfig({
        ...PROD_VALID_AUTH_VARS,
        OIDC_ISSUER_URL: 'https://localhost:8443/realms/secureflow',
      }),
    ).toThrow(/localhost/);

    expect(() =>
      loadAuthConfig({
        ...PROD_VALID_AUTH_VARS,
        OIDC_REDIRECT_URI: 'http://app.secureflow.example/callback',
      }),
    ).toThrow(/https/);

    expect(() =>
      loadAuthConfig({
        ...PROD_VALID_AUTH_VARS,
        CORS_ORIGIN: '*',
      }),
    ).toThrow(/wildcard/);

    expect(() =>
      loadAuthConfig({
        ...PROD_VALID_AUTH_VARS,
        CORS_ORIGIN: 'http://app.secureflow.example',
      }),
    ).toThrow(/https/);
  });

  it('rejects placeholder or short client secrets and bootstrap subjects in production without leaking secrets', () => {
    const unsafeSecrets = [
      'change_me',
      'placeholder-secret-value',
      'secureflow_dev_secret_value',
      'short',
    ];

    for (const badSecret of unsafeSecrets) {
      let thrown = '';
      try {
        loadAuthConfig({
          ...PROD_VALID_AUTH_VARS,
          OIDC_CLIENT_SECRET: badSecret,
        });
      } catch (err) {
        thrown = err instanceof Error ? err.message : String(err);
      }

      expect(thrown).toMatch(/OIDC_CLIENT_SECRET/);
      expect(thrown).not.toContain(badSecret);
    }

    expect(() =>
      loadEnv({
        NODE_ENV: 'production',
        DATABASE_URL: PROD_SYNTHETIC_DB_URL,
        OIDC_ALLOW_INSECURE_HTTP: 'true',
      }),
    ).toThrow(/OIDC_ALLOW_INSECURE_HTTP/);

    expect(() =>
      loadEnv({
        NODE_ENV: 'production',
        DATABASE_URL: PROD_SYNTHETIC_DB_URL,
        SESSION_COOKIE_SECURE: 'false',
      }),
    ).toThrow(/SESSION_COOKIE_SECURE/);

    expect(() =>
      loadEnv({
        NODE_ENV: 'production',
        DATABASE_URL: PROD_SYNTHETIC_DB_URL,
        BOOTSTRAP_ADMIN_OIDC_SUB: 'placeholder',
      }),
    ).toThrow(/BOOTSTRAP_ADMIN_OIDC_SUB/);
  });

  it('enforces idle <= absolute session timeout, mandatory openid scope, and strict redirect allowlist', () => {
    expect(() =>
      loadAuthConfig({
        ...PROD_VALID_AUTH_VARS,
        SESSION_IDLE_TIMEOUT_SECONDS: '36000',
        SESSION_ABSOLUTE_TIMEOUT_SECONDS: '28800',
      }),
    ).toThrow(/SESSION_IDLE_TIMEOUT_SECONDS/);

    expect(() =>
      loadAuthConfig({
        ...PROD_VALID_AUTH_VARS,
        OIDC_SCOPES: 'profile email',
      }),
    ).toThrow(/openid/);

    expect(() =>
      loadAuthConfig({
        ...PROD_VALID_AUTH_VARS,
        OIDC_REDIRECT_URI: 'https://app.secureflow.example/callback#fragment',
      }),
    ).toThrow(/fragment/);

    const allowlist = ['https://app.secureflow.example/api/v1/auth/callback'];
    expect(
      normalizeAndValidateRedirectUri(
        'https://app.secureflow.example/api/v1/auth/callback',
        allowlist,
        true,
      ),
    ).toBe('https://app.secureflow.example/api/v1/auth/callback');

    expect(() =>
      normalizeAndValidateRedirectUri(
        'https://app.secureflow.example/api/v1/auth/callback-evil',
        allowlist,
        true,
      ),
    ).toThrow(/allowlist/);

    expect(() =>
      normalizeAndValidateRedirectUri(
        'http://app.secureflow.example/api/v1/auth/callback',
        allowlist,
        true,
      ),
    ).toThrow(/https/);
  });

  it('validates OIDC_POST_LOGOUT_REDIRECT_URI and OIDC_ALLOWED_POST_LOGOUT_REDIRECT_URIS including production HTTPS enforcement', () => {
    const prodConfig = loadAuthConfig({
      NODE_ENV: 'production',
      AUTH_ENABLED: 'true',
      CORS_ORIGIN: 'https://app.secureflow.example',
      OIDC_ISSUER_URL: 'https://idp.secureflow.example/realms/secureflow',
      OIDC_CLIENT_ID: 'secureflow-bff',
      OIDC_CLIENT_SECRET: 'prod-strong-client-secret-value-over-16-chars',
      OIDC_REDIRECT_URI: 'https://app.secureflow.example/api/v1/auth/callback',
      OIDC_POST_LOGOUT_REDIRECT_URI: 'https://app.secureflow.example/login',
      OIDC_ALLOWED_POST_LOGOUT_REDIRECT_URIS: 'https://app.secureflow.example/signed-out',
    });

    expect(prodConfig.oidc.postLogoutRedirectUri).toBe('https://app.secureflow.example/login');
    expect(prodConfig.oidc.allowedPostLogoutRedirectUris).toEqual([
      'https://app.secureflow.example/login',
      'https://app.secureflow.example/signed-out',
    ]);

    expect(() =>
      loadAuthConfig({
        NODE_ENV: 'production',
        AUTH_ENABLED: 'true',
        CORS_ORIGIN: 'https://app.secureflow.example',
        OIDC_ISSUER_URL: 'https://idp.secureflow.example/realms/secureflow',
        OIDC_CLIENT_ID: 'secureflow-bff',
        OIDC_CLIENT_SECRET: 'prod-strong-client-secret-value-over-16-chars',
        OIDC_REDIRECT_URI: 'https://app.secureflow.example/api/v1/auth/callback',
        OIDC_POST_LOGOUT_REDIRECT_URI: 'http://app.secureflow.example/login',
      }),
    ).toThrow(/https/i);
  });
});
