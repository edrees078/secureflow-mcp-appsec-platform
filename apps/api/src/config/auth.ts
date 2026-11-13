import { z } from 'zod';
import { DomainValidationError } from '@secureflow/shared';
import {
  resolveCookieProfile,
  type CookieProfile,
  type CookieRuntimeMode,
} from '../auth/cookies.js';

export type OidcClientAuthMethod = 'client_secret_basic' | 'client_secret_post';

export interface OidcProtocolConfig {
  readonly issuerUrl: string;
  readonly clientId: string;
  readonly clientSecret: string;
  readonly clientAuthMethod: OidcClientAuthMethod;
  readonly redirectUri: string;
  readonly allowedRedirectUris: readonly string[];
  readonly postLogoutRedirectUri: string;
  readonly allowedPostLogoutRedirectUris: readonly string[];
  readonly scopes: string;
  readonly clockToleranceSeconds: number;
  readonly allowInsecureHttp: boolean;
  readonly requestTimeoutSeconds: number;
}

export interface SessionLifecycleConfig {
  readonly idleTimeoutSeconds: number;
  readonly absoluteTimeoutSeconds: number;
  readonly oidcTxnTtlSeconds: number;
}

export interface AuthRuntimeConfig {
  readonly mode: CookieRuntimeMode;
  readonly authEnabled: boolean;
  readonly oidc: OidcProtocolConfig;
  readonly session: SessionLifecycleConfig;
  readonly cookies: CookieProfile;
  readonly allowedOrigins: readonly string[];
}

const KNOWN_PLACEHOLDER_PATTERNS: ReadonlyArray<RegExp> = [
  /^change[_-]?me$/i,
  /change[_-]?me/i,
  /^placeholder$/i,
  /placeholder/i,
  /^dummy$/i,
  /^default$/i,
  /^secret$/i,
  /^password$/i,
  /^test[_-]?secret/i,
  /^dev[_-]?secret/i,
  /^secureflow_dev_/i,
  /^your[-_]?client[-_]?(?:id|secret)$/i,
  /^123456/,
];

const LOCALHOST_HOSTNAMES = new Set(['localhost', '127.0.0.1', '::1', '[::1]', '0.0.0.0']);

function parseOptionalBooleanFlag(
  raw: string | undefined,
  fieldName: string,
  defaultValue: boolean,
): boolean {
  if (raw === undefined || raw.trim() === '') {
    return defaultValue;
  }
  const normalized = raw.trim().toLowerCase();
  if (normalized === 'true' || normalized === '1') {
    return true;
  }
  if (normalized === 'false' || normalized === '0') {
    return false;
  }
  throw new DomainValidationError(`${fieldName} must be a boolean value ('true' or 'false')`);
}

/**
 * Checks whether a configured credential or identifier matches known placeholder patterns.
 */
export function isPlaceholderCredentialValue(value: string): boolean {
  const trimmed = value.trim();
  if (trimmed.length === 0) {
    return true;
  }
  return KNOWN_PLACEHOLDER_PATTERNS.some((pattern) => pattern.test(trimmed));
}

/**
 * Normalizes and validates an exact web origin (`scheme://host[:port]`) with no path, query, fragment, or userinfo.
 */
export function normalizeCanonicalOrigin(rawOrigin: string): string {
  const trimmed = rawOrigin.trim();
  if (!trimmed || trimmed === '*' || trimmed.includes('*')) {
    throw new DomainValidationError('Allowed origin must be an explicit origin without wildcards');
  }

  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    throw new DomainValidationError(`Invalid origin URL: '${trimmed}'`);
  }

  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    throw new DomainValidationError(`Origin must use http or https scheme: '${trimmed}'`);
  }
  if (parsed.username !== '' || parsed.password !== '') {
    throw new DomainValidationError('Origin must not contain embedded userinfo credentials');
  }
  if (parsed.pathname !== '/' || parsed.search !== '' || parsed.hash !== '') {
    throw new DomainValidationError(`Origin must not contain path, query, or fragment: '${trimmed}'`);
  }

  return parsed.origin;
}

/**
 * Normalizes an OIDC issuer or callback redirect URI while rejecting fragments, wildcards, and embedded credentials.
 */
export function normalizeCanonicalHttpUrl(rawUrl: string, label: string): string {
  const trimmed = rawUrl.trim();
  if (!trimmed || trimmed.includes('*')) {
    throw new DomainValidationError(`${label} must be a valid explicit URL without wildcards`);
  }

  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    throw new DomainValidationError(`${label} must be a valid absolute URL`);
  }

  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    throw new DomainValidationError(`${label} must use http or https protocol`);
  }
  if (parsed.username !== '' || parsed.password !== '') {
    throw new DomainValidationError(`${label} must not embed credentials in URL`);
  }
  if (parsed.hash !== '') {
    throw new DomainValidationError(`${label} must not contain a URL fragment`);
  }

  return parsed.toString();
}

/**
 * Enforces exact redirect URI membership against the pre-configured allowlist.
 */
export function normalizeAndValidateRedirectUri(
  candidateRedirectUri: string,
  allowlist: readonly string[],
  requireHttps: boolean,
): string {
  const normalizedCandidate = normalizeCanonicalHttpUrl(candidateRedirectUri, 'Redirect URI');
  const candidateUrl = new URL(normalizedCandidate);

  if (requireHttps && candidateUrl.protocol !== 'https:') {
    throw new DomainValidationError('Redirect URI must use https in production mode');
  }

  const normalizedAllowlist = new Set(
    allowlist.map((entry) => normalizeCanonicalHttpUrl(entry, 'Allowed redirect URI')),
  );

  if (!normalizedAllowlist.has(normalizedCandidate)) {
    throw new DomainValidationError(
      'Redirect URI is not present in the configured OIDC redirect URI allowlist',
    );
  }

  return normalizedCandidate;
}

const RawAuthEnvSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  AUTH_ENABLED: z.string().optional(),
  CORS_ORIGIN: z.string().trim().min(1).default('http://127.0.0.1:5173,http://localhost:5173'),
  OIDC_ISSUER_URL: z.string().trim().optional(),
  OIDC_CLIENT_ID: z.string().trim().optional(),
  OIDC_CLIENT_SECRET: z.string().trim().optional(),
  OIDC_CLIENT_AUTH_METHOD: z
    .enum(['client_secret_basic', 'client_secret_post'])
    .default('client_secret_basic'),
  OIDC_REDIRECT_URI: z.string().trim().optional(),
  OIDC_ALLOWED_REDIRECT_URIS: z.string().trim().optional(),
  OIDC_POST_LOGOUT_REDIRECT_URI: z.string().trim().optional(),
  OIDC_ALLOWED_POST_LOGOUT_REDIRECT_URIS: z.string().trim().optional(),
  OIDC_SCOPES: z.string().trim().optional(),
  OIDC_CLOCK_TOLERANCE_SECONDS: z
    .string()
    .trim()
    .optional()
    .transform((v) => (v && v.length > 0 ? Number(v) : 30))
    .pipe(z.number().int().min(0).max(300)),
  OIDC_ALLOW_INSECURE_HTTP: z.string().optional(),
  OIDC_REQUEST_TIMEOUT_SECONDS: z
    .string()
    .trim()
    .optional()
    .transform((v) => (v && v.length > 0 ? Number(v) : 10))
    .pipe(z.number().int().min(1).max(60)),
  SESSION_IDLE_TIMEOUT_SECONDS: z
    .string()
    .trim()
    .optional()
    .transform((v) => (v && v.length > 0 ? Number(v) : 1800))
    .pipe(z.number().int().min(60).max(86400)),
  SESSION_ABSOLUTE_TIMEOUT_SECONDS: z
    .string()
    .trim()
    .optional()
    .transform((v) => (v && v.length > 0 ? Number(v) : 28800))
    .pipe(z.number().int().min(300).max(604800)),
  OIDC_TXN_TTL_SECONDS: z
    .string()
    .trim()
    .optional()
    .transform((v) => (v && v.length > 0 ? Number(v) : 300))
    .pipe(z.number().int().min(30).max(900)),
  SESSION_COOKIE_SECURE: z.string().optional(),
});

function validateOidcUriList(
  primaryUri: string,
  extraCsv: string | undefined,
  extraFieldName: string,
  isProduction: boolean,
  label: string,
): readonly string[] {
  const extraUris = (extraCsv ?? '')
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0)
    .map((entry) => normalizeCanonicalHttpUrl(entry, extraFieldName));

  const allowlist = Array.from(new Set([primaryUri, ...extraUris]));
  for (const uri of allowlist) {
    const parsedUri = new URL(uri);
    if (isProduction) {
      if (parsedUri.protocol !== 'https:') {
        throw new DomainValidationError(
          `All OIDC ${label} URIs must use https protocol in production`,
        );
      }
      if (LOCALHOST_HOSTNAMES.has(parsedUri.hostname.toLowerCase())) {
        throw new DomainValidationError(
          `OIDC ${label} URIs must not target localhost or loopback addresses in production`,
        );
      }
    }
  }
  return Object.freeze(allowlist);
}

/**
 * Validates OIDC, session lifecycle, cookie profile, and origin configuration cleanly
 * without echoing secret values in exceptions.
 */
export function loadAuthConfig(
  override?: Partial<Record<string, string | undefined>>,
): AuthRuntimeConfig {
  const source: Record<string, string | undefined> = override
    ? { ...process.env, ...override }
    : { ...process.env };

  const parsedEnv = RawAuthEnvSchema.safeParse(source);
  if (!parsedEnv.success) {
    const safeIssues = parsedEnv.error.issues.map((issue) => ({
      path: issue.path.join('.'),
      code: issue.code,
      message: issue.message,
    }));
    throw new DomainValidationError('Invalid authentication configuration schema', safeIssues);
  }

  const raw = parsedEnv.data;
  const runtimeMode: CookieRuntimeMode =
    raw.NODE_ENV === 'production' ? 'production' : 'development';
  const isProduction = runtimeMode === 'production';

  const authEnabled = parseOptionalBooleanFlag(raw.AUTH_ENABLED, 'AUTH_ENABLED', false);
  const allowInsecureHttp = parseOptionalBooleanFlag(
    raw.OIDC_ALLOW_INSECURE_HTTP,
    'OIDC_ALLOW_INSECURE_HTTP',
    false,
  );
  const cookieSecureOverride =
    raw.SESSION_COOKIE_SECURE !== undefined && raw.SESSION_COOKIE_SECURE.trim() !== ''
      ? parseOptionalBooleanFlag(raw.SESSION_COOKIE_SECURE, 'SESSION_COOKIE_SECURE', isProduction)
      : undefined;

  if (isProduction && allowInsecureHttp) {
    throw new DomainValidationError(
      'OIDC_ALLOW_INSECURE_HTTP must be false in production environment',
    );
  }
  if (isProduction && cookieSecureOverride === false) {
    throw new DomainValidationError(
      'SESSION_COOKIE_SECURE cannot be false in production environment',
    );
  }

  const cookies = resolveCookieProfile(runtimeMode, {
    ...(cookieSecureOverride !== undefined ? { secure: cookieSecureOverride } : {}),
  });

  if (!raw.OIDC_ISSUER_URL) {
    throw new DomainValidationError('OIDC_ISSUER_URL is required');
  }
  const issuerUrl = normalizeCanonicalHttpUrl(raw.OIDC_ISSUER_URL, 'OIDC_ISSUER_URL');
  const parsedIssuer = new URL(issuerUrl);

  if (isProduction) {
    if (parsedIssuer.protocol !== 'https:') {
      throw new DomainValidationError('OIDC_ISSUER_URL must use https protocol in production');
    }
    if (LOCALHOST_HOSTNAMES.has(parsedIssuer.hostname.toLowerCase())) {
      throw new DomainValidationError(
        'OIDC_ISSUER_URL must not target localhost or loopback addresses in production',
      );
    }
  } else if (parsedIssuer.protocol === 'http:' && !allowInsecureHttp) {
    throw new DomainValidationError(
      'HTTP OIDC_ISSUER_URL requires explicit OIDC_ALLOW_INSECURE_HTTP=true in development/test',
    );
  }

  if (!raw.OIDC_CLIENT_ID || raw.OIDC_CLIENT_ID.length < 2) {
    throw new DomainValidationError('OIDC_CLIENT_ID is required');
  }
  if (isProduction && isPlaceholderCredentialValue(raw.OIDC_CLIENT_ID)) {
    throw new DomainValidationError('OIDC_CLIENT_ID must not use placeholder values in production');
  }

  if (!raw.OIDC_CLIENT_SECRET || raw.OIDC_CLIENT_SECRET.length === 0) {
    throw new DomainValidationError('OIDC_CLIENT_SECRET is required');
  }
  if (isProduction) {
    if (raw.OIDC_CLIENT_SECRET.length < 16) {
      throw new DomainValidationError(
        'OIDC_CLIENT_SECRET must be at least 16 characters in production',
      );
    }
    if (isPlaceholderCredentialValue(raw.OIDC_CLIENT_SECRET)) {
      throw new DomainValidationError(
        'OIDC_CLIENT_SECRET must not use development/placeholder credentials in production',
      );
    }
  }

  if (!raw.OIDC_REDIRECT_URI) {
    throw new DomainValidationError('OIDC_REDIRECT_URI is required');
  }
  const primaryRedirectUri = normalizeCanonicalHttpUrl(raw.OIDC_REDIRECT_URI, 'OIDC_REDIRECT_URI');
  const allowedRedirectUris = validateOidcUriList(
    primaryRedirectUri,
    raw.OIDC_ALLOWED_REDIRECT_URIS,
    'OIDC_ALLOWED_REDIRECT_URIS',
    isProduction,
    'redirect',
  );

  const scopesRaw = raw.OIDC_SCOPES && raw.OIDC_SCOPES.length > 0
    ? raw.OIDC_SCOPES
    : 'openid profile email';
  const scopeTokens = scopesRaw.split(/\s+/).filter(Boolean);
  if (!scopeTokens.includes('openid')) {
    throw new DomainValidationError('OIDC_SCOPES must include the mandatory openid scope');
  }

  if (raw.SESSION_IDLE_TIMEOUT_SECONDS > raw.SESSION_ABSOLUTE_TIMEOUT_SECONDS) {
    throw new DomainValidationError(
      'SESSION_IDLE_TIMEOUT_SECONDS cannot exceed SESSION_ABSOLUTE_TIMEOUT_SECONDS',
    );
  }

  const allowedOrigins = Array.from(
    new Set(
      raw.CORS_ORIGIN.split(',')
        .map((origin) => origin.trim())
        .filter(Boolean)
        .map((origin) => normalizeCanonicalOrigin(origin)),
    ),
  );
  if (allowedOrigins.length === 0) {
    throw new DomainValidationError('At least one valid CORS_ORIGIN is required');
  }
  if (isProduction) {
    for (const origin of allowedOrigins) {
      const parsedOrigin = new URL(origin);
      if (parsedOrigin.protocol !== 'https:') {
        throw new DomainValidationError('Allowed origins must use https protocol in production');
      }
      if (LOCALHOST_HOSTNAMES.has(parsedOrigin.hostname.toLowerCase())) {
        throw new DomainValidationError(
          'Allowed origins must not target localhost or loopback addresses in production',
        );
      }
    }
  }

  const primaryPostLogoutRedirectUri =
    raw.OIDC_POST_LOGOUT_REDIRECT_URI && raw.OIDC_POST_LOGOUT_REDIRECT_URI.length > 0
      ? normalizeCanonicalHttpUrl(raw.OIDC_POST_LOGOUT_REDIRECT_URI, 'OIDC_POST_LOGOUT_REDIRECT_URI')
      : `${allowedOrigins[0]}/login`;
  const allowedPostLogoutRedirectUris = validateOidcUriList(
    primaryPostLogoutRedirectUri,
    raw.OIDC_ALLOWED_POST_LOGOUT_REDIRECT_URIS,
    'OIDC_ALLOWED_POST_LOGOUT_REDIRECT_URIS',
    isProduction,
    'post-logout redirect',
  );

  return Object.freeze({
    mode: runtimeMode,
    authEnabled,
    oidc: Object.freeze({
      issuerUrl,
      clientId: raw.OIDC_CLIENT_ID,
      clientSecret: raw.OIDC_CLIENT_SECRET,
      clientAuthMethod: raw.OIDC_CLIENT_AUTH_METHOD,
      redirectUri: primaryRedirectUri,
      allowedRedirectUris,
      postLogoutRedirectUri: primaryPostLogoutRedirectUri,
      allowedPostLogoutRedirectUris,
      scopes: scopeTokens.join(' '),
      clockToleranceSeconds: raw.OIDC_CLOCK_TOLERANCE_SECONDS,
      allowInsecureHttp,
      requestTimeoutSeconds: raw.OIDC_REQUEST_TIMEOUT_SECONDS,
    }),
    session: Object.freeze({
      idleTimeoutSeconds: raw.SESSION_IDLE_TIMEOUT_SECONDS,
      absoluteTimeoutSeconds: raw.SESSION_ABSOLUTE_TIMEOUT_SECONDS,
      oidcTxnTtlSeconds: raw.OIDC_TXN_TTL_SECONDS,
    }),
    cookies,
    allowedOrigins: Object.freeze(allowedOrigins),
  });
}
