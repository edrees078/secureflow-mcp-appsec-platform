import { DomainValidationError } from '@secureflow/shared';

export const COOKIE_NAME_PRODUCTION_SESSION = '__Host-sf_session' as const;
export const COOKIE_NAME_PRODUCTION_OIDC_TXN = '__Host-sf_oidc_txn' as const;
export const COOKIE_NAME_DEV_SESSION = 'sf_session' as const;
export const COOKIE_NAME_DEV_OIDC_TXN = 'sf_oidc_txn' as const;

const MAX_COOKIE_HEADER_LENGTH = 16 * 1024;
const MAX_COOKIE_PAIRS = 100;
const MAX_COOKIE_VALUE_LENGTH = 4096;

/** RFC 6265 token characters for cookie names. */
const COOKIE_NAME_REGEX = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

/**
 * RFC 6265 cookie-octet characters (US-ASCII printable excluding whitespace, DQUOTE, comma, semicolon, backslash).
 */
const COOKIE_VALUE_REGEX = /^[\x21\x23-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]*$/;

/** Control characters including NUL, CR, LF, and DEL. */
const CONTROL_CHAR_REGEX = /[\x00-\x1f\x7f]/;

export type CookieRuntimeMode = 'production' | 'development';
export type CookieSameSite = 'Lax' | 'Strict';

export interface CookieProfile {
  readonly mode: CookieRuntimeMode;
  readonly sessionCookieName:
    | typeof COOKIE_NAME_PRODUCTION_SESSION
    | typeof COOKIE_NAME_DEV_SESSION;
  readonly oidcTxnCookieName:
    | typeof COOKIE_NAME_PRODUCTION_OIDC_TXN
    | typeof COOKIE_NAME_DEV_OIDC_TXN;
  readonly secure: boolean;
  readonly httpOnly: true;
  readonly sameSite: 'Lax';
  readonly path: '/';
  readonly domain?: never;
}

export interface CookieSerializeOptions {
  readonly httpOnly?: boolean;
  readonly secure?: boolean;
  readonly sameSite?: CookieSameSite;
  readonly path?: string;
  readonly domain?: string;
  readonly maxAge?: number;
  readonly expires?: Date;
}

export interface ParsedCookiePair {
  readonly name: string;
  readonly value: string;
}

export interface CookieHeaderParseResult {
  readonly valid: boolean;
  readonly reason?: string;
  readonly occurrences: ReadonlyMap<string, readonly string[]>;
  readonly malformedNames: ReadonlySet<string>;
}

export type CookieExtractionStatus = 'ok' | 'missing' | 'duplicate' | 'malformed';

export interface CookieExtractionResult {
  readonly present: boolean;
  readonly status: CookieExtractionStatus;
  readonly value: string | null;
  readonly reason?: string;
}

/**
 * Resolves the active cookie profile while enforcing strict separation between
 * production `__Host-` host-locked cookies and local HTTP development cookies.
 */
export function resolveCookieProfile(
  mode: CookieRuntimeMode,
  options?: { readonly secure?: boolean },
): CookieProfile {
  if (mode === 'production') {
    if (options?.secure === false) {
      throw new DomainValidationError(
        'Production cookie profile strictly requires Secure=true',
      );
    }

    return Object.freeze({
      mode: 'production',
      sessionCookieName: COOKIE_NAME_PRODUCTION_SESSION,
      oidcTxnCookieName: COOKIE_NAME_PRODUCTION_OIDC_TXN,
      secure: true,
      httpOnly: true,
      sameSite: 'Lax',
      path: '/',
    });
  }

  return Object.freeze({
    mode: 'development',
    sessionCookieName: COOKIE_NAME_DEV_SESSION,
    oidcTxnCookieName: COOKIE_NAME_DEV_OIDC_TXN,
    secure: options?.secure ?? false,
    httpOnly: true,
    sameSite: 'Lax',
    path: '/',
  });
}

function assertValidCookieName(name: string): void {
  if (
    typeof name !== 'string' ||
    name.length === 0 ||
    name.length > 256 ||
    !COOKIE_NAME_REGEX.test(name)
  ) {
    throw new DomainValidationError(`Invalid RFC 6265 cookie name: '${name}'`);
  }
}

function assertValidCookieValue(value: string, allowEmpty: boolean): void {
  if (typeof value !== 'string') {
    throw new DomainValidationError('Cookie value must be a string');
  }
  if (!allowEmpty && value.length === 0) {
    throw new DomainValidationError('Cookie value must not be empty');
  }
  if (value.length > MAX_COOKIE_VALUE_LENGTH) {
    throw new DomainValidationError(
      `Cookie value exceeds maximum allowed length (${MAX_COOKIE_VALUE_LENGTH})`,
    );
  }
  if (CONTROL_CHAR_REGEX.test(value) || !COOKIE_VALUE_REGEX.test(value)) {
    throw new DomainValidationError('Cookie value contains forbidden or non-RFC6265 characters');
  }
}

function assertValidCookieOptions(
  name: string,
  options: CookieSerializeOptions,
  isClearing: boolean,
): void {
  if (options.path !== undefined) {
    if (
      options.path.length === 0 ||
      !options.path.startsWith('/') ||
      options.path.includes(';') ||
      CONTROL_CHAR_REGEX.test(options.path)
    ) {
      throw new DomainValidationError('Cookie Path attribute is invalid');
    }
  }

  if (options.domain !== undefined) {
    if (
      options.domain.length === 0 ||
      options.domain.includes(';') ||
      CONTROL_CHAR_REGEX.test(options.domain)
    ) {
      throw new DomainValidationError('Cookie Domain attribute is invalid');
    }
  }

  if (options.maxAge !== undefined) {
    if (!Number.isInteger(options.maxAge) || options.maxAge < 0) {
      throw new DomainValidationError('Cookie Max-Age must be a non-negative integer');
    }
  }

  if (options.expires !== undefined) {
    if (!(options.expires instanceof Date) || Number.isNaN(options.expires.getTime())) {
      throw new DomainValidationError('Cookie Expires must be a valid Date');
    }
  }

  if (name.startsWith('__Host-')) {
    if (options.secure !== true) {
      throw new DomainValidationError(
        `Cookie '${name}' with __Host- prefix requires Secure=true`,
      );
    }
    if (options.path !== '/') {
      throw new DomainValidationError(
        `Cookie '${name}' with __Host- prefix requires Path=/`,
      );
    }
    if (options.domain !== undefined) {
      throw new DomainValidationError(
        `Cookie '${name}' with __Host- prefix must omit Domain attribute`,
      );
    }
  } else if (name.startsWith('__Secure-')) {
    if (options.secure !== true) {
      throw new DomainValidationError(
        `Cookie '${name}' with __Secure- prefix requires Secure=true`,
      );
    }
  }

  if (isClearing && options.maxAge !== 0) {
    throw new DomainValidationError('Cookie clearing requires Max-Age=0');
  }
}

/**
 * Serializes a single Set-Cookie header value while enforcing RFC 6265 syntax
 * and `__Host-` / `__Secure-` prefix invariants.
 */
export function serializeCookie(
  name: string,
  value: string,
  options: CookieSerializeOptions = {},
): string {
  const isClearing = options.maxAge === 0 && value === '';
  assertValidCookieName(name);
  assertValidCookieValue(value, isClearing);
  assertValidCookieOptions(name, options, isClearing);

  const parts: string[] = [`${name}=${value}`];

  if (options.maxAge !== undefined) {
    parts.push(`Max-Age=${options.maxAge}`);
  }
  if (options.expires !== undefined) {
    parts.push(`Expires=${options.expires.toUTCString()}`);
  }
  if (options.domain !== undefined) {
    parts.push(`Domain=${options.domain}`);
  }
  if (options.path !== undefined) {
    parts.push(`Path=${options.path}`);
  }
  if (options.httpOnly) {
    parts.push('HttpOnly');
  }
  if (options.secure) {
    parts.push('Secure');
  }
  if (options.sameSite) {
    parts.push(`SameSite=${options.sameSite}`);
  }

  return parts.join('; ');
}

/**
 * Serializes the authoritative server-managed session cookie using the active profile.
 */
export function serializeSessionCookie(
  profile: CookieProfile,
  rawSessionToken: string,
  maxAgeSeconds: number,
): string {
  if (!Number.isInteger(maxAgeSeconds) || maxAgeSeconds <= 0) {
    throw new DomainValidationError('Session cookie maxAgeSeconds must be a positive integer');
  }
  return serializeCookie(profile.sessionCookieName, rawSessionToken, {
    httpOnly: profile.httpOnly,
    secure: profile.secure,
    sameSite: profile.sameSite,
    path: profile.path,
    maxAge: maxAgeSeconds,
  });
}

/**
 * Serializes the single-use OIDC transaction cookie using the active profile.
 */
export function serializeOidcTxnCookie(
  profile: CookieProfile,
  rawTxnToken: string,
  maxAgeSeconds: number,
): string {
  if (!Number.isInteger(maxAgeSeconds) || maxAgeSeconds <= 0) {
    throw new DomainValidationError('OIDC transaction cookie maxAgeSeconds must be a positive integer');
  }
  return serializeCookie(profile.oidcTxnCookieName, rawTxnToken, {
    httpOnly: profile.httpOnly,
    secure: profile.secure,
    sameSite: profile.sameSite,
    path: profile.path,
    maxAge: maxAgeSeconds,
  });
}

function serializeClearedCookie(profile: CookieProfile, cookieName: string): string {
  return serializeCookie(cookieName, '', {
    httpOnly: profile.httpOnly,
    secure: profile.secure,
    sameSite: profile.sameSite,
    path: profile.path,
    maxAge: 0,
    expires: new Date(0),
  });
}

/**
 * Serializes an immediate expiration header value to clear the session cookie.
 */
export function clearSessionCookie(profile: CookieProfile): string {
  return serializeClearedCookie(profile, profile.sessionCookieName);
}

/**
 * Serializes an immediate expiration header value to clear the OIDC transaction cookie.
 */
export function clearOidcTxnCookie(profile: CookieProfile): string {
  return serializeClearedCookie(profile, profile.oidcTxnCookieName);
}

/**
 * Parses an HTTP `Cookie` header (or repeated header array) while preserving duplicates
 * and detecting malformed syntax without silently dropping ambiguity.
 */
export function parseCookieHeader(
  rawCookieHeader: string | readonly string[] | undefined,
): CookieHeaderParseResult {
  const occurrences = new Map<string, string[]>();
  const malformedNames = new Set<string>();

  if (rawCookieHeader === undefined) {
    return { valid: true, occurrences, malformedNames };
  }

  const headerParts = Array.isArray(rawCookieHeader) ? rawCookieHeader : [rawCookieHeader];
  const nonEmptyParts = headerParts.filter((part): part is string => typeof part === 'string');

  if (nonEmptyParts.length !== headerParts.length) {
    return {
      valid: false,
      reason: 'INVALID_COOKIE_HEADER_TYPE',
      occurrences,
      malformedNames,
    };
  }

  const joined = nonEmptyParts.join('; ');
  if (joined.trim().length === 0) {
    return { valid: true, occurrences, malformedNames };
  }

  if (joined.length > MAX_COOKIE_HEADER_LENGTH) {
    return {
      valid: false,
      reason: 'COOKIE_HEADER_TOO_LARGE',
      occurrences,
      malformedNames,
    };
  }

  if (CONTROL_CHAR_REGEX.test(joined)) {
    return {
      valid: false,
      reason: 'COOKIE_HEADER_CONTROL_CHAR',
      occurrences,
      malformedNames,
    };
  }

  const rawSegments = nonEmptyParts.flatMap((header) => header.split(';'));
  if (rawSegments.length > MAX_COOKIE_PAIRS) {
    return {
      valid: false,
      reason: 'COOKIE_PAIR_LIMIT_EXCEEDED',
      occurrences,
      malformedNames,
    };
  }

  let hasInvalidSyntax = false;
  let failureReason: string | undefined;

  for (const rawSegment of rawSegments) {
    const segment = rawSegment.trim();
    if (segment.length === 0) {
      hasInvalidSyntax = true;
      failureReason ??= 'EMPTY_COOKIE_SEGMENT';
      continue;
    }

    const eqIndex = segment.indexOf('=');
    if (eqIndex <= 0) {
      hasInvalidSyntax = true;
      failureReason ??= 'MALFORMED_COOKIE_PAIR';
      if (COOKIE_NAME_REGEX.test(segment)) {
        malformedNames.add(segment);
      }
      continue;
    }

    const name = segment.slice(0, eqIndex);
    const value = segment.slice(eqIndex + 1);

    if (!COOKIE_NAME_REGEX.test(name)) {
      hasInvalidSyntax = true;
      failureReason ??= 'INVALID_COOKIE_NAME';
      continue;
    }

    if (value.length > MAX_COOKIE_VALUE_LENGTH || !COOKIE_VALUE_REGEX.test(value)) {
      hasInvalidSyntax = true;
      failureReason ??= 'INVALID_COOKIE_VALUE';
      malformedNames.add(name);
      continue;
    }

    const existing = occurrences.get(name);
    if (existing) {
      existing.push(value);
    } else {
      occurrences.set(name, [value]);
    }
  }

  return {
    valid: !hasInvalidSyntax,
    ...(failureReason ? { reason: failureReason } : {}),
    occurrences,
    malformedNames,
  };
}

/**
 * Extracts a single named cookie deterministically:
 * - Rejects duplicate cookie occurrences (`status: 'duplicate'`).
 * - Rejects malformed syntax (`status: 'malformed'`).
 * - Never falls back from prefixed names (`__Host-`) to unprefixed names.
 */
export function extractNamedCookie(
  rawCookieHeader: string | readonly string[] | undefined,
  expectedCookieName: string,
): CookieExtractionResult {
  assertValidCookieName(expectedCookieName);

  const parsed = parseCookieHeader(rawCookieHeader);
  if (!parsed.valid) {
    if (parsed.malformedNames.has(expectedCookieName)) {
      return {
        present: false,
        status: 'malformed',
        value: null,
        reason: parsed.reason ?? 'MALFORMED_TARGET_COOKIE',
      };
    }

    if (
      parsed.reason === 'COOKIE_HEADER_TOO_LARGE' ||
      parsed.reason === 'COOKIE_HEADER_CONTROL_CHAR' ||
      parsed.reason === 'COOKIE_PAIR_LIMIT_EXCEEDED' ||
      parsed.reason === 'INVALID_COOKIE_HEADER_TYPE'
    ) {
      return {
        present: false,
        status: 'malformed',
        value: null,
        reason: parsed.reason,
      };
    }
  }

  const values = parsed.occurrences.get(expectedCookieName);
  if (!values || values.length === 0) {
    if (!parsed.valid) {
      return {
        present: false,
        status: 'malformed',
        value: null,
        reason: parsed.reason ?? 'MALFORMED_COOKIE_HEADER',
      };
    }
    return {
      present: false,
      status: 'missing',
      value: null,
    };
  }

  if (values.length > 1) {
    return {
      present: false,
      status: 'duplicate',
      value: null,
      reason: 'DUPLICATE_COOKIE',
    };
  }

  const singleValue = values[0];
  if (!singleValue || singleValue.trim().length === 0) {
    return {
      present: false,
      status: 'malformed',
      value: null,
      reason: 'EMPTY_COOKIE_VALUE',
    };
  }

  return {
    present: true,
    status: 'ok',
    value: singleValue,
  };
}

/**
 * Reads the authoritative session cookie strictly matching the active cookie profile.
 * In production mode, unprefixed `sf_session` cookies are ignored (never used as fallback).
 */
export function readSessionCookie(
  rawCookieHeader: string | readonly string[] | undefined,
  profile: CookieProfile,
): CookieExtractionResult {
  return extractNamedCookie(rawCookieHeader, profile.sessionCookieName);
}

/**
 * Reads the OIDC transaction cookie strictly matching the active cookie profile.
 * In production mode, unprefixed `sf_oidc_txn` cookies are ignored (never used as fallback).
 */
export function readOidcTxnCookie(
  rawCookieHeader: string | readonly string[] | undefined,
  profile: CookieProfile,
): CookieExtractionResult {
  return extractNamedCookie(rawCookieHeader, profile.oidcTxnCookieName);
}
