import { createHash, timingSafeEqual } from 'node:crypto';
import type { Request, Response, NextFunction, RequestHandler } from 'express';
import { DomainValidationError, ForbiddenError } from '@secureflow/shared';
import { normalizeCanonicalOrigin } from '../config/auth.js';

const SAFE_READ_METHODS = new Set(['GET', 'HEAD']);
const ALLOWED_STATE_CHANGE_FETCH_SITES = new Set(['same-origin', 'same-site']);
const MAX_CSRF_HEADER_LENGTH = 256;

export interface CsrfMiddlewareOptions {
  /** Strictly allowed browser origins (exact scheme + host + optional port). */
  readonly allowedOrigins: readonly string[];
  /** Custom HTTP header name carrying the anti-CSRF token (defaults to `x-csrf-token`). */
  readonly headerName?: string;
  /** Authoritative resolver returning the server-side session-bound CSRF token. */
  readonly resolveSessionCsrfToken?: (req: Request) => string | null | undefined;
}

function constantTimeCompareStrings(a: string, b: string): boolean {
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  const digestA = createHash('sha256').update(bufA).digest();
  const digestB = createHash('sha256').update(bufB).digest();
  return timingSafeEqual(digestA, digestB) && bufA.byteLength === bufB.byteLength;
}

function readSingleHeaderValue(
  req: Request,
  headerName: string,
): { readonly present: boolean; readonly duplicate: boolean; readonly value?: string } {
  const lower = headerName.toLowerCase();
  const raw = req.headers[lower];
  if (raw === undefined) {
    return { present: false, duplicate: false };
  }
  if (Array.isArray(raw)) {
    return { present: true, duplicate: true };
  }
  // RFC 9110: Origin, Referer, Sec-Fetch-Site, and anti-CSRF token headers cannot contain commas.
  // When Node HTTP parser encounters repeated headers, it joins them with a comma.
  if (raw.includes(',')) {
    return { present: true, duplicate: true, value: raw };
  }
  if (Array.isArray(req.rawHeaders)) {
    let count = 0;
    for (let i = 0; i < req.rawHeaders.length; i += 2) {
      if (req.rawHeaders[i]?.toLowerCase() === lower) {
        count++;
        if (count > 1) {
          return { present: true, duplicate: true, value: raw };
        }
      }
    }
  }
  return { present: true, duplicate: false, value: raw };
}

function extractCanonicalOriginFromUrl(rawUrl: string): string | null {
  try {
    const parsed = new URL(rawUrl);
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
      return null;
    }
    if (parsed.origin === 'null') {
      return null;
    }
    return parsed.origin;
  } catch {
    return null;
  }
}

/**
 * Validates `Origin` (primary) or `Referer` (fallback) against exact allowed origins.
 * Fails closed when neither header is present on state-changing requests.
 */
function validateRequestOrigin(
  req: Request,
  allowedOriginSet: ReadonlySet<string>,
): void {
  const originHeader = readSingleHeaderValue(req, 'origin');
  if (originHeader.duplicate) {
    throw new ForbiddenError('CSRF validation failed: duplicate Origin header rejected');
  }

  if (originHeader.present) {
    const rawOrigin = originHeader.value?.trim() ?? '';
    if (!rawOrigin || rawOrigin.toLowerCase() === 'null') {
      throw new ForbiddenError('CSRF validation failed: untrusted or null Origin rejected');
    }
    const parsedOrigin = extractCanonicalOriginFromUrl(rawOrigin);
    if (!parsedOrigin || !allowedOriginSet.has(parsedOrigin)) {
      throw new ForbiddenError('CSRF validation failed: Origin not allowed');
    }
    return;
  }

  const refererHeader = readSingleHeaderValue(req, 'referer');
  if (refererHeader.duplicate) {
    throw new ForbiddenError('CSRF validation failed: duplicate Referer header rejected');
  }

  if (refererHeader.present) {
    const rawReferer = refererHeader.value?.trim() ?? '';
    const parsedRefererOrigin = extractCanonicalOriginFromUrl(rawReferer);
    if (!parsedRefererOrigin || !allowedOriginSet.has(parsedRefererOrigin)) {
      throw new ForbiddenError('CSRF validation failed: Referer origin not allowed');
    }
    return;
  }

  throw new ForbiddenError('CSRF validation failed: Origin or Referer header required');
}

/**
 * Validates Fetch Metadata `Sec-Fetch-Site` when supplied by modern browsers.
 */
function validateFetchMetadata(req: Request): void {
  const fetchSite = readSingleHeaderValue(req, 'sec-fetch-site');
  if (fetchSite.duplicate) {
    throw new ForbiddenError('CSRF validation failed: duplicate Sec-Fetch-Site header rejected');
  }
  if (!fetchSite.present) {
    return;
  }

  const normalized = (fetchSite.value ?? '').trim().toLowerCase();
  if (!ALLOWED_STATE_CHANGE_FETCH_SITES.has(normalized)) {
    throw new ForbiddenError('CSRF validation failed: cross-site request blocked');
  }
}

/**
 * Creates a reusable defense-in-depth CSRF middleware grounded in server-side
 * session-bound tokens, constant-time comparison, strict Origin/Referer validation,
 * and Fetch Metadata enforcement.
 */
export function createCsrfMiddleware(options: CsrfMiddlewareOptions): RequestHandler {
  if (!options.allowedOrigins || options.allowedOrigins.length === 0) {
    throw new DomainValidationError(
      'CSRF middleware requires at least one explicitly allowed origin',
    );
  }

  const allowedOriginSet = new Set<string>(
    options.allowedOrigins.map((origin) => normalizeCanonicalOrigin(origin)),
  );
  const headerName = (options.headerName ?? 'x-csrf-token').trim().toLowerCase();
  if (!headerName) {
    throw new DomainValidationError('CSRF headerName must be a non-empty string');
  }

  const resolveSessionToken =
    options.resolveSessionCsrfToken ??
    ((req: Request): string | null | undefined => req.sessionCsrfToken);

  return (req: Request, _res: Response, next: NextFunction): void => {
    const method = req.method.toUpperCase();

    try {
      // 1. Handle CORS preflight without requiring anti-CSRF headers, while verifying Origin if provided.
      if (method === 'OPTIONS') {
        const originHeader = readSingleHeaderValue(req, 'origin');
        if (originHeader.duplicate) {
          throw new ForbiddenError('CSRF preflight rejected: duplicate Origin header');
        }
        if (originHeader.present) {
          const parsedOrigin = extractCanonicalOriginFromUrl((originHeader.value ?? '').trim());
          if (!parsedOrigin || !allowedOriginSet.has(parsedOrigin)) {
            throw new ForbiddenError('CSRF preflight rejected: Origin not allowed');
          }
        }
        next();
        return;
      }

      // 2. Allow read-only idempotent safe methods cleanly.
      if (SAFE_READ_METHODS.has(method)) {
        next();
        return;
      }

      // 3. Enforce Fetch Metadata check (`Sec-Fetch-Site` when present) on state-changing methods.
      validateFetchMetadata(req);

      // 4. Enforce strict `Origin` or safe `Referer` fallback check (fail closed when absent).
      validateRequestOrigin(req, allowedOriginSet);

      // 5. Enforce server-side session-bound anti-CSRF token with constant-time comparison.
      const expectedToken = resolveSessionToken(req);
      if (typeof expectedToken !== 'string' || expectedToken.trim().length < 16) {
        throw new ForbiddenError('CSRF validation failed: missing server session token binding');
      }

      const submittedHeader = readSingleHeaderValue(req, headerName);
      if (submittedHeader.duplicate) {
        throw new ForbiddenError('CSRF validation failed: duplicate anti-CSRF header rejected');
      }

      const submittedToken = (submittedHeader.value ?? '').trim();
      if (
        !submittedHeader.present ||
        submittedToken.length === 0 ||
        submittedToken.length > MAX_CSRF_HEADER_LENGTH
      ) {
        throw new ForbiddenError('CSRF validation failed: missing anti-CSRF token');
      }

      if (!constantTimeCompareStrings(submittedToken, expectedToken)) {
        throw new ForbiddenError('CSRF validation failed: invalid anti-CSRF token');
      }

      next();
    } catch (err) {
      next(err);
    }
  };
}
