import type { Request, Response, NextFunction, RequestHandler } from 'express';
import { UnauthorizedError, ForbiddenError } from '@secureflow/shared';
import type { IAuthService } from '@secureflow/domain';
import { readSessionCookie, type CookieProfile } from '../auth/cookies.js';

/**
 * Production fail-closed authentication boundary middleware.
 *
 * In accordance with Gate 3E/Phase 4 security specifications:
 * - Unconditionally rejects protected operational requests with HTTP 401 UNAUTHORIZED when auth is disabled.
 * - Never grants access merely because req.actor exists.
 * - Never establishes identity from client-supplied headers (e.g. x-user-id, Authorization),
 *   body fields, query parameters, or unverified claims.
 * - Does not introduce any authentication-bypass environment variable.
 */
export const requireAuth: RequestHandler = (
  _req: Request,
  _res: Response,
  next: NextFunction
): void => {
  next(new UnauthorizedError('Authentication required to access this resource'));
};

export interface SessionAuthMiddlewareOptions {
  readonly authService: IAuthService;
  readonly cookies: CookieProfile;
}

/**
 * Server-managed BFF session authenticator (Gate 4B.3).
 *
 * Security Invariants:
 * 1. Strictly reads the session cookie matching the configured cookie profile (e.g., '__Host-sf_session' in production).
 * 2. Never establishes identity from client-supplied headers (e.g., 'x-user-id', 'x-actor-role', 'Authorization').
 * 3. Revalidates session active status, expiration, idle timeout, and user active status against PostgreSQL on every request.
 * 4. Resolves authoritative project memberships from PostgreSQL via AuthService.resolveSessionActor.
 * 5. Attaches trusted req.actor, req.sessionId, req.sessionCsrfToken, and req.user to the request context.
 * 6. Completely fail-closed: invalid, expired, revoked, or tampered sessions fail with HTTP 401/403 without leaking secrets.
 */
export function createSessionAuthMiddleware(
  options: SessionAuthMiddlewareOptions
): RequestHandler {
  return async (req: Request, _res: Response, next: NextFunction): Promise<void> => {
    try {
      const extraction = readSessionCookie(req.headers['cookie'], options.cookies);
      if (!extraction.present || extraction.status !== 'ok' || !extraction.value) {
        throw new UnauthorizedError('Authentication required to access this resource');
      }

      const resolved = await options.authService.resolveSessionActor(
        {
          rawSessionToken: extraction.value,
        },
        new Date()
      );

      req.actor = resolved.actor;
      req.sessionId = resolved.session.id;
      req.sessionCsrfToken = resolved.session.csrfToken;

      next();
    } catch (err) {
      if (err instanceof UnauthorizedError || err instanceof ForbiddenError) {
        next(err);
      } else {
        next(new UnauthorizedError('Authentication required to access this resource'));
      }
    }
  };
}
