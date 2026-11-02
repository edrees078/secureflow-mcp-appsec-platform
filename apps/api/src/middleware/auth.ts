import type { Request, Response, NextFunction, RequestHandler } from 'express';
import { UnauthorizedError } from '@secureflow/shared';

/**
 * Production fail-closed authentication boundary middleware.
 *
 * In accordance with Gate 3E security specifications:
 * - Unconditionally rejects protected operational requests with HTTP 401 UNAUTHORIZED.
 * - Never grants access merely because req.actor exists.
 * - Never establishes identity from client-supplied headers (e.g. x-user-id, Authorization),
 *   body fields, query parameters, or unverified claims.
 * - Does not introduce any authentication-bypass environment variable.
 * - Sits before operational routes, validation middleware, and controller execution.
 *
 * Full session and Keycloak OIDC authentication will be established in Phase 4 via
 * the server-managed BFF session authenticator.
 */
export const requireAuth: RequestHandler = (
  _req: Request,
  _res: Response,
  next: NextFunction
): void => {
  next(new UnauthorizedError('Authentication required to access this resource'));
};
