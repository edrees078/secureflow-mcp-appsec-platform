import { Router } from 'express';
import type { Router as ExpressRouter, Request, Response, NextFunction, RequestHandler } from 'express';
import { z } from 'zod';
import { DomainValidationError, UnauthorizedError } from '@secureflow/shared';
import type { IAuthService } from '@secureflow/domain';
import type { AuthRuntimeConfig } from '../../config/auth.js';
import type { OidcAuthFlowCoordinator } from '../../auth/oidc-flow.js';
import {
  serializeOidcTxnCookie,
  serializeSessionCookie,
  clearOidcTxnCookie,
  clearSessionCookie,
  readOidcTxnCookie,
  readSessionCookie,
} from '../../auth/cookies.js';

const LogoutBodySchema = z
  .object({
    postLogoutRedirectUri: z.string().trim().min(1).max(2048).optional(),
  })
  .strict();

export interface AuthRouterOptions {
  readonly authService: IAuthService;
  readonly flowCoordinator: OidcAuthFlowCoordinator;
  readonly authConfig: AuthRuntimeConfig;
  readonly sessionAuthMiddleware: RequestHandler;
  readonly csrfMiddleware: RequestHandler;
}

/**
 * Creates the Express router for Integrated BFF Authentication endpoints (/api/v1/auth).
 *
 * In accordance with Phase 4 security specifications:
 * 1. Public endpoints:
 *    - GET /api/v1/auth/login — Initiates OIDC flow, sets OIDC txn cookie, redirects to IdP.
 *    - GET /api/v1/auth/callback — Consumes txn cookie, exchanges code, sets session cookie.
 * 2. Protected endpoints:
 *    - GET /api/v1/auth/me — Requires active session cookie, returns user & session CSRF token.
 *    - POST /api/v1/auth/logout — Requires active session cookie AND anti-CSRF token, revokes session in DB.
 * 3. Fail-Closed Boundaries:
 *    - Callback failures burn transaction and never establish authenticated session.
 *    - Replay or expiration of OIDC transaction fails with HTTP 401.
 *    - Zero secrets leaked in responses or headers.
 */
export function createAuthRouter(options: AuthRouterOptions): ExpressRouter {
  const router = Router();
  const { authService, flowCoordinator, authConfig, sessionAuthMiddleware, csrfMiddleware } = options;

  // 1. GET /login — Public endpoint initiating OIDC Authorization Code Flow with PKCE
  router.get('/login', async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const rawReturnTo = typeof req.query['returnTo'] === 'string' ? req.query['returnTo'].trim() : undefined;
      const returnTo =
        rawReturnTo && rawReturnTo.startsWith('/') && !rawReturnTo.startsWith('//') && !rawReturnTo.includes('\\')
          ? rawReturnTo
          : '/';

      const started = await flowCoordinator.startAuthorizationFlow({ returnTo }, new Date());
      const maxAgeSeconds = Math.max(1, Math.floor((started.expiresAt.getTime() - Date.now()) / 1000));
      const txnCookie = serializeOidcTxnCookie(authConfig.cookies, started.rawTxnToken, maxAgeSeconds);
      res.setHeader('Set-Cookie', txnCookie);
      res.redirect(302, started.authorizationUrl.toString());
    } catch (err) {
      next(err);
    }
  });

  // 2. GET /callback — Public callback endpoint completing OIDC exchange & establishing session
  router.get('/callback', async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const txnExtract = readOidcTxnCookie(req.headers['cookie'], authConfig.cookies);
      if (!txnExtract.present || txnExtract.status !== 'ok' || !txnExtract.value) {
        res.setHeader('Set-Cookie', clearOidcTxnCookie(authConfig.cookies));
        throw new UnauthorizedError('OIDC transaction cookie missing or invalid');
      }

      const host = req.get('host') ?? '127.0.0.1:3000';
      const protocol = authConfig.cookies.secure ? 'https' : (req.protocol ?? 'http');
      const callbackUrl = new URL(req.originalUrl, `${protocol}://${host}`);

      let completed;
      try {
        completed = await flowCoordinator.completeAuthorizationCallback(
          {
            callbackUrl,
            rawTxnToken: txnExtract.value,
            ipAddress: req.ip ?? null,
            userAgent: req.get('user-agent') ?? null,
          },
          new Date(),
        );
      } catch (exchangeErr) {
        res.setHeader('Set-Cookie', clearOidcTxnCookie(authConfig.cookies));
        throw exchangeErr;
      }

      const maxAgeSeconds = Math.max(1, Math.floor((completed.expiresAt.getTime() - Date.now()) / 1000));
      const sessionCookie = serializeSessionCookie(authConfig.cookies, completed.rawSessionToken, maxAgeSeconds);
      const clearTxn = clearOidcTxnCookie(authConfig.cookies);
      res.setHeader('Set-Cookie', [sessionCookie, clearTxn]);

      if (req.accepts('json') && !req.accepts('html')) {
        res.status(200).json({
          data: {
            user: completed.user,
            sessionId: completed.sessionId,
            csrfToken: completed.csrfToken,
            returnTo: completed.returnTo,
          },
        });
      } else {
        res.redirect(302, completed.returnTo);
      }
    } catch (err) {
      next(err);
    }
  });

  // 3. GET /me — Protected endpoint returning authenticated user identity & session anti-CSRF token
  router.get('/me', sessionAuthMiddleware, (req: Request, res: Response): void => {
    res.status(200).json({
      data: {
        actor: req.actor,
        sessionId: req.sessionId,
        csrfToken: req.sessionCsrfToken,
      },
    });
  });

  // 4. POST /logout — Protected endpoint requiring session authentication and CSRF token
  router.post('/logout', sessionAuthMiddleware, csrfMiddleware, async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const parsedResult = LogoutBodySchema.safeParse(req.body ?? {});
      if (!parsedResult.success) {
        throw new DomainValidationError('Invalid logout request body');
      }

      const endSessionUrl = await flowCoordinator.buildLogoutUrl({
        postLogoutRedirectUri: parsedResult.data.postLogoutRedirectUri,
      });

      const extraction = readSessionCookie(req.headers['cookie'], authConfig.cookies);
      if (extraction.present && extraction.status === 'ok' && extraction.value) {
        await authService.revokeSession(
          {
            rawSessionToken: extraction.value,
            reason: 'USER_LOGOUT',
            ipAddress: req.ip ?? null,
            userAgent: req.get('user-agent') ?? null,
          },
          new Date(),
        );
      }

      const clearSession = clearSessionCookie(authConfig.cookies);
      const clearTxn = clearOidcTxnCookie(authConfig.cookies);
      res.setHeader('Set-Cookie', [clearSession, clearTxn]);

      res.status(200).json({
        data: {
          loggedOut: true,
          endSessionUrl: endSessionUrl ? endSessionUrl.toString() : null,
        },
      });
    } catch (err) {
      next(err);
    }
  });

  return router;
}
