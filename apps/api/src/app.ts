import express from 'express';
import type { Express } from 'express';
import type { DomainServices } from '@secureflow/domain';
import { requestIdMiddleware } from './middleware/request-id.js';
import { createSecurityMiddleware } from './middleware/security.js';
import { httpLoggerMiddleware } from './middleware/http-logger.js';
import { notFoundMiddleware } from './middleware/not-found.js';
import { errorHandlerMiddleware } from './middleware/error-handler.js';
import { requireAuth, createSessionAuthMiddleware } from './middleware/auth.js';
import { createCsrfMiddleware } from './middleware/csrf.js';
import { OpenIdConnectClient, type IOidcClient } from './auth/oidc-client.js';
import { OidcAuthFlowCoordinator } from './auth/oidc-flow.js';
import type { AuthRuntimeConfig } from './config/auth.js';
import { healthRouter, createApiRouter, createAuthRouter } from './routes/index.js';

export interface CreateAppOptions {
  readonly authConfig?: AuthRuntimeConfig | undefined;
  readonly oidcClient?: IOidcClient | undefined;
}

/**
 * Creates the production Express application instance.
 *
 * In accordance with Phase 3/4 security specifications:
 * - Public health endpoints (/health/ready) remain unauthenticated and never invoke domain services.
 * - When authentication is enabled (AUTH_ENABLED=true):
 *   - Mounts public BFF auth routes (/api/v1/auth/login, /api/v1/auth/callback) before protected gates.
 *   - Protects /api/v1/auth/me with session authentication.
 *   - Protects /api/v1/auth/logout with session authentication AND anti-CSRF token validation.
 *   - Protects all operational routes (/api/v1) with server-managed session authentication and CSRF guards.
 *   - Session authentication runs BEFORE protected body parsing so unauthenticated requests fail closed
 *     immediately without buffering or allocating memory for JSON parsing.
 * - When authentication is disabled (AUTH_ENABLED=false):
 *   - Sits behind fail-closed requireAuth boundary (unconditional HTTP 401 UNAUTHORIZED).
 * - Injects DomainServices into operational REST routers via dependency injection.
 */
export function createApp(
  services?: DomainServices,
  options?: CreateAppOptions | AuthRuntimeConfig,
): Express {
  const app = express();

  const authConfig =
    options && 'authConfig' in options
      ? options.authConfig
      : (options as AuthRuntimeConfig | undefined);
  const explicitOidcClient =
    options && 'oidcClient' in options ? options.oidcClient : undefined;

  // 1. Request ID correlation
  app.use(requestIdMiddleware);

  // 2. HTTP Security headers & CORS
  const [helmetMiddleware, corsMiddleware] = createSecurityMiddleware();
  if (helmetMiddleware) app.use(helmetMiddleware);
  if (corsMiddleware) app.use(corsMiddleware);

  // 3. HTTP Request Logging
  app.use(httpLoggerMiddleware);

  // Body parsers with bounded limit
  const jsonParser = express.json({ limit: '1mb' });
  const urlencodedParser = express.urlencoded({ extended: true, limit: '1mb' });

  // 4. Public Health routes (unauthenticated)
  app.use('/health', jsonParser, urlencodedParser, healthRouter);

  // 5. Authentication & Operational API v1 routes
  const authService = services?.authService;
  const authEnabled = authConfig?.authEnabled === true && Boolean(authService);

  if (authEnabled && services && authService && authConfig) {
    const oidcClient = explicitOidcClient ?? new OpenIdConnectClient(authConfig.oidc);
    const flowCoordinator = new OidcAuthFlowCoordinator(
      authService,
      oidcClient,
      authConfig,
    );
    const sessionAuth = createSessionAuthMiddleware({
      authService,
      cookies: authConfig.cookies,
    });
    const csrf = createCsrfMiddleware({
      allowedOrigins: authConfig.allowedOrigins,
    });

    // Mount BFF auth routes under /api/v1/auth
    const authRouter = createAuthRouter({
      authService,
      flowCoordinator,
      authConfig,
      sessionAuthMiddleware: sessionAuth,
      csrfMiddleware: csrf,
    });
    app.use('/api/v1/auth', jsonParser, urlencodedParser, authRouter);

    // Mount protected operational REST endpoints behind sessionAuth and CSRF guards
    const apiRouter = createApiRouter(services);
    app.use('/api/v1', sessionAuth, csrf, jsonParser, urlencodedParser, apiRouter);
  } else if (services) {
    // Fail-closed requireAuth boundary (AUTH_ENABLED=false)
    const apiRouter = createApiRouter(services);
    app.use('/api/v1', requireAuth, jsonParser, urlencodedParser, apiRouter);
  } else {
    app.use('/api/v1', requireAuth);
  }

  // 6. 404 handler
  app.use(notFoundMiddleware);

  // 7. Centralized error handling
  app.use(errorHandlerMiddleware);

  return app;
}
