import express from 'express';
import type { Express } from 'express';
import type { DomainServices } from '@secureflow/domain';
import { requestIdMiddleware } from './middleware/request-id.js';
import { createSecurityMiddleware } from './middleware/security.js';
import { httpLoggerMiddleware } from './middleware/http-logger.js';
import { notFoundMiddleware } from './middleware/not-found.js';
import { errorHandlerMiddleware } from './middleware/error-handler.js';
import { requireAuth } from './middleware/auth.js';
import { healthRouter, createApiRouter } from './routes/index.js';

/**
 * Creates the production Express application instance.
 *
 * In accordance with Phase 3 security specifications:
 * - Sits behind fail-closed requireAuth boundary for all /api/v1 operational routes.
 * - Security Principle: requireAuth precedes protected body parsing so unauthenticated
 *   requests fail closed immediately without buffering or allocating memory for JSON parsing.
 * - Public health endpoints (/health/ready) remain unauthenticated and never invoke domain services.
 * - Injects DomainServices into operational REST routers via dependency injection.
 */
export function createApp(services?: DomainServices): Express {
  const app = express();

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

  // 5. Protected Operational API v1 routes (fail-closed requireAuth boundary)
  // requireAuth runs BEFORE jsonParser/urlencodedParser on protected routes
  if (services) {
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
