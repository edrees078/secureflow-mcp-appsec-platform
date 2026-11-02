import express from 'express';
import type { Express } from 'express';
import type { DomainServices, ActorContext } from '@secureflow/domain';
import { requestIdMiddleware } from '../../src/middleware/request-id.js';
import { notFoundMiddleware } from '../../src/middleware/not-found.js';
import { errorHandlerMiddleware } from '../../src/middleware/error-handler.js';
import { createApiRouter } from '../../src/routes/index.js';

export interface CreateTestAppOptions {
  services: DomainServices;
  actor?: ActorContext | (() => ActorContext | undefined);
}

/**
 * Creates an Express test application instance for isolated controller testing.
 *
 * In accordance with Phase 3 security specifications:
 * - Isolated strictly within apps/api/tests/helpers/ (never imported by production code).
 * - Injects the ActorContext directly into req.actor purely via process memory.
 * - Test identity is NEVER parsed or derived from HTTP headers or query parameters.
 * - Reuses the exact same controller, router, and validation implementations as production.
 */
export function createTestApp(options: CreateTestAppOptions): Express {
  const app = express();

  // 1. Request ID correlation
  app.use(requestIdMiddleware);

  // 2. Body parsing
  app.use(express.json({ limit: '1mb' }));
  app.use(express.urlencoded({ extended: true, limit: '1mb' }));

  // 3. In-memory test actor injection middleware
  app.use((req, _res, next) => {
    if (typeof options.actor === 'function') {
      req.actor = options.actor();
    } else if (options.actor) {
      req.actor = options.actor;
    }
    next();
  });

  // 4. Mount API router directly under /api/v1 (bypassing production fail-closed requireAuth)
  const apiRouter = createApiRouter(options.services);
  app.use('/api/v1', apiRouter);

  // 5. 404 handler
  app.use(notFoundMiddleware);

  // 6. Centralized error handling
  app.use(errorHandlerMiddleware);

  return app;
}
