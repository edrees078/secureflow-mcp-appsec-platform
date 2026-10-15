import express from 'express';
import type { Express } from 'express';
import { requestIdMiddleware } from './middleware/request-id.js';
import { createSecurityMiddleware } from './middleware/security.js';
import { httpLoggerMiddleware } from './middleware/http-logger.js';
import { notFoundMiddleware } from './middleware/not-found.js';
import { errorHandlerMiddleware } from './middleware/error-handler.js';
import { apiRouter } from './routes/index.js';

export function createApp(): Express {
  const app = express();

  // 1. Request ID correlation
  app.use(requestIdMiddleware);

  // 2. HTTP Security headers & CORS
  const [helmetMiddleware, corsMiddleware] = createSecurityMiddleware();
  if (helmetMiddleware) app.use(helmetMiddleware);
  if (corsMiddleware) app.use(corsMiddleware);

  // 3. HTTP Request Logging
  app.use(httpLoggerMiddleware);

  // 4. Body parsing
  app.use(express.json({ limit: '1mb' }));
  app.use(express.urlencoded({ extended: true, limit: '1mb' }));

  // 5. Application routes
  app.use(apiRouter);

  // 6. 404 handler
  app.use(notFoundMiddleware);

  // 7. Centralized error handling
  app.use(errorHandlerMiddleware);

  return app;
}
