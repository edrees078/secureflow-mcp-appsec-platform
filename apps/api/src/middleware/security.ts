import helmet from 'helmet';
import cors from 'cors';
import type { RequestHandler } from 'express';
import { env } from '../config/env.js';

export function createSecurityMiddleware(): RequestHandler[] {
  const isProduction = env.NODE_ENV === 'production';

  const helmetOptions = isProduction
    ? {
        frameguard: {
          action: 'sameorigin' as const,
        },
        xContentTypeOptions: true,
        hsts: {
          maxAge: 31536000,
          includeSubDomains: true,
          preload: true,
        },
      }
    : {
        contentSecurityPolicy: false,
        hsts: false,
        frameguard: {
          action: 'sameorigin' as const,
        },
        xContentTypeOptions: true,
      };

  const helmetMiddleware = helmet(helmetOptions);

  const corsMiddleware = cors({
    origin(requestOrigin, callback) {
      // Allow requests with no origin (e.g. curl, server-to-server)
      if (!requestOrigin) {
        callback(null, true);
        return;
      }

      const allowedOrigins = env.CORS_ORIGIN.split(',').map((o) => o.trim());

      if (allowedOrigins.includes(requestOrigin)) {
        callback(null, true);
      } else {
        callback(new Error(`CORS origin '${requestOrigin}' not allowed`));
      }
    },
    credentials: true,
    methods: ['GET', 'HEAD', 'PUT', 'PATCH', 'POST', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Request-Id'],
    exposedHeaders: ['X-Request-Id'],
  });

  return [helmetMiddleware, corsMiddleware];
}
