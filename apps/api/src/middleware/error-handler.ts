import type { Request, Response, NextFunction, ErrorRequestHandler } from 'express';
import { SecureFlowError } from '@secureflow/shared';
import { logger } from '../logger/logger.js';

export interface ApiErrorResponse {
  error: {
    code: string;
    message: string;
    details?: unknown;
  };
}

export const errorHandlerMiddleware: ErrorRequestHandler = (
  err: unknown,
  req: Request,
  res: Response,
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  _next: NextFunction
): void => {
  // 1. Handle JSON syntax / body parser errors
  if (err instanceof SyntaxError && 'body' in err) {
    res.status(400).json({
      error: {
        code: 'BAD_REQUEST',
        message: 'Malformed JSON payload in request body',
      },
    });
    return;
  }

  // 2. Handle CORS origin rejection
  if (err instanceof Error && err.message.includes('CORS origin')) {
    res.status(403).json({
      error: {
        code: 'FORBIDDEN_CORS',
        message: err.message,
      },
    });
    return;
  }

  // 3. Handle known operational SecureFlowError
  if (err instanceof SecureFlowError) {
    const errorBody: ApiErrorResponse = {
      error: {
        code: err.code,
        message: err.message,
      },
    };
    res.status(err.statusCode).json(errorBody);
    return;
  }

  // 4. Handle unexpected internal server errors
  logger.error(
    {
      err,
      requestId: req.id,
      method: req.method,
      url: req.originalUrl || req.url,
    },
    'Unhandled internal server error'
  );

  res.status(500).json({
    error: {
      code: 'INTERNAL_ERROR',
      message: 'An unexpected internal server error occurred',
    },
  });
};
