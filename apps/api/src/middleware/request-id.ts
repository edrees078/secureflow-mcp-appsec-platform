import type { Request, Response, NextFunction } from 'express';
import { randomUUID } from 'node:crypto';

// Strict regex allowing only safe URL-safe alphanumeric characters, hyphens, and underscores up to 64 chars.
// Prevents CRLF log injection, header injection, and control character attacks.
const SAFE_REQUEST_ID_REGEX = /^[a-zA-Z0-9_-]{1,64}$/;

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      id?: string;
    }
  }
}

export function requestIdMiddleware(req: Request, res: Response, next: NextFunction): void {
  const externalHeader = req.headers['x-request-id'];

  let validId: string;
  if (typeof externalHeader === 'string' && SAFE_REQUEST_ID_REGEX.test(externalHeader)) {
    validId = externalHeader;
  } else {
    validId = randomUUID();
  }

  req.id = validId;
  res.setHeader('X-Request-Id', validId);

  next();
}
