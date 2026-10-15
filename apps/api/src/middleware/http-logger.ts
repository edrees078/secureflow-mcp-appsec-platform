import { pinoHttp } from 'pino-http';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { logger } from '../logger/logger.js';

export const httpLoggerMiddleware = pinoHttp({
  logger,
  genReqId(req: IncomingMessage) {
    return (req as IncomingMessage & { id?: string }).id ?? 'unknown';
  },
  customLogLevel(_req: IncomingMessage, res: ServerResponse, err?: Error) {
    if (res.statusCode >= 500 || err) {
      return 'error';
    }
    if (res.statusCode >= 400) {
      return 'warn';
    }
    return 'info';
  },
  autoLogging: {
    ignore: (req: IncomingMessage) => req.url === '/health/ready',
  },
});
