import { pinoHttp, stdSerializers } from 'pino-http';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type pino from 'pino';
import {
  logger,
  sanitizeSerializedRequest,
  sanitizeSerializedResponse,
} from '../logger/logger.js';

export function createHttpLoggerMiddleware(customLogger: pino.Logger = logger) {
  return pinoHttp({
    logger: customLogger,
    serializers: {
      req(req: IncomingMessage) {
        const record = req as unknown as Record<string, unknown>;
        const serialized =
          typeof record['socket'] === 'object' && !('raw' in record)
            ? stdSerializers.req(req)
            : req;
        return sanitizeSerializedRequest(serialized);
      },
      res(res: ServerResponse) {
        const record = res as unknown as Record<string, unknown>;
        const serialized =
          typeof record['getHeaders'] === 'function'
            ? stdSerializers.res(res)
            : res;
        return sanitizeSerializedResponse(serialized);
      },
    },
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
}

export const httpLoggerMiddleware = createHttpLoggerMiddleware();
