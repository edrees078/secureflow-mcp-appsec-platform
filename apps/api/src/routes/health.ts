import { Router } from 'express';
import type { Request, Response, Router as ExpressRouter } from 'express';

export const healthRouter: ExpressRouter = Router();

healthRouter.get('/ready', (_req: Request, res: Response) => {
  res.status(200).json({
    status: 'ready',
    service: 'secureflow-api',
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
    checks: {
      http: 'ok',
    },
  });
});
