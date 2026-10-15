import { Router } from 'express';
import type { Router as ExpressRouter } from 'express';
import { healthRouter } from './health.js';

export const apiRouter: ExpressRouter = Router();

apiRouter.use('/health', healthRouter);
