import { Router } from 'express';
import type { Router as ExpressRouter } from 'express';
import type { DomainServices } from '@secureflow/domain';
import { healthRouter } from './health.js';
import { createProjectsRouter } from './v1/projects.js';

export { healthRouter };

export function createApiRouter(services: DomainServices): ExpressRouter {
  const router = Router();
  router.use('/projects', createProjectsRouter(services));
  return router;
}
