import { Router } from 'express';
import type { Router as ExpressRouter } from 'express';
import type { DomainServices } from '@secureflow/domain';
import { healthRouter } from './health.js';
import { createProjectsRouter } from './v1/projects.js';
import { createFindingsRouter } from './v1/findings.js';
import { createTasksRouter } from './v1/tasks.js';
import { createAuditEventsRouter } from './v1/audit-events.js';

export { healthRouter };

export function createApiRouter(services: DomainServices): ExpressRouter {
  const router = Router();
  router.use('/projects', createProjectsRouter(services));
  router.use('/findings', createFindingsRouter(services));
  router.use('/tasks', createTasksRouter(services));
  router.use('/audit-events', createAuditEventsRouter(services));
  return router;
}
