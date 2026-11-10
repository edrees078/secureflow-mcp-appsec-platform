import { Router } from 'express';
import type { Router as ExpressRouter, Request, Response, NextFunction } from 'express';
import type { DomainServices } from '@secureflow/domain';
import {
  UpdateTaskNotesInputSchema,
  UuidSchema,
  type UpdateTaskNotesInput,
} from '@secureflow/schemas';
import { UnauthorizedError } from '@secureflow/shared';
import { z } from 'zod';
import {
  validateRequest,
  getValidatedBody,
  getValidatedParams,
} from '../../middleware/validate.js';

export const TaskIdParamSchema = z
  .object({
    id: UuidSchema,
  })
  .strict();

export type TaskIdParam = z.output<typeof TaskIdParamSchema>;

/**
 * Creates the Express router for Remediation Task REST API endpoints (/api/v1/tasks).
 *
 * Architecture & Security Principles (Sub-Gate 3E.3):
 * 1. Thin Controller Adapter: Controllers delegate immediately to domain service methods.
 *    No direct database or repository access.
 * 2. Actor Context Invariant: Every route handler passes req.actor to domain methods.
 * 3. Express 5 Compatibility: Inputs are retrieved from typed validated request context (getValidated).
 * 4. Invariant Enforcement:
 *    - Preserves assignment-based Developer permissions.
 *    - Preserves project membership requirements.
 *    - Preserves soft-deleted parent finding restrictions.
 *    - Preserves the approved HTTP 404 existence-hiding behavior.
 *    - Preserves task-note validation (max 5000 characters).
 * 5. Canonical Status Codes:
 *    - GET /tasks/:id -> 200 OK with data
 *    - PATCH /tasks/:id/notes -> 200 OK with data
 */
export function createTasksRouter(services: DomainServices): ExpressRouter {
  const router = Router();
  const { taskService } = services;

  // 1. GET /api/v1/tasks/:id — Retrieve task detail
  router.get(
    '/:id',
    validateRequest({ params: TaskIdParamSchema }),
    async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      try {
        if (!req.actor) {
          throw new UnauthorizedError('Authentication required');
        }
        const params = getValidatedParams<TaskIdParam>(req);
        const task = await taskService.getTask(req.actor, params.id);
        res.status(200).json({ data: task });
      } catch (err) {
        next(err);
      }
    }
  );

  // 2. PATCH /api/v1/tasks/:id/notes — Update developer task progress notes
  router.patch(
    '/:id/notes',
    validateRequest({
      params: TaskIdParamSchema,
      body: UpdateTaskNotesInputSchema,
    }),
    async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      try {
        if (!req.actor) {
          throw new UnauthorizedError('Authentication required');
        }
        const params = getValidatedParams<TaskIdParam>(req);
        const body = getValidatedBody<UpdateTaskNotesInput>(req);
        const task = await taskService.updateTaskNotes(req.actor, params.id, body);
        res.status(200).json({ data: task });
      } catch (err) {
        next(err);
      }
    }
  );

  return router;
}
