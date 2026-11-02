import { Router } from 'express';
import type { Router as ExpressRouter, Request, Response, NextFunction } from 'express';
import type { DomainServices } from '@secureflow/domain';
import {
  CreateProjectInputSchema,
  UpdateProjectInputSchema,
  AddProjectMemberInputSchema,
  ListProjectsQuerySchema,
  UuidSchema,
  type CreateProjectInput,
  type UpdateProjectInput,
  type AddProjectMemberInput,
  type ListProjectsQuery,
} from '@secureflow/schemas';
import { UnauthorizedError } from '@secureflow/shared';
import { z } from 'zod';
import {
  validateRequest,
  getValidatedBody,
  getValidatedParams,
  getValidatedQuery,
} from '../../middleware/validate.js';

export const ProjectIdParamSchema = z
  .object({
    id: UuidSchema,
  })
  .strict();

export const ProjectMemberParamSchema = z
  .object({
    id: UuidSchema,
    userId: UuidSchema,
  })
  .strict();

export type ProjectIdParam = z.output<typeof ProjectIdParamSchema>;
export type ProjectMemberParam = z.output<typeof ProjectMemberParamSchema>;

/**
 * Creates the Express router for Project Management REST API endpoints (/api/v1/projects).
 *
 * Architecture & Security Principles (Sub-Gate 3E.2):
 * 1. Thin Controller Adapter: Controllers delegate immediately to domain service methods.
 *    No direct database or repository access.
 * 2. Actor Context Invariant: Every route handler passes req.actor to domain methods.
 * 3. Express 5 Compatibility: Inputs are retrieved from typed validated request context (getValidated).
 * 4. Canonical Status Codes:
 *    - POST /projects -> 201 Created
 *    - GET /projects -> 200 OK with data and pagination
 *    - GET /projects/:id -> 200 OK with data
 *    - PATCH /projects/:id -> 200 OK with data
 *    - DELETE /projects/:id -> 200 OK with data (archived project)
 *    - GET /projects/:id/members -> 200 OK with data
 *    - POST /projects/:id/members -> 201 Created with data
 *    - DELETE /projects/:id/members/:userId -> 204 No Content
 */
export function createProjectsRouter(services: DomainServices): ExpressRouter {
  const router = Router();
  const { projectService } = services;

  // POST /api/v1/projects
  router.post(
    '/',
    validateRequest({ body: CreateProjectInputSchema }),
    async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      try {
        if (!req.actor) {
          throw new UnauthorizedError('Authentication required');
        }
        const body = getValidatedBody<CreateProjectInput>(req);
        const project = await projectService.createProject(req.actor, body);
        res.status(201).json({ data: project });
      } catch (err) {
        next(err);
      }
    }
  );

  // GET /api/v1/projects
  router.get(
    '/',
    validateRequest({ query: ListProjectsQuerySchema }),
    async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      try {
        if (!req.actor) {
          throw new UnauthorizedError('Authentication required');
        }
        const query = getValidatedQuery<ListProjectsQuery>(req);
        const filter = {
          page: query.page,
          limit: query.limit,
          ...(query.search !== undefined ? { search: query.search } : {}),
          ...(query.includeInactive !== undefined ? { includeInactive: query.includeInactive } : {}),
        };
        const result = await projectService.listProjects(req.actor, filter);
        res.status(200).json({
          data: result.items,
          pagination: {
            total: result.total,
            page: result.page,
            limit: result.limit,
            totalPages: result.totalPages,
          },
        });
      } catch (err) {
        next(err);
      }
    }
  );

  // GET /api/v1/projects/:id
  router.get(
    '/:id',
    validateRequest({ params: ProjectIdParamSchema }),
    async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      try {
        if (!req.actor) {
          throw new UnauthorizedError('Authentication required');
        }
        const params = getValidatedParams<ProjectIdParam>(req);
        const project = await projectService.getProject(req.actor, params.id);
        res.status(200).json({ data: project });
      } catch (err) {
        next(err);
      }
    }
  );

  // PATCH /api/v1/projects/:id
  router.patch(
    '/:id',
    validateRequest({
      params: ProjectIdParamSchema,
      body: UpdateProjectInputSchema,
    }),
    async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      try {
        if (!req.actor) {
          throw new UnauthorizedError('Authentication required');
        }
        const params = getValidatedParams<ProjectIdParam>(req);
        const body = getValidatedBody<UpdateProjectInput>(req);
        const project = await projectService.updateProject(req.actor, params.id, body);
        res.status(200).json({ data: project });
      } catch (err) {
        next(err);
      }
    }
  );

  // DELETE /api/v1/projects/:id (Archive)
  router.delete(
    '/:id',
    validateRequest({ params: ProjectIdParamSchema }),
    async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      try {
        if (!req.actor) {
          throw new UnauthorizedError('Authentication required');
        }
        const params = getValidatedParams<ProjectIdParam>(req);
        const project = await projectService.archiveProject(req.actor, params.id);
        res.status(200).json({ data: project });
      } catch (err) {
        next(err);
      }
    }
  );

  // GET /api/v1/projects/:id/members
  router.get(
    '/:id/members',
    validateRequest({ params: ProjectIdParamSchema }),
    async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      try {
        if (!req.actor) {
          throw new UnauthorizedError('Authentication required');
        }
        const params = getValidatedParams<ProjectIdParam>(req);
        const members = await projectService.listMembers(req.actor, params.id);
        res.status(200).json({ data: members });
      } catch (err) {
        next(err);
      }
    }
  );

  // POST /api/v1/projects/:id/members
  router.post(
    '/:id/members',
    validateRequest({
      params: ProjectIdParamSchema,
      body: AddProjectMemberInputSchema,
    }),
    async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      try {
        if (!req.actor) {
          throw new UnauthorizedError('Authentication required');
        }
        const params = getValidatedParams<ProjectIdParam>(req);
        const body = getValidatedBody<AddProjectMemberInput>(req);
        const member = await projectService.addMember(req.actor, params.id, body);
        res.status(201).json({ data: member });
      } catch (err) {
        next(err);
      }
    }
  );

  // DELETE /api/v1/projects/:id/members/:userId
  router.delete(
    '/:id/members/:userId',
    validateRequest({ params: ProjectMemberParamSchema }),
    async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      try {
        if (!req.actor) {
          throw new UnauthorizedError('Authentication required');
        }
        const params = getValidatedParams<ProjectMemberParam>(req);
        await projectService.removeMember(req.actor, params.id, params.userId);
        res.status(204).end();
      } catch (err) {
        next(err);
      }
    }
  );

  return router;
}
