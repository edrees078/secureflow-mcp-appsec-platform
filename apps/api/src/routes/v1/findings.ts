import { Router } from 'express';
import type { Router as ExpressRouter, Request, Response, NextFunction } from 'express';
import type { DomainServices } from '@secureflow/domain';
import {
  CreateFindingInputSchema,
  UpdateFindingMetadataInputSchema,
  TriageFindingInputSchema,
  AssignFindingInputSchema,
  SubmitRemediationInputSchema,
  VerifyFindingInputSchema,
  CloseFindingInputSchema,
  SoftDeleteFindingInputSchema,
  ForceCloseFindingInputSchema,
  ForceReopenFindingInputSchema,
  ListFindingsQuerySchema,
  UuidSchema,
  type CreateFindingInput,
  type UpdateFindingMetadataInput,
  type TriageFindingInput,
  type AssignFindingInput,
  type SubmitRemediationInput,
  type VerifyFindingInput,
  type CloseFindingInput,
  type SoftDeleteFindingInput,
  type ForceCloseFindingInput,
  type ForceReopenFindingInput,
  type ListFindingsQuery,
  type ListFindingsFilterInput,
} from '@secureflow/schemas';
import { UnauthorizedError } from '@secureflow/shared';
import { z } from 'zod';
import {
  validateRequest,
  getValidatedBody,
  getValidatedParams,
  getValidatedQuery,
} from '../../middleware/validate.js';

export const FindingIdParamSchema = z
  .object({
    id: UuidSchema,
  })
  .strict();

export type FindingIdParam = z.output<typeof FindingIdParamSchema>;

/**
 * Creates the Express router for Finding Lifecycle REST API endpoints (/api/v1/findings).
 *
 * Architecture & Security Principles (Sub-Gate 3E.3):
 * 1. Thin Controller Adapter: Controllers delegate immediately to domain service methods.
 *    No direct database or repository access.
 * 2. Actor Context Invariant: Every route handler passes req.actor to domain methods.
 * 3. Express 5 Compatibility: Inputs are retrieved from typed validated request context (getValidated).
 * 4. Optimistic Concurrency Control (OCC): Every mutating endpoint requires expectedVersion.
 * 5. Unified Verification: POST /findings/:id/verify handles both VERIFIED and REOPENED outcomes.
 * 6. DELETE with Body Contract: DELETE /findings/:id consumes a JSON body containing expectedVersion.
 *    Note: HTTP clients/proxies may restrict bodies in DELETE requests; within SecureFlow's API
 *    contract this is the official Gate 3E.3 interface.
 * 7. Canonical Status Codes:
 *    - POST /findings -> 201 Created
 *    - GET /findings -> 200 OK with data and pagination
 *    - GET /findings/:id -> 200 OK with data
 *    - PATCH /findings/:id -> 200 OK with data
 *    - POST /findings/:id/triage -> 200 OK with data
 *    - POST /findings/:id/assign -> 200 OK with data
 *    - POST /findings/:id/submit-remediation -> 200 OK with data
 *    - POST /findings/:id/verify -> 200 OK with data
 *    - POST /findings/:id/close -> 200 OK with data
 *    - DELETE /findings/:id -> 200 OK with data (soft-deleted finding record)
 *    - POST /findings/:id/force-close -> 200 OK with data (exceptional Admin force-close)
 *    - POST /findings/:id/force-reopen -> 200 OK with data (exceptional Admin force-reopen)
 */
export function createFindingsRouter(services: DomainServices): ExpressRouter {
  const router = Router();
  const { findingService } = services;

  // 1. POST /api/v1/findings — Create finding (Analyst-scoped)
  router.post(
    '/',
    validateRequest({ body: CreateFindingInputSchema }),
    async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      try {
        if (!req.actor) {
          throw new UnauthorizedError('Authentication required');
        }
        const body = getValidatedBody<CreateFindingInput>(req);
        const finding = await findingService.createFinding(req.actor, body);
        res.status(201).json({ data: finding });
      } catch (err) {
        next(err);
      }
    }
  );

  // 2. GET /api/v1/findings — List / filter findings with pagination
  router.get(
    '/',
    validateRequest({ query: ListFindingsQuerySchema }),
    async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      try {
        if (!req.actor) {
          throw new UnauthorizedError('Authentication required');
        }
        const query = getValidatedQuery<ListFindingsQuery>(req);
        const filter: ListFindingsFilterInput = {
          ...(query.projectId !== undefined ? { projectId: query.projectId } : {}),
          ...(query.status !== undefined ? { status: query.status } : {}),
          ...(query.severity !== undefined ? { severity: query.severity } : {}),
          ...(query.category !== undefined ? { category: query.category } : {}),
          ...(query.assignedToId !== undefined ? { assignedToId: query.assignedToId } : {}),
          ...(query.search !== undefined ? { search: query.search } : {}),
          page: query.page,
          limit: query.limit,
          ...(query.includeDeleted !== undefined ? { includeDeleted: query.includeDeleted } : {}),
        };
        const result = await findingService.listFindings(req.actor, filter);
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

  // 3. GET /api/v1/findings/:id — Get finding detail (existence-hiding 404 for unauthorized)
  router.get(
    '/:id',
    validateRequest({ params: FindingIdParamSchema }),
    async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      try {
        if (!req.actor) {
          throw new UnauthorizedError('Authentication required');
        }
        const params = getValidatedParams<FindingIdParam>(req);
        const finding = await findingService.getFinding(req.actor, params.id);
        res.status(200).json({ data: finding });
      } catch (err) {
        next(err);
      }
    }
  );

  // 4. PATCH /api/v1/findings/:id — Update finding metadata (Analyst-scoped, OCC)
  router.patch(
    '/:id',
    validateRequest({
      params: FindingIdParamSchema,
      body: UpdateFindingMetadataInputSchema,
    }),
    async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      try {
        if (!req.actor) {
          throw new UnauthorizedError('Authentication required');
        }
        const params = getValidatedParams<FindingIdParam>(req);
        const body = getValidatedBody<UpdateFindingMetadataInput>(req);
        const finding = await findingService.updateFindingMetadata(req.actor, params.id, body);
        res.status(200).json({ data: finding });
      } catch (err) {
        next(err);
      }
    }
  );

  // 5. POST /api/v1/findings/:id/triage — Triage finding (OPEN -> TRIAGED, OCC)
  router.post(
    '/:id/triage',
    validateRequest({
      params: FindingIdParamSchema,
      body: TriageFindingInputSchema,
    }),
    async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      try {
        if (!req.actor) {
          throw new UnauthorizedError('Authentication required');
        }
        const params = getValidatedParams<FindingIdParam>(req);
        const body = getValidatedBody<TriageFindingInput>(req);
        const finding = await findingService.triageFinding(req.actor, params.id, body);
        res.status(200).json({ data: finding });
      } catch (err) {
        next(err);
      }
    }
  );

  // 6. POST /api/v1/findings/:id/assign — Assign finding to Developer (TRIAGED/REOPENED -> IN_PROGRESS, OCC)
  router.post(
    '/:id/assign',
    validateRequest({
      params: FindingIdParamSchema,
      body: AssignFindingInputSchema,
    }),
    async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      try {
        if (!req.actor) {
          throw new UnauthorizedError('Authentication required');
        }
        const params = getValidatedParams<FindingIdParam>(req);
        const body = getValidatedBody<AssignFindingInput>(req);
        const finding = await findingService.assignFinding(req.actor, params.id, body);
        res.status(200).json({ data: finding });
      } catch (err) {
        next(err);
      }
    }
  );

  // 7. POST /api/v1/findings/:id/submit-remediation — Developer submits remediation (IN_PROGRESS -> READY_FOR_REVIEW, OCC)
  router.post(
    '/:id/submit-remediation',
    validateRequest({
      params: FindingIdParamSchema,
      body: SubmitRemediationInputSchema,
    }),
    async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      try {
        if (!req.actor) {
          throw new UnauthorizedError('Authentication required');
        }
        const params = getValidatedParams<FindingIdParam>(req);
        const body = getValidatedBody<SubmitRemediationInput>(req);
        const finding = await findingService.submitRemediation(req.actor, params.id, body);
        res.status(200).json({ data: finding });
      } catch (err) {
        next(err);
      }
    }
  );

  // 8. POST /api/v1/findings/:id/verify — Verify or reject remediation (READY_FOR_REVIEW -> VERIFIED / REOPENED, SoD, OCC)
  router.post(
    '/:id/verify',
    validateRequest({
      params: FindingIdParamSchema,
      body: VerifyFindingInputSchema,
    }),
    async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      try {
        if (!req.actor) {
          throw new UnauthorizedError('Authentication required');
        }
        const params = getValidatedParams<FindingIdParam>(req);
        const body = getValidatedBody<VerifyFindingInput>(req);
        const finding = await findingService.verifyFinding(req.actor, params.id, body);
        res.status(200).json({ data: finding });
      } catch (err) {
        next(err);
      }
    }
  );

  // 9. POST /api/v1/findings/:id/close — Ordinary closure by Analyst (VERIFIED -> CLOSED, OCC)
  router.post(
    '/:id/close',
    validateRequest({
      params: FindingIdParamSchema,
      body: CloseFindingInputSchema,
    }),
    async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      try {
        if (!req.actor) {
          throw new UnauthorizedError('Authentication required');
        }
        const params = getValidatedParams<FindingIdParam>(req);
        const body = getValidatedBody<CloseFindingInput>(req);
        const finding = await findingService.closeFinding(req.actor, params.id, body);
        res.status(200).json({ data: finding });
      } catch (err) {
        next(err);
      }
    }
  );

  // 10. DELETE /api/v1/findings/:id — Soft-delete finding (Analyst-scoped, OCC)
  router.delete(
    '/:id',
    validateRequest({
      params: FindingIdParamSchema,
      body: SoftDeleteFindingInputSchema,
    }),
    async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      try {
        if (!req.actor) {
          throw new UnauthorizedError('Authentication required');
        }
        const params = getValidatedParams<FindingIdParam>(req);
        const body = getValidatedBody<SoftDeleteFindingInput>(req);
        const finding = await findingService.softDeleteFinding(req.actor, params.id, body);
        res.status(200).json({ data: finding });
      } catch (err) {
        next(err);
      }
    }
  );

  // 11. POST /api/v1/findings/:id/force-close — Exceptional force-close finding (Global Admin, OCC)
  router.post(
    '/:id/force-close',
    validateRequest({
      params: FindingIdParamSchema,
      body: ForceCloseFindingInputSchema,
    }),
    async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      try {
        if (!req.actor) {
          throw new UnauthorizedError('Authentication required');
        }
        const params = getValidatedParams<FindingIdParam>(req);
        const body = getValidatedBody<ForceCloseFindingInput>(req);
        const finding = await findingService.forceCloseFinding(req.actor, params.id, body);
        res.status(200).json({ data: finding });
      } catch (err) {
        next(err);
      }
    }
  );

  // 12. POST /api/v1/findings/:id/force-reopen — Exceptional force-reopen finding (Global Admin, OCC)
  router.post(
    '/:id/force-reopen',
    validateRequest({
      params: FindingIdParamSchema,
      body: ForceReopenFindingInputSchema,
    }),
    async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      try {
        if (!req.actor) {
          throw new UnauthorizedError('Authentication required');
        }
        const params = getValidatedParams<FindingIdParam>(req);
        const body = getValidatedBody<ForceReopenFindingInput>(req);
        const finding = await findingService.forceReopenFinding(req.actor, params.id, body);
        res.status(200).json({ data: finding });
      } catch (err) {
        next(err);
      }
    }
  );

  return router;
}
