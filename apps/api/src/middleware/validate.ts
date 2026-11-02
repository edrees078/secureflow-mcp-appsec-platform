import type { Request, Response, NextFunction, RequestHandler } from 'express';
import { type ZodType, ZodError } from 'zod';
import { DomainValidationError, SecureFlowError } from '@secureflow/shared';

export interface ValidationSchemas<TBody = unknown, TQuery = unknown, TParams = unknown> {
  body?: ZodType<TBody>;
  query?: ZodType<TQuery>;
  params?: ZodType<TParams>;
}

export interface ValidatedData<TBody = unknown, TQuery = unknown, TParams = unknown> {
  body?: TBody;
  query?: TQuery;
  params?: TParams;
}

/**
 * Express 5-compatible Zod validation middleware.
 *
 * In accordance with Phase 3 security specifications:
 * - Does NOT overwrite req.query or req.params (which are getters in Express 5).
 * - Stores validated and parsed DTOs in a dedicated req.validated context.
 * - Supports asynchronous Zod parsing via parseAsync.
 * - Formats Zod validation issues into DomainValidationError (HTTP 400 VALIDATION_ERROR).
 * - Ensures malformed input is rejected before reaching domain services.
 */
export function validateRequest<TBody = unknown, TQuery = unknown, TParams = unknown>(
  schemas: ValidationSchemas<TBody, TQuery, TParams>
): RequestHandler {
  return async (req: Request, _res: Response, next: NextFunction): Promise<void> => {
    try {
      const validated: ValidatedData<TBody, TQuery, TParams> =
        (req.validated as ValidatedData<TBody, TQuery, TParams>) ?? {};

      if (schemas.params) {
        validated.params = await schemas.params.parseAsync(req.params);
      }
      if (schemas.query) {
        validated.query = await schemas.query.parseAsync(req.query);
      }
      if (schemas.body) {
        validated.body = await schemas.body.parseAsync(req.body);
      }

      req.validated = validated;
      next();
    } catch (err: unknown) {
      if (err instanceof ZodError) {
        next(
          new DomainValidationError('Request validation failed', {
            issues: err.issues,
          })
        );
        return;
      }
      next(err);
    }
  };
}

/**
 * Type-safe accessor for validated request data.
 * Throws explicit internal error if accessed without running validation middleware.
 */
export function getValidated<TBody = unknown, TQuery = unknown, TParams = unknown>(
  req: Request
): { body: TBody; query: TQuery; params: TParams } {
  if (!req.validated) {
    throw new SecureFlowError('Missing request validation context', 'INTERNAL_ERROR', 500);
  }
  return req.validated as { body: TBody; query: TQuery; params: TParams };
}

/**
 * Type-safe accessor for validated request body.
 * Throws explicit internal error if body was not validated.
 */
export function getValidatedBody<T>(req: Request): T {
  if (!req.validated || req.validated.body === undefined) {
    throw new SecureFlowError('Missing request body validation context', 'INTERNAL_ERROR', 500);
  }
  return req.validated.body as T;
}

/**
 * Type-safe accessor for validated request query.
 * Throws explicit internal error if query was not validated.
 */
export function getValidatedQuery<T>(req: Request): T {
  if (!req.validated || req.validated.query === undefined) {
    throw new SecureFlowError('Missing request query validation context', 'INTERNAL_ERROR', 500);
  }
  return req.validated.query as T;
}

/**
 * Type-safe accessor for validated request params.
 * Throws explicit internal error if params was not validated.
 */
export function getValidatedParams<T>(req: Request): T {
  if (!req.validated || req.validated.params === undefined) {
    throw new SecureFlowError('Missing request params validation context', 'INTERNAL_ERROR', 500);
  }
  return req.validated.params as T;
}
