import { describe, it, expect } from 'vitest';
import express from 'express';
import type { Request, Response } from 'express';
import request from 'supertest';
import { z } from 'zod';
import {
  validateRequest,
  getValidated,
  getValidatedBody,
  getValidatedQuery,
  getValidatedParams,
} from '../../src/middleware/validate.js';
import { errorHandlerMiddleware } from '../../src/middleware/error-handler.js';
import { UuidSchema } from '@secureflow/schemas';

describe('Express 5 Zod Validation Middleware & Context Accessors', () => {
  it('validates request params, query, and body and populates req.validated context', async () => {
    const app = express();
    app.use(express.json());

    const ParamsSchema = z.object({ id: UuidSchema }).strict();
    const QuerySchema = z.object({ page: z.preprocess(Number, z.number().int().min(1)) }).strict();
    const BodySchema = z.object({ title: z.string().min(3) }).strict();

    app.post(
      '/test/:id',
      validateRequest({
        params: ParamsSchema,
        query: QuerySchema,
        body: BodySchema,
      }),
      (req: Request, res: Response) => {
        const validated = getValidated<
          { title: string },
          { page: number },
          { id: string }
        >(req);

        res.status(200).json({
          received: validated,
          individualAccessors: {
            body: getValidatedBody(req),
            query: getValidatedQuery(req),
            params: getValidatedParams(req),
          },
        });
      }
    );
    app.use(errorHandlerMiddleware);

    const validId = '00000000-0000-0000-0000-000000000001';
    const res = await request(app)
      .post(`/test/${validId}?page=3`)
      .send({ title: 'Valid Title' });

    expect(res.status).toBe(200);
    expect(res.body.received).toEqual({
      params: { id: validId },
      query: { page: 3 },
      body: { title: 'Valid Title' },
    });
    expect(res.body.individualAccessors.body).toEqual({ title: 'Valid Title' });
    expect(res.body.individualAccessors.query).toEqual({ page: 3 });
    expect(res.body.individualAccessors.params).toEqual({ id: validId });
  });

  it('formats Zod validation errors to HTTP 400 VALIDATION_ERROR with issues in details', async () => {
    const app = express();
    app.use(express.json());

    const BodySchema = z.object({
      name: z.string().min(3, 'Name too short'),
    }).strict();

    app.post('/validate-body', validateRequest({ body: BodySchema }), (_req, res) => {
      res.status(200).json({ status: 'ok' });
    });
    app.use(errorHandlerMiddleware);

    const res = await request(app)
      .post('/validate-body')
      .send({ name: 'ab' });

    expect(res.status).toBe(400);
    expect(res.body.error).toEqual({
      code: 'VALIDATION_ERROR',
      message: 'Request validation failed',
      details: {
        issues: expect.arrayContaining([
          expect.objectContaining({
            message: 'Name too short',
            path: ['name'],
          }),
        ]),
      },
    });
  });

  it('rejects invalid UUID in route parameters with HTTP 400', async () => {
    const app = express();
    const ParamsSchema = z.object({ id: UuidSchema }).strict();

    app.get('/test-param/:id', validateRequest({ params: ParamsSchema }), (_req, res) => {
      res.status(200).json({ status: 'ok' });
    });
    app.use(errorHandlerMiddleware);

    const res = await request(app).get('/test-param/not-a-valid-uuid');

    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('VALIDATION_ERROR');
    expect(res.body.error.details.issues[0].message).toBe('Invalid UUID format');
  });

  it('throws HTTP 500 when accessors are invoked without running validation middleware', async () => {
    const app = express();

    app.get('/unvalidated-route', (req: Request) => {
      getValidated(req);
    });
    app.use(errorHandlerMiddleware);

    const res = await request(app).get('/unvalidated-route');

    expect(res.status).toBe(500);
    expect(res.body.error.code).toBe('INTERNAL_ERROR');
    expect(res.body.error.message).toBe('An internal server error occurred');
  });

  it('throws HTTP 500 when specific segment accessor is invoked without that segment schema', async () => {
    const app = express();
    const ParamsSchema = z.object({ id: z.string() });

    app.get(
      '/partial-validate/:id',
      validateRequest({ params: ParamsSchema }),
      (req: Request) => {
        getValidatedBody(req);
      }
    );
    app.use(errorHandlerMiddleware);

    const res = await request(app).get('/partial-validate/123');

    expect(res.status).toBe(500);
    expect(res.body.error.code).toBe('INTERNAL_ERROR');
    expect(res.body.error.message).toBe('An internal server error occurred');
  });

  it('supports asynchronous Zod refinement schemas', async () => {
    const app = express();
    app.use(express.json());

    const AsyncSchema = z.object({
      code: z.string().refine(async (val) => {
        await new Promise((resolve) => setTimeout(resolve, 5));
        return val === 'ALLOWED';
      }, 'Async code validation rejected'),
    });

    app.post('/async-refine', validateRequest({ body: AsyncSchema }), (_req, res) => {
      res.status(200).json({ status: 'ok' });
    });
    app.use(errorHandlerMiddleware);

    const failRes = await request(app)
      .post('/async-refine')
      .send({ code: 'DISALLOWED' });
    expect(failRes.status).toBe(400);
    expect(failRes.body.error.details.issues[0].message).toBe('Async code validation rejected');

    const passRes = await request(app)
      .post('/async-refine')
      .send({ code: 'ALLOWED' });
    expect(passRes.status).toBe(200);
  });
});
