import { describe, it, expect } from 'vitest';
import request from 'supertest';
import express from 'express';
import { createApp } from '../src/app.js';
import { errorHandlerMiddleware } from '../src/middleware/error-handler.js';
import { SecureFlowError } from '@secureflow/shared';

describe('Centralized Error Handling & Nested Schema', () => {
  const app = createApp();

  describe('404 Not Found Handler', () => {
    it('returns standardized nested error response for non-existent routes', async () => {
      const res = await request(app).get('/non-existent-endpoint');

      expect(res.status).toBe(404);
      expect(res.body).toEqual({
        error: {
          code: 'NOT_FOUND',
          message: 'Cannot GET /non-existent-endpoint',
        },
      });
    });
  });

  describe('Malformed JSON Body Parser Handling', () => {
    it('returns HTTP 400 with BAD_REQUEST for broken JSON syntax', async () => {
      const res = await request(app)
        .post('/health/ready')
        .set('Content-Type', 'application/json')
        .send('{ invalid json: "broken",');

      expect(res.status).toBe(400);
      expect(res.body).toEqual({
        error: {
          code: 'BAD_REQUEST',
          message: 'Malformed JSON payload in request body',
        },
      });
    });
  });

  describe('Operational & Asynchronous Error Handling', () => {
    it('maps operational SecureFlowError to appropriate HTTP status and code', async () => {
      const testApp = express();
      testApp.use(express.json());
      testApp.get('/test-operational-error', () => {
        throw new SecureFlowError('Project resource not found', 'PROJECT_NOT_FOUND', 404);
      });
      testApp.use(errorHandlerMiddleware);

      const res = await request(testApp).get('/test-operational-error');

      expect(res.status).toBe(404);
      expect(res.body).toEqual({
        error: {
          code: 'PROJECT_NOT_FOUND',
          message: 'Project resource not found',
        },
      });
    });

    it('catches unexpected asynchronous exceptions and returns safe 500 without stack leaks', async () => {
      const testApp = express();
      testApp.use(express.json());
      testApp.get('/test-crash', async () => {
        // Simulates an unexpected asynchronous runtime crash
        await new Promise((resolve) => setTimeout(resolve, 5));
        throw new Error('Database connection failed unexpectedly with internal password secret');
      });
      testApp.use(errorHandlerMiddleware);

      const res = await request(testApp).get('/test-crash');

      expect(res.status).toBe(500);
      expect(res.body).toEqual({
        error: {
          code: 'INTERNAL_ERROR',
          message: 'An unexpected internal server error occurred',
        },
      });

      // Crucial security check: Ensure internal error details and stack traces are NOT leaked
      expect(JSON.stringify(res.body)).not.toContain('Database connection failed');
      expect(JSON.stringify(res.body)).not.toContain('password');
      expect(JSON.stringify(res.body)).not.toContain('stack');
    });
  });
});
