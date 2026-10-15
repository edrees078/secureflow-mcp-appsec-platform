import { describe, it, expect } from 'vitest';
import request from 'supertest';
import { createApp } from '../src/app.js';

describe('HTTP Security Middleware & Headers', () => {
  const app = createApp();

  describe('Helmet Security Headers', () => {
    it('sets standard security headers', async () => {
      const res = await request(app).get('/health/ready');

      expect(res.headers['x-content-type-options']).toBe('nosniff');
      expect(res.headers['x-frame-options']).toBe('SAMEORIGIN');
    });
  });

  describe('CORS Enforcement', () => {
    it('allows trusted origin and sets credentials header', async () => {
      const res = await request(app)
        .get('/health/ready')
        .set('Origin', 'http://localhost:5173');

      expect(res.status).toBe(200);
      expect(res.headers['access-control-allow-origin']).toBe('http://localhost:5173');
      expect(res.headers['access-control-allow-credentials']).toBe('true');
    });

    it('rejects untrusted origin with 403 Forbidden', async () => {
      const res = await request(app)
        .get('/health/ready')
        .set('Origin', 'http://unauthorized-malicious-site.com');

      expect(res.status).toBe(403);
      expect(res.body).toEqual({
        error: {
          code: 'FORBIDDEN_CORS',
          message: expect.stringContaining('CORS origin'),
        },
      });
      expect(res.headers['access-control-allow-origin']).toBeUndefined();
    });
  });

  describe('Request-ID Sanitization & Propagation', () => {
    it('propagates a valid external X-Request-Id header', async () => {
      const clientTraceId = 'client-trace-12345_abc';
      const res = await request(app)
        .get('/health/ready')
        .set('X-Request-Id', clientTraceId);

      expect(res.status).toBe(200);
      expect(res.headers['x-request-id']).toBe(clientTraceId);
    });

    it('generates a new UUID when X-Request-Id is absent', async () => {
      const res = await request(app).get('/health/ready');

      expect(res.status).toBe(200);
      const reqId = res.headers['x-request-id'];
      expect(reqId).toBeDefined();
      // Verify valid UUID format
      expect(reqId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i);
    });

    it('rejects unsafe X-Request-Id containing invalid characters or excessive length and replaces it with a valid UUID', async () => {
      // 1. Script injection attempt
      const xssAttempt = '<script>alert(1)</script>';
      const resXss = await request(app)
        .get('/health/ready')
        .set('X-Request-Id', xssAttempt);

      expect(resXss.status).toBe(200);
      expect(resXss.headers['x-request-id']).not.toBe(xssAttempt);
      expect(resXss.headers['x-request-id']).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i);

      // 2. Excessively long ID (> 64 chars)
      const longId = 'a'.repeat(100);
      const resLong = await request(app)
        .get('/health/ready')
        .set('X-Request-Id', longId);

      expect(resLong.status).toBe(200);
      expect(resLong.headers['x-request-id']).not.toBe(longId);
      expect(resLong.headers['x-request-id']).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i);
    });
  });
});
