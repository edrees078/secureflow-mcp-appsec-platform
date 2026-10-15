import { describe, it, expect } from 'vitest';
import request from 'supertest';
import { createApp } from '../src/app.js';

describe('Health Endpoint (GET /health/ready)', () => {
  const app = createApp();

  it('returns HTTP 200 with honest readiness status', async () => {
    const res = await request(app).get('/health/ready');

    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toMatch(/json/);
    expect(res.body).toEqual({
      status: 'ready',
      service: 'secureflow-api',
      uptime: expect.any(Number),
      timestamp: expect.any(String),
      checks: {
        http: 'ok',
      },
    });

    // Verify timestamp is a valid ISO 8601 string
    expect(new Date(res.body.timestamp).toISOString()).toBe(res.body.timestamp);
    expect(res.body.uptime).toBeGreaterThanOrEqual(0);

    // Verify readiness reports only implemented guarantees (no fake DB checks)
    expect(res.body.checks).not.toHaveProperty('database');
    expect(res.body.checks).not.toHaveProperty('postgres');
  });
});
