import path from 'node:path';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import request from 'supertest';
import {
  createDomainServices,
  ActorContext,
  type DomainServices,
} from '@secureflow/domain';
import { SecureFlowError } from '@secureflow/shared';
import { createTestApp } from '../helpers/test-app.js';
import type { Express } from 'express';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
dotenv.config({ path: path.resolve(__dirname, '../../../../.env') });
dotenv.config({ path: path.resolve(__dirname, '../../../.env') });

function validateTestDatabaseUrl(rawUrl?: string): string {
  if (!rawUrl || typeof rawUrl !== 'string' || rawUrl.trim().length === 0) {
    throw new SecureFlowError(
      'SAFETY REFUSAL: TEST_DATABASE_URL is required and cannot be empty. Fallback to DATABASE_URL is strictly prohibited.',
      'TEST_DATABASE_URL_REQUIRED',
      500
    );
  }

  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new SecureFlowError(
      'SAFETY REFUSAL: TEST_DATABASE_URL is not a valid URL.',
      'TEST_DATABASE_URL_INVALID',
      500
    );
  }

  const dbName = parsed.pathname.replace(/^\//, '');
  if (dbName === 'secureflow_dev') {
    throw new SecureFlowError(
      'SAFETY REFUSAL: TEST_DATABASE_URL must NEVER target development database "secureflow_dev". It must target "secureflow_test".',
      'TEST_DATABASE_TARGET_DEV_REFUSED',
      500
    );
  }

  if (dbName !== 'secureflow_test') {
    throw new SecureFlowError(
      `SAFETY REFUSAL: Target database must be "secureflow_test", got "${dbName}".`,
      'TEST_DATABASE_TARGET_INVALID',
      500
    );
  }

  if (parsed.port !== '5433') {
    throw new SecureFlowError(
      `SAFETY REFUSAL: PostgreSQL 17 test container must run on host port 5433, got "${parsed.port}".`,
      'TEST_DATABASE_PORT_INVALID',
      500
    );
  }

  return rawUrl;
}

describe('PostgreSQL 17.11 Integration: Project REST API (/api/v1/projects)', () => {
  let domainServices: DomainServices;
  let testApp: Express;
  let currentActor: ActorContext;

  // Verified active user accounts in secureflow_test
  const adminActor = new ActorContext({
    id: '59c69e57-4a9f-42fd-8e6b-40a357ca9cb5',
    globalRole: 'ADMIN',
    isActive: true,
  });

  const memberAnalystActor = new ActorContext({
    id: '2765d3dc-d8a4-439e-8ef9-3c7585800716',
    globalRole: 'ANALYST',
    isActive: true,
  });

  const foreignAnalystActor = new ActorContext({
    id: '23e46735-3ef3-4c83-ba94-0cb5149f08b6',
    globalRole: 'ANALYST',
    isActive: true,
  });

  let createdProjectId: string;

  beforeAll(async () => {
    const rawTestUrl = validateTestDatabaseUrl(process.env.TEST_DATABASE_URL);
    domainServices = createDomainServices({
      connectionString: rawTestUrl,
      maxConnections: 5,
      connectionTimeoutMillis: 5000,
      statementTimeoutMillis: 10000,
    });

    testApp = createTestApp({
      services: domainServices,
      actor: () => currentActor,
    });
  });

  afterAll(async () => {
    if (domainServices) {
      await domainServices.close();
    }
  });

  it('1. POST /api/v1/projects — Admin creates project via HTTP with database persistence', async () => {
    currentActor = adminActor;

    const res = await request(testApp)
      .post('/api/v1/projects')
      .send({
        name: `Integ Project ${Date.now()}`,
        description: 'End-to-end integration test project',
      });

    expect(res.status).toBe(201);
    expect(res.body.data).toBeDefined();
    expect(res.body.data.id).toMatch(/^[0-9a-f-]{36}$/);
    expect(res.body.data.isActive).toBe(true);

    createdProjectId = res.body.data.id;
  });

  it('2. GET /api/v1/projects/:id — Admin retrieves persisted project record from PostgreSQL', async () => {
    currentActor = adminActor;

    const res = await request(testApp).get(`/api/v1/projects/${createdProjectId}`);

    expect(res.status).toBe(200);
    expect(res.body.data.id).toBe(createdProjectId);
  });

  it('3. GET /api/v1/projects — Admin lists projects with bounded pagination from PostgreSQL', async () => {
    currentActor = adminActor;

    const res = await request(testApp).get('/api/v1/projects?page=1&limit=10');

    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.data)).toBe(true);
    expect(res.body.pagination).toBeDefined();
    expect(res.body.pagination.page).toBe(1);
    expect(res.body.pagination.limit).toBe(10);
  });

  it('4. POST /api/v1/projects/:id/members — Admin adds analyst member to project in PostgreSQL', async () => {
    currentActor = adminActor;

    const res = await request(testApp)
      .post(`/api/v1/projects/${createdProjectId}/members`)
      .send({
        userId: memberAnalystActor.id,
        role: 'ANALYST',
      });

    expect(res.status).toBe(201);
    expect(res.body.data.projectId).toBe(createdProjectId);
    expect(res.body.data.userId).toBe(memberAnalystActor.id);
    expect(res.body.data.role).toBe('ANALYST');
  });

  it('5. GET /api/v1/projects/:id/members — Member analyst retrieves member list from PostgreSQL', async () => {
    currentActor = new ActorContext({
      id: memberAnalystActor.id,
      globalRole: 'ANALYST',
      isActive: true,
      memberships: [{ projectId: createdProjectId, role: 'ANALYST' }],
    });

    const res = await request(testApp).get(`/api/v1/projects/${createdProjectId}/members`);

    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.data)).toBe(true);
    expect(res.body.data.some((m: { userId: string }) => m.userId === memberAnalystActor.id)).toBe(true);
  });

  it('6. GET /api/v1/projects/:id — Non-member analyst receives HTTP 404 existence hiding from PostgreSQL', async () => {
    currentActor = foreignAnalystActor;

    const res = await request(testApp).get(`/api/v1/projects/${createdProjectId}`);

    expect(res.status).toBe(404);
    expect(res.body.error.code).toBe('NOT_FOUND');
  });

  it('7. PATCH /api/v1/projects/:id — Admin updates project metadata in PostgreSQL', async () => {
    currentActor = adminActor;

    const res = await request(testApp)
      .patch(`/api/v1/projects/${createdProjectId}`)
      .send({
        description: 'Updated integration test description',
      });

    expect(res.status).toBe(200);
    expect(res.body.data.description).toBe('Updated integration test description');
  });

  it('8. DELETE /api/v1/projects/:id/members/:userId — Admin removes member returning HTTP 204 from PostgreSQL', async () => {
    currentActor = adminActor;

    const res = await request(testApp).delete(
      `/api/v1/projects/${createdProjectId}/members/${memberAnalystActor.id}`
    );

    expect(res.status).toBe(204);
    expect(res.text).toBe('');
  });

  it('9. DELETE /api/v1/projects/:id — Admin archives project returning HTTP 200 from PostgreSQL', async () => {
    currentActor = adminActor;

    const res = await request(testApp).delete(`/api/v1/projects/${createdProjectId}`);

    expect(res.status).toBe(200);
    expect(res.body.data.isActive).toBe(false);
  });
});
