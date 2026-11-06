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
import {
  createTestDatabaseClient,
  validateTestDatabaseUrl,
  type TestDatabaseClient,
} from '@secureflow/domain/testing';
import { createTestApp } from '../helpers/test-app.js';
import type { Express } from 'express';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
dotenv.config({ path: path.resolve(__dirname, '../../../../.env') });
dotenv.config({ path: path.resolve(__dirname, '../../../.env') });

describe('PostgreSQL 17.11 Integration: Project REST API (/api/v1/projects)', () => {
  let domainServices: DomainServices;
  let testDbClient: TestDatabaseClient;
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
  const createdProjectIds: string[] = [];

  beforeAll(async () => {
    const rawTestUrl = validateTestDatabaseUrl(process.env.TEST_DATABASE_URL);
    testDbClient = await createTestDatabaseClient(rawTestUrl);
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
    let cleanupError: unknown = null;
    try {
      if (testDbClient && createdProjectIds.length > 0) {
        for (const projId of createdProjectIds) {
          await testDbClient.cleanupProjectHierarchy(projId);
        }
      }
    } catch (err: unknown) {
      cleanupError = err;
    } finally {
      try {
        if (testDbClient) {
          await testDbClient.close();
        }
      } catch (closeErr) {
        if (!cleanupError) cleanupError = closeErr;
      }
      try {
        if (domainServices) {
          await domainServices.close();
        }
      } catch (closeErr) {
        if (!cleanupError) cleanupError = closeErr;
      }

      if (cleanupError) {
        const errorMsg = cleanupError instanceof Error ? cleanupError.message : String(cleanupError);
        throw new Error(`Integration teardown cleanup failure: ${errorMsg}`);
      }
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
    createdProjectIds.push(createdProjectId);
    testDbClient.registerSyntheticProject(createdProjectId);
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

  it('10. Database verification — Pre-existing records remain intact while synthetic project is tracked', async () => {
    // Assert synthetic project exists in database prior to teardown
    const checkRes = await testDbClient.query(
      'SELECT id, is_active FROM projects WHERE id = $1;',
      [createdProjectId]
    );
    expect(checkRes.rows.length).toBe(1);
    expect(checkRes.rows[0].is_active).toBe(false);

    // Assert pre-existing users are intact
    const adminCheck = await testDbClient.query(
      'SELECT id, is_active FROM users WHERE id = $1;',
      [adminActor.id]
    );
    expect(adminCheck.rows.length).toBe(1);
    expect(adminCheck.rows[0].is_active).toBe(true);
  });
});
