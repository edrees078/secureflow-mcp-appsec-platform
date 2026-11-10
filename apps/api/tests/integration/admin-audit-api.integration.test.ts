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
import { createApp } from '../../src/app.js';
import type { Express } from 'express';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
dotenv.config({ path: path.resolve(__dirname, '../../../../.env') });
dotenv.config({ path: path.resolve(__dirname, '../../../.env') });

describe('PostgreSQL 17.11 Integration: Global Admin Finding Operations & Audit Log REST API', () => {
  let domainServices: DomainServices;
  let testDbClient: TestDatabaseClient;
  let testApp: Express;
  let currentActor: ActorContext;

  const adminActor = new ActorContext({
    id: '59c69e57-4a9f-42fd-8e6b-40a357ca9cb5',
    globalRole: 'ADMIN',
    isActive: true,
  });

  const analystActor = new ActorContext({
    id: '2765d3dc-d8a4-439e-8ef9-3c7585800716',
    globalRole: 'ANALYST',
    isActive: true,
  });

  const dev1Actor = new ActorContext({
    id: '875e4e49-9294-4286-83a6-0f79d8405fba',
    globalRole: 'DEVELOPER',
    isActive: true,
  });

  let testProjectId: string;
  let testFindingId: string;
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

    // Create synthetic test project
    const project = await domainServices.projectService.createProject(adminActor, {
      name: `Admin Audit Test Project ${Date.now()}`,
      description: 'Project for testing admin exceptional operations and audit ledger REST API',
    });
    testProjectId = project.id;
    createdProjectIds.push(testProjectId);
    testDbClient.registerSyntheticProject(testProjectId);

    // Add project members: Analyst and Developer
    await domainServices.projectService.addMember(adminActor, testProjectId, {
      userId: analystActor.id,
      role: 'ANALYST',
    });
    await domainServices.projectService.addMember(adminActor, testProjectId, {
      userId: dev1Actor.id,
      role: 'DEVELOPER',
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

  // ---------------------------------------------------------------------------
  // 1. Initial Finding Creation Through HTTP
  // ---------------------------------------------------------------------------
  it('1. POST /api/v1/findings — Analyst creates initial finding in OPEN status with version 1', async () => {
    currentActor = analystActor;

    const res = await request(testApp)
      .post('/api/v1/findings')
      .send({
        projectId: testProjectId,
        title: 'Critical RCE in Document Converter Service',
        description: 'Improper sanitation of uploaded PDF triggers arbitrary code execution.',
        severity: 'CRITICAL',
        category: 'INJECTION',
        cvssScore: 9.8,
        dueDate: '2026-12-31',
      });

    expect(res.status).toBe(201);
    expect(res.body.data.id).toBeDefined();
    expect(res.body.data.status).toBe('OPEN');
    expect(res.body.data.version).toBe(1);
    testFindingId = res.body.data.id;
  });

  // ---------------------------------------------------------------------------
  // 2. Non-Admin Actors Denied Force-Close
  // ---------------------------------------------------------------------------
  it('2. POST /api/v1/findings/:id/force-close — Rejects non-admin callers (Analyst, Developer) with HTTP 403', async () => {
    // Analyst attempt
    currentActor = analystActor;
    const analystRes = await request(testApp)
      .post(`/api/v1/findings/${testFindingId}/force-close`)
      .send({
        expectedVersion: 1,
        justification: 'Attempted force-close by analyst',
      });

    expect(analystRes.status).toBe(403);
    expect(analystRes.body.error.code).toBe('FORBIDDEN');

    // Developer attempt
    currentActor = dev1Actor;
    const devRes = await request(testApp)
      .post(`/api/v1/findings/${testFindingId}/force-close`)
      .send({
        expectedVersion: 1,
        justification: 'Attempted force-close by developer',
      });

    expect(devRes.status).toBe(403);
    expect(devRes.body.error.code).toBe('FORBIDDEN');

    // Verify finding remains OPEN and version 1 in DB
    const dbRes = await testDbClient.query(
      'SELECT status, version FROM findings WHERE id = $1;',
      [testFindingId],
    );
    expect(dbRes.rows[0].status).toBe('OPEN');
    expect(dbRes.rows[0].version).toBe(1);
  });

  // ---------------------------------------------------------------------------
  // 2b. Mandatory Justification & ExpectedVersion Validation on Force-Close
  // ---------------------------------------------------------------------------
  it('2b. POST /api/v1/findings/:id/force-close — Rejects empty, whitespace-only (spaces/tabs/newlines), or invalid expectedVersion with HTTP 400 and zero state/audit writes', async () => {
    currentActor = adminActor;

    for (const badBody of [
      { expectedVersion: 1, justification: '' },
      { expectedVersion: 1, justification: '   ' },
      { expectedVersion: 1, justification: ' \t\n\r ' },
      { expectedVersion: 0, justification: 'Valid justification text' },
      { justification: 'Missing expectedVersion' },
    ]) {
      const res = await request(testApp)
        .post(`/api/v1/findings/${testFindingId}/force-close`)
        .send(badBody);

      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
    }

    // Verify finding remains OPEN and version 1 in PostgreSQL
    const dbRes = await testDbClient.query(
      'SELECT status, version FROM findings WHERE id = $1;',
      [testFindingId],
    );
    expect(dbRes.rows[0].status).toBe('OPEN');
    expect(dbRes.rows[0].version).toBe(1);

    // Verify zero force-close audit events were emitted
    const auditRes = await testDbClient.query(
      `SELECT count(*) FROM audit_events WHERE resource_id = $1::uuid AND event_type = 'finding.force_closed';`,
      [testFindingId],
    );
    expect(parseInt(auditRes.rows[0].count, 10)).toBe(0);
  });

  // ---------------------------------------------------------------------------
  // 3. Global Admin Exceptional Force-Close
  // ---------------------------------------------------------------------------
  it('3. POST /api/v1/findings/:id/force-close — Global Admin force-closes finding (OPEN -> CLOSED, OCC version 2)', async () => {
    currentActor = adminActor;

    const res = await request(testApp)
      .post(`/api/v1/findings/${testFindingId}/force-close`)
      .send({
        expectedVersion: 1,
        justification: 'Emergency mitigation applied at perimeter WAF under Incident INC-9021.',
      });

    expect(res.status).toBe(200);
    expect(res.body.data.id).toBe(testFindingId);
    expect(res.body.data.status).toBe('CLOSED');
    expect(res.body.data.version).toBe(2);

    // Verify finding row updated in PostgreSQL
    const dbRes = await testDbClient.query(
      'SELECT status, version FROM findings WHERE id = $1;',
      [testFindingId],
    );
    expect(dbRes.rows[0].status).toBe('CLOSED');
    expect(dbRes.rows[0].version).toBe(2);

    // Verify audit event persisted in PostgreSQL
    const auditRes = await testDbClient.query(
      `SELECT event_category, event_type, resource_id, actor_id, after_state
       FROM audit_events
       WHERE resource_id = $1::uuid AND event_type = 'finding.force_closed';`,
      [testFindingId],
    );
    expect(auditRes.rows.length).toBe(1);
    expect(auditRes.rows[0].event_category).toBe('FINDING');
    expect(auditRes.rows[0].actor_id).toBe(adminActor.id);
    expect(auditRes.rows[0].after_state.status).toBe('CLOSED');
    expect(auditRes.rows[0].after_state.justification).toBe(
      'Emergency mitigation applied at perimeter WAF under Incident INC-9021.'
    );
  });

  // ---------------------------------------------------------------------------
  // 4. Stale OCC Version on Force Operations
  // ---------------------------------------------------------------------------
  it('4. POST /api/v1/findings/:id/force-reopen — Returns HTTP 409 CONCURRENCY_CONFLICT on stale expectedVersion', async () => {
    currentActor = adminActor;

    // Stale version: passing version 1 when DB version is 2
    const res = await request(testApp)
      .post(`/api/v1/findings/${testFindingId}/force-reopen`)
      .send({
        expectedVersion: 1,
        justification: 'Attempting reopen with stale OCC version',
      });

    expect(res.status).toBe(409);
    expect(res.body.error.code).toBe('CONCURRENCY_CONFLICT');

    // Verify finding remains CLOSED and version remains 2
    const dbRes = await testDbClient.query(
      'SELECT status, version FROM findings WHERE id = $1;',
      [testFindingId],
    );
    expect(dbRes.rows[0].status).toBe('CLOSED');
    expect(dbRes.rows[0].version).toBe(2);
  });

  // ---------------------------------------------------------------------------
  // 5. Non-Admin Actors Denied Force-Reopen
  // ---------------------------------------------------------------------------
  it('5. POST /api/v1/findings/:id/force-reopen — Rejects non-admin callers (Analyst, Developer) with HTTP 403', async () => {
    // Analyst attempt
    currentActor = analystActor;
    const analystRes = await request(testApp)
      .post(`/api/v1/findings/${testFindingId}/force-reopen`)
      .send({
        expectedVersion: 2,
        justification: 'Attempted force-reopen by analyst',
      });

    expect(analystRes.status).toBe(403);
    expect(analystRes.body.error.code).toBe('FORBIDDEN');

    // Developer attempt
    currentActor = dev1Actor;
    const devRes = await request(testApp)
      .post(`/api/v1/findings/${testFindingId}/force-reopen`)
      .send({
        expectedVersion: 2,
        justification: 'Attempted force-reopen by developer',
      });

    expect(devRes.status).toBe(403);
    expect(devRes.body.error.code).toBe('FORBIDDEN');

    // Verify finding remains CLOSED and version 2 in DB
    const dbRes = await testDbClient.query(
      'SELECT status, version FROM findings WHERE id = $1;',
      [testFindingId],
    );
    expect(dbRes.rows[0].status).toBe('CLOSED');
    expect(dbRes.rows[0].version).toBe(2);
  });

  // ---------------------------------------------------------------------------
  // 5b. Mandatory Justification & ExpectedVersion Validation on Force-Reopen
  // ---------------------------------------------------------------------------
  it('5b. POST /api/v1/findings/:id/force-reopen — Rejects empty, whitespace-only (spaces/tabs/newlines), or invalid expectedVersion with HTTP 400 and zero state/audit writes', async () => {
    currentActor = adminActor;

    for (const badBody of [
      { expectedVersion: 2, justification: '' },
      { expectedVersion: 2, justification: '   ' },
      { expectedVersion: 2, justification: ' \t\n\r ' },
      { expectedVersion: -1, justification: 'Valid justification text' },
      { justification: 'Missing expectedVersion' },
    ]) {
      const res = await request(testApp)
        .post(`/api/v1/findings/${testFindingId}/force-reopen`)
        .send(badBody);

      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
    }

    // Verify finding remains CLOSED and version 2 in PostgreSQL
    const dbRes = await testDbClient.query(
      'SELECT status, version FROM findings WHERE id = $1;',
      [testFindingId],
    );
    expect(dbRes.rows[0].status).toBe('CLOSED');
    expect(dbRes.rows[0].version).toBe(2);

    // Verify zero force-reopen audit events were emitted
    const auditRes = await testDbClient.query(
      `SELECT count(*) FROM audit_events WHERE resource_id = $1::uuid AND event_type = 'finding.force_reopened';`,
      [testFindingId],
    );
    expect(parseInt(auditRes.rows[0].count, 10)).toBe(0);
  });

  // ---------------------------------------------------------------------------
  // 6. Global Admin Exceptional Force-Reopen
  // ---------------------------------------------------------------------------
  it('6. POST /api/v1/findings/:id/force-reopen — Global Admin force-reopens finding (CLOSED -> REOPENED, OCC version 3)', async () => {
    currentActor = adminActor;

    const res = await request(testApp)
      .post(`/api/v1/findings/${testFindingId}/force-reopen`)
      .send({
        expectedVersion: 2,
        justification: 'WAF bypass identified in testing; vulnerability re-emerged on secondary port.',
      });

    expect(res.status).toBe(200);
    expect(res.body.data.id).toBe(testFindingId);
    expect(res.body.data.status).toBe('REOPENED');
    expect(res.body.data.version).toBe(3);

    // Verify finding row updated in PostgreSQL
    const dbRes = await testDbClient.query(
      'SELECT status, version FROM findings WHERE id = $1;',
      [testFindingId],
    );
    expect(dbRes.rows[0].status).toBe('REOPENED');
    expect(dbRes.rows[0].version).toBe(3);

    // Verify audit event persisted in PostgreSQL
    const auditRes = await testDbClient.query(
      `SELECT event_category, event_type, resource_id, actor_id, after_state
       FROM audit_events
       WHERE resource_id = $1::uuid AND event_type = 'finding.force_reopened';`,
      [testFindingId],
    );
    expect(auditRes.rows.length).toBe(1);
    expect(auditRes.rows[0].event_category).toBe('FINDING');
    expect(auditRes.rows[0].actor_id).toBe(adminActor.id);
    expect(auditRes.rows[0].after_state.status).toBe('REOPENED');
    expect(auditRes.rows[0].after_state.justification).toBe(
      'WAF bypass identified in testing; vulnerability re-emerged on secondary port.'
    );
  });

  // ---------------------------------------------------------------------------
  // 7. Non-Admin Actors Denied Audit Log Query (NEG-12)
  // ---------------------------------------------------------------------------
  it('7. GET /api/v1/audit-events — Rejects non-admin callers (Analyst, Developer) with HTTP 403 (NEG-12)', async () => {
    // Analyst attempt
    currentActor = analystActor;
    const analystRes = await request(testApp).get('/api/v1/audit-events');
    expect(analystRes.status).toBe(403);
    expect(analystRes.body.error.code).toBe('FORBIDDEN');

    // Developer attempt
    currentActor = dev1Actor;
    const devRes = await request(testApp).get('/api/v1/audit-events');
    expect(devRes.status).toBe(403);
    expect(devRes.body.error.code).toBe('FORBIDDEN');
  });

  // ---------------------------------------------------------------------------
  // 8. Global Admin Queries Audit Events Ledger
  // ---------------------------------------------------------------------------
  it('8. GET /api/v1/audit-events — Global Admin queries audit events with filtering and pagination', async () => {
    currentActor = adminActor;

    const res = await request(testApp)
      .get('/api/v1/audit-events')
      .query({
        eventCategory: 'FINDING',
        resourceId: testFindingId,
        page: '1',
        limit: '10',
      });

    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.data)).toBe(true);
    expect(res.body.pagination).toBeDefined();
    expect(res.body.pagination.page).toBe(1);
    expect(res.body.pagination.limit).toBe(10);
    expect(res.body.pagination.total).toBeGreaterThanOrEqual(2);

    // Verify finding.force_closed and finding.force_reopened exist in the results
    const eventTypes = res.body.data.map((evt: { eventType: string }) => evt.eventType);
    expect(eventTypes).toContain('finding.force_closed');
    expect(eventTypes).toContain('finding.force_reopened');

    // Verify event payload structure
    const forceCloseEvt = res.body.data.find(
      (evt: { eventType: string }) => evt.eventType === 'finding.force_closed'
    );
    expect(forceCloseEvt).toBeDefined();
    expect(forceCloseEvt.eventCategory).toBe('FINDING');
    expect(forceCloseEvt.resourceId).toBe(testFindingId);
    expect(forceCloseEvt.actorId).toBe(adminActor.id);
    expect(Object.keys(forceCloseEvt).sort()).toEqual([
      'actorId',
      'afterState',
      'beforeState',
      'createdAt',
      'eventCategory',
      'eventType',
      'id',
      'ipAddress',
      'resourceId',
      'resourceType',
      'userAgent',
    ]);

    // Verify deterministic descending createdAt ordering
    for (let i = 0; i < res.body.data.length - 1; i++) {
      const currentTs = new Date(res.body.data[i].createdAt).getTime();
      const nextTs = new Date(res.body.data[i + 1].createdAt).getTime();
      expect(currentTs).toBeGreaterThanOrEqual(nextTs);
    }

    // Verify multi-page pagination (limit = 1, page = 1 vs page = 2)
    const page1Res = await request(testApp)
      .get('/api/v1/audit-events')
      .query({
        eventCategory: 'FINDING',
        resourceId: testFindingId,
        page: '1',
        limit: '1',
      });
    const page2Res = await request(testApp)
      .get('/api/v1/audit-events')
      .query({
        eventCategory: 'FINDING',
        resourceId: testFindingId,
        page: '2',
        limit: '1',
      });

    expect(page1Res.status).toBe(200);
    expect(page2Res.status).toBe(200);
    expect(page1Res.body.data.length).toBe(1);
    expect(page2Res.body.data.length).toBe(1);
    expect(page1Res.body.data[0].id).not.toBe(page2Res.body.data[0].id);
    expect(page1Res.body.pagination.page).toBe(1);
    expect(page2Res.body.pagination.page).toBe(2);
    expect(page1Res.body.pagination.totalPages).toBe(page1Res.body.pagination.total);
  });

  // ---------------------------------------------------------------------------
  // 9. Read-Only Ledger Invariant
  // ---------------------------------------------------------------------------
  it('9. GET /api/v1/audit-events — Audit inspection is strictly read-only (zero records added or modified)', async () => {
    currentActor = adminActor;

    // Record audit table row count before query
    const countBeforeRes = await testDbClient.query<{ count: string }>(
      'SELECT count(*) FROM audit_events;'
    );
    const countBefore = parseInt(countBeforeRes.rows[0].count, 10);

    // Execute audit query
    const res = await request(testApp)
      .get('/api/v1/audit-events')
      .query({
        page: '1',
        limit: '5',
      });

    expect(res.status).toBe(200);
    expect(res.body.data.length).toBeLessThanOrEqual(5);

    // Record audit table row count after query — must be identical
    const countAfterRes = await testDbClient.query<{ count: string }>(
      'SELECT count(*) FROM audit_events;'
    );
    const countAfter = parseInt(countAfterRes.rows[0].count, 10);

    expect(countAfter).toBe(countBefore);
  });

  // ---------------------------------------------------------------------------
  // 10. Fail-Closed Production Authentication
  // ---------------------------------------------------------------------------
  it('10. Production createApp rejects requests on Sub-Gate 3E.4 endpoints with HTTP 401 UNAUTHORIZED', async () => {
    const prodApp = createApp(domainServices);

    // Force-close unauthenticated
    const forceCloseRes = await request(prodApp)
      .post(`/api/v1/findings/${testFindingId}/force-close`)
      .send({
        expectedVersion: 3,
        justification: 'Unauthenticated attempt',
      });
    expect(forceCloseRes.status).toBe(401);
    expect(forceCloseRes.body.error.code).toBe('UNAUTHORIZED');

    // Force-reopen unauthenticated
    const forceReopenRes = await request(prodApp)
      .post(`/api/v1/findings/${testFindingId}/force-reopen`)
      .send({
        expectedVersion: 3,
        justification: 'Unauthenticated attempt',
      });
    expect(forceReopenRes.status).toBe(401);
    expect(forceReopenRes.body.error.code).toBe('UNAUTHORIZED');

    // Audit events unauthenticated
    const auditRes = await request(prodApp).get('/api/v1/audit-events');
    expect(auditRes.status).toBe(401);
    expect(auditRes.body.error.code).toBe('UNAUTHORIZED');
  });
});
