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

describe('PostgreSQL 17.11 Integration: Finding Lifecycle & Remediation Task REST API (/api/v1/findings & /api/v1/tasks)', () => {
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

  const dev2Actor = new ActorContext({
    id: '3cf719ca-162d-4cbd-af7c-4a4d0366ce49',
    globalRole: 'DEVELOPER',
    isActive: true,
  });

  const foreignAnalystActor = new ActorContext({
    id: '23e46735-3ef3-4c83-ba94-0cb5149f08b6',
    globalRole: 'ANALYST',
    isActive: true,
  });

  let primaryProjectId: string;
  let foreignProjectId: string;
  let testFindingId: string;
  let secondFindingId: string;
  let activeTaskId: string;
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

    // Setup Primary Synthetic Project
    const proj1 = await domainServices.projectService.createProject(adminActor, {
      name: `Primary Finding Test Project ${Date.now()}`,
      description: 'Project for testing finding and task REST endpoints',
    });
    primaryProjectId = proj1.id;
    createdProjectIds.push(primaryProjectId);
    testDbClient.registerSyntheticProject(primaryProjectId);

    // Setup Foreign Synthetic Project (for cross-project isolation tests)
    const proj2 = await domainServices.projectService.createProject(adminActor, {
      name: `Foreign Finding Test Project ${Date.now()}`,
      description: 'Project for testing cross-project existence hiding',
    });
    foreignProjectId = proj2.id;
    createdProjectIds.push(foreignProjectId);
    testDbClient.registerSyntheticProject(foreignProjectId);

    // Add members to Primary Project: Analyst, Dev1, Dev2
    await domainServices.projectService.addMember(adminActor, primaryProjectId, {
      userId: analystActor.id,
      role: 'ANALYST',
    });
    await domainServices.projectService.addMember(adminActor, primaryProjectId, {
      userId: dev1Actor.id,
      role: 'DEVELOPER',
    });
    await domainServices.projectService.addMember(adminActor, primaryProjectId, {
      userId: dev2Actor.id,
      role: 'DEVELOPER',
    });

    // Add foreign analyst member to Foreign Project
    await domainServices.projectService.addMember(adminActor, foreignProjectId, {
      userId: foreignAnalystActor.id,
      role: 'ANALYST',
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
  // 1. Finding Creation Through HTTP
  // ---------------------------------------------------------------------------
  it('1. POST /api/v1/findings — Analyst creates finding in OPEN status with version 1', async () => {
    currentActor = analystActor;

    const res = await request(testApp)
      .post('/api/v1/findings')
      .send({
        projectId: primaryProjectId,
        title: 'Remote Code Execution in YAML Parser',
        description: 'Unsafe deserialization in yaml.load allows arbitrary command execution.',
        severity: 'CRITICAL',
        category: 'INJECTION',
        cvssScore: 9.8,
        dueDate: '2026-12-31',
      });

    expect(res.status).toBe(201);
    expect(res.body.data).toBeDefined();
    expect(res.body.data.id).toMatch(/^[0-9a-f-]{36}$/);
    expect(res.body.data.status).toBe('OPEN');
    expect(res.body.data.version).toBe(1);
    expect(res.body.data.cvssScore).toBe(9.8);
    expect(res.body.data.isDeleted).toBe(false);

    testFindingId = res.body.data.id;

    // Verify in PostgreSQL
    const dbRes = await testDbClient.query(
      'SELECT status, version, cvss_score FROM findings WHERE id = $1;',
      [testFindingId],
    );
    expect(dbRes.rows[0].status).toBe('OPEN');
    expect(dbRes.rows[0].version).toBe(1);
    expect(Number(dbRes.rows[0].cvss_score)).toBe(9.8);
  });

  // ---------------------------------------------------------------------------
  // 2. Finding Listing and Filtering Through HTTP
  // ---------------------------------------------------------------------------
  it('2. GET /api/v1/findings — Analyst lists findings scoped to authorized project', async () => {
    currentActor = analystActor;

    const res = await request(testApp)
      .get('/api/v1/findings')
      .query({
        projectId: primaryProjectId,
        status: 'OPEN',
        severity: 'CRITICAL',
        page: '1',
        limit: '10',
      });

    expect(res.status).toBe(200);
    expect(res.body.data).toBeInstanceOf(Array);
    expect(res.body.data.length).toBeGreaterThanOrEqual(1);
    const found = res.body.data.find((f: { id: string }) => f.id === testFindingId);
    expect(found).toBeDefined();
    expect(res.body.pagination).toBeDefined();
    expect(res.body.pagination.page).toBe(1);
    expect(res.body.pagination.limit).toBe(10);
  });

  // ---------------------------------------------------------------------------
  // 3. Triage Through HTTP
  // ---------------------------------------------------------------------------
  it('3. POST /api/v1/findings/:id/triage — Analyst triages finding (OPEN -> TRIAGED, v1 -> v2)', async () => {
    currentActor = analystActor;

    const res = await request(testApp)
      .post(`/api/v1/findings/${testFindingId}/triage`)
      .send({
        expectedVersion: 1,
        severity: 'CRITICAL',
      });

    expect(res.status).toBe(200);
    expect(res.body.data.status).toBe('TRIAGED');
    expect(res.body.data.version).toBe(2);

    // Verify in PostgreSQL
    const dbRes = await testDbClient.query(
      'SELECT status, version FROM findings WHERE id = $1;',
      [testFindingId],
    );
    expect(dbRes.rows[0].status).toBe('TRIAGED');
    expect(dbRes.rows[0].version).toBe(2);
  });

  // ---------------------------------------------------------------------------
  // 4. Assignment Through HTTP
  // ---------------------------------------------------------------------------
  it('4. POST /api/v1/findings/:id/assign — Analyst assigns finding to Dev1 (TRIAGED -> IN_PROGRESS, v2 -> v3)', async () => {
    currentActor = analystActor;

    const res = await request(testApp)
      .post(`/api/v1/findings/${testFindingId}/assign`)
      .send({
        expectedVersion: 2,
        assignedToId: dev1Actor.id,
        taskDescription: 'Replace yaml.load with yaml.safe_load and add unit tests',
        dueDate: '2026-12-15',
      });

    expect(res.status).toBe(200);
    expect(res.body.data.status).toBe('IN_PROGRESS');
    expect(res.body.data.version).toBe(3);
    expect(res.body.data.assignedToId).toBe(dev1Actor.id);

    // Verify task created in PostgreSQL
    const taskRes = await testDbClient.query(
      'SELECT id, status, assigned_to_id, notes FROM remediation_tasks WHERE finding_id = $1;',
      [testFindingId],
    );
    expect(taskRes.rows.length).toBe(1);
    expect(taskRes.rows[0].status).toBe('PENDING');
    expect(taskRes.rows[0].assigned_to_id).toBe(dev1Actor.id);
    activeTaskId = taskRes.rows[0].id;
  });

  // ---------------------------------------------------------------------------
  // 5. Task Note Authorization Through HTTP
  // ---------------------------------------------------------------------------
  it('5. PATCH /api/v1/tasks/:id/notes — Assigned Dev1 updates notes; Unassigned Dev2 is rejected (403)', async () => {
    // A. Unassigned Dev2 rejected with 403
    currentActor = dev2Actor;
    const dev2Res = await request(testApp)
      .patch(`/api/v1/tasks/${activeTaskId}/notes`)
      .send({ notes: 'Dev2 notes should be rejected' });
    expect(dev2Res.status).toBe(403);
    expect(dev2Res.body.error.code).toBe('FORBIDDEN');

    // B. Assigned Dev1 successfully updates notes with 200
    currentActor = dev1Actor;
    const dev1Res = await request(testApp)
      .patch(`/api/v1/tasks/${activeTaskId}/notes`)
      .send({ notes: 'Dev1: Started refactoring the YAML parser configuration.' });
    expect(dev1Res.status).toBe(200);
    expect(dev1Res.body.data.notes).toBe('Dev1: Started refactoring the YAML parser configuration.');

    // C. GET /api/v1/tasks/:id returns task detail
    const getRes = await request(testApp).get(`/api/v1/tasks/${activeTaskId}`);
    expect(getRes.status).toBe(200);
    expect(getRes.body.data.id).toBe(activeTaskId);
    expect(getRes.body.data.notes).toBe('Dev1: Started refactoring the YAML parser configuration.');
  });

  // ---------------------------------------------------------------------------
  // 6. Remediation Submission Through HTTP
  // ---------------------------------------------------------------------------
  it('6. POST /api/v1/findings/:id/submit-remediation — Assigned Dev1 submits remediation (IN_PROGRESS -> READY_FOR_REVIEW, v3 -> v4)', async () => {
    currentActor = dev1Actor;

    const res = await request(testApp)
      .post(`/api/v1/findings/${testFindingId}/submit-remediation`)
      .send({
        expectedVersion: 3,
        notes: 'Replaced with safe_load. Tested with exploit payloads in test suite.',
      });

    expect(res.status).toBe(200);
    expect(res.body.data.status).toBe('READY_FOR_REVIEW');
    expect(res.body.data.version).toBe(4);

    // Verify task is SUBMITTED in PostgreSQL
    const taskRes = await testDbClient.query(
      'SELECT status FROM remediation_tasks WHERE id = $1;',
      [activeTaskId],
    );
    expect(taskRes.rows[0].status).toBe('SUBMITTED');
  });

  // ---------------------------------------------------------------------------
  // 7. Rejection Through HTTP (Cycle 1)
  // ---------------------------------------------------------------------------
  it('7. POST /api/v1/findings/:id/verify (outcome: REOPENED) — Analyst rejects remediation (READY_FOR_REVIEW -> REOPENED, v4 -> v5)', async () => {
    // Dev1 cannot verify their own work (Separation of duties)
    currentActor = dev1Actor;
    const sodRes = await request(testApp)
      .post(`/api/v1/findings/${testFindingId}/verify`)
      .send({
        expectedVersion: 4,
        outcome: 'VERIFIED',
      });
    expect(sodRes.status).toBe(403);
    expect(sodRes.body.error.code).toBe('FORBIDDEN');

    // Analyst rejects with outcome REOPENED
    currentActor = analystActor;
    const res = await request(testApp)
      .post(`/api/v1/findings/${testFindingId}/verify`)
      .send({
        expectedVersion: 4,
        outcome: 'REOPENED',
        notes: 'Exploit payload test 3 still triggers unexpected behavior.',
      });

    expect(res.status).toBe(200);
    expect(res.body.data.status).toBe('REOPENED');
    expect(res.body.data.version).toBe(5);

    // Verify historical task status in PostgreSQL is REJECTED
    const taskRes = await testDbClient.query(
      'SELECT status FROM remediation_tasks WHERE id = $1;',
      [activeTaskId],
    );
    expect(taskRes.rows[0].status).toBe('REJECTED');
  });

  // ---------------------------------------------------------------------------
  // 8. Reassignment Through HTTP (Cycle 2)
  // ---------------------------------------------------------------------------
  it('8. POST /api/v1/findings/:id/assign — Analyst reassigns finding to Dev2 (REOPENED -> IN_PROGRESS, v5 -> v6)', async () => {
    currentActor = analystActor;

    const res = await request(testApp)
      .post(`/api/v1/findings/${testFindingId}/assign`)
      .send({
        expectedVersion: 5,
        assignedToId: dev2Actor.id,
        taskDescription: 'Cycle 2: Resolve test 3 boundary case with explicit schema validator',
      });

    expect(res.status).toBe(200);
    expect(res.body.data.status).toBe('IN_PROGRESS');
    expect(res.body.data.version).toBe(6);
    expect(res.body.data.assignedToId).toBe(dev2Actor.id);

    // Verify Cycle 2 task created in PostgreSQL while Cycle 1 task remains REJECTED
    const tasksRes = await testDbClient.query(
      'SELECT id, status, assigned_to_id FROM remediation_tasks WHERE finding_id = $1 ORDER BY created_at ASC;',
      [testFindingId],
    );
    expect(tasksRes.rows.length).toBe(2);
    expect(tasksRes.rows[0].status).toBe('REJECTED');
    expect(tasksRes.rows[1].status).toBe('PENDING');
    expect(tasksRes.rows[1].assigned_to_id).toBe(dev2Actor.id);
  });

  // ---------------------------------------------------------------------------
  // 9. Successful Verification Through HTTP
  // ---------------------------------------------------------------------------
  it('9. POST /api/v1/findings/:id/verify (outcome: VERIFIED) — Dev2 submits and Analyst verifies (v6 -> v7 -> v8)', async () => {
    // Dev2 submits remediation
    currentActor = dev2Actor;
    const submitRes = await request(testApp)
      .post(`/api/v1/findings/${testFindingId}/submit-remediation`)
      .send({
        expectedVersion: 6,
        notes: 'Cycle 2 complete. Added strict schema check preventing arbitrary object reconstruction.',
      });
    expect(submitRes.status).toBe(200);
    expect(submitRes.body.data.status).toBe('READY_FOR_REVIEW');
    expect(submitRes.body.data.version).toBe(7);

    // Analyst verifies remediation
    currentActor = analystActor;
    const verifyRes = await request(testApp)
      .post(`/api/v1/findings/${testFindingId}/verify`)
      .send({
        expectedVersion: 7,
        outcome: 'VERIFIED',
        notes: 'All test vectors confirmed fixed.',
      });

    expect(verifyRes.status).toBe(200);
    expect(verifyRes.body.data.status).toBe('VERIFIED');
    expect(verifyRes.body.data.version).toBe(8);

    // Verify Cycle 2 task is VERIFIED in PostgreSQL
    const task2Res = await testDbClient.query(
      'SELECT status FROM remediation_tasks WHERE finding_id = $1 ORDER BY created_at DESC LIMIT 1;',
      [testFindingId],
    );
    expect(task2Res.rows[0].status).toBe('VERIFIED');
  });

  // ---------------------------------------------------------------------------
  // 10. Ordinary Closure Through HTTP
  // ---------------------------------------------------------------------------
  it('10. POST /api/v1/findings/:id/close — Analyst performs ordinary closure (VERIFIED -> CLOSED, v8 -> v9)', async () => {
    currentActor = analystActor;

    const res = await request(testApp)
      .post(`/api/v1/findings/${testFindingId}/close`)
      .send({
        expectedVersion: 8,
        notes: 'Remediation signed off and deployed to production.',
      });

    expect(res.status).toBe(200);
    expect(res.body.data.status).toBe('CLOSED');
    expect(res.body.data.version).toBe(9);

    // Verify finding in PostgreSQL
    const findingRes = await testDbClient.query(
      'SELECT status, version FROM findings WHERE id = $1;',
      [testFindingId],
    );
    expect(findingRes.rows[0].status).toBe('CLOSED');
    expect(findingRes.rows[0].version).toBe(9);
  });

  // ---------------------------------------------------------------------------
  // 11. OCC Conflict Through HTTP
  // ---------------------------------------------------------------------------
  it('11. PATCH /api/v1/findings/:id — Stale expectedVersion returns HTTP 409 CONCURRENCY_CONFLICT', async () => {
    currentActor = analystActor;

    const res = await request(testApp)
      .patch(`/api/v1/findings/${testFindingId}`)
      .send({
        expectedVersion: 1, // Current version is 9
        title: 'Conflict Title Update',
      });

    expect(res.status).toBe(409);
    expect(res.body.error.code).toBe('CONCURRENCY_CONFLICT');

    // Verify record in PostgreSQL was NOT modified
    const dbRes = await testDbClient.query(
      'SELECT version, title FROM findings WHERE id = $1;',
      [testFindingId],
    );
    expect(dbRes.rows[0].version).toBe(9);
    expect(dbRes.rows[0].title).toBe('Remote Code Execution in YAML Parser');
  });

  // ---------------------------------------------------------------------------
  // 12. Cross-Project Unauthorized Access & Soft-Deleted Restrictions
  // ---------------------------------------------------------------------------
  it('12. Cross-project unauthorized access and soft-deleted finding restrictions enforce existence hiding (404)', async () => {
    currentActor = analystActor;

    // A. Create a finding in foreign project (where primary analyst is not a member)
    const foreignFinding = await domainServices.findingService.createFinding(
      foreignAnalystActor,
      {
        projectId: foreignProjectId,
        title: 'Foreign Project Finding',
        description: 'Finding in project where test analyst has no membership',
        severity: 'LOW',
        category: 'CONFIG_EXPOSURE',
      },
    );

    // Analyst attempts to access foreign finding through HTTP -> 404 existence hiding
    const foreignRes = await request(testApp).get(`/api/v1/findings/${foreignFinding.id}`);
    expect(foreignRes.status).toBe(404);
    expect(foreignRes.body.error.code).toBe('NOT_FOUND');

    // B. Create a second finding in primary project for soft-deletion test
    const createRes = await request(testApp)
      .post('/api/v1/findings')
      .send({
        projectId: primaryProjectId,
        title: 'Finding To Be Soft Deleted',
        description: 'Verifies soft-deletion lifecycle and access restrictions',
        severity: 'MEDIUM',
        category: 'CRYPTO',
      });
    expect(createRes.status).toBe(201);
    secondFindingId = createRes.body.data.id;

    // Soft-delete finding via DELETE /api/v1/findings/:id with body { expectedVersion: 1 }
    const deleteRes = await request(testApp)
      .delete(`/api/v1/findings/${secondFindingId}`)
      .send({ expectedVersion: 1 });

    expect(deleteRes.status).toBe(200);
    expect(deleteRes.body.data.isDeleted).toBe(true);
    expect(deleteRes.body.data.version).toBe(2);

    // Verify record in PostgreSQL has is_deleted = true (not physically removed)
    const dbSoftRes = await testDbClient.query(
      'SELECT is_deleted, version FROM findings WHERE id = $1;',
      [secondFindingId],
    );
    expect(dbSoftRes.rows[0].is_deleted).toBe(true);
    expect(dbSoftRes.rows[0].version).toBe(2);

    // Subsequent GET as Analyst returns HTTP 404 (existence hiding)
    const getDeletedRes = await request(testApp).get(`/api/v1/findings/${secondFindingId}`);
    expect(getDeletedRes.status).toBe(404);
    expect(getDeletedRes.body.error.code).toBe('NOT_FOUND');

    // Subsequent PATCH as Analyst returns HTTP 404 (existence hiding)
    const patchDeletedRes = await request(testApp)
      .patch(`/api/v1/findings/${secondFindingId}`)
      .send({ expectedVersion: 2, title: 'Attempted Update on Deleted' });
    expect(patchDeletedRes.status).toBe(404);
    expect(patchDeletedRes.body.error.code).toBe('NOT_FOUND');
  });
});
