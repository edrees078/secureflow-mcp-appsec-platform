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

describe('PostgreSQL 17.11 Integration: Test Cleanup & Zero-Accumulation Regression', () => {
  let domainServices: DomainServices;
  let testDbClient: TestDatabaseClient;
  let testApp: Express;
  let rawTestUrl: string;

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

  beforeAll(async () => {
    rawTestUrl = validateTestDatabaseUrl(process.env.TEST_DATABASE_URL);
    testDbClient = await createTestDatabaseClient(rawTestUrl);
    domainServices = createDomainServices({
      connectionString: rawTestUrl,
      maxConnections: 5,
      connectionTimeoutMillis: 5000,
      statementTimeoutMillis: 10000,
    });

    testApp = createTestApp({
      services: domainServices,
      actor: () => adminActor,
    });
  });

  afterAll(async () => {
    if (testDbClient) {
      await testDbClient.close();
    }
    if (domainServices) {
      await domainServices.close();
    }
  });

  it('1. Enforces strict test database isolation, loopback host, and URL safety rules', () => {
    // Missing URL fails closed
    expect(() => validateTestDatabaseUrl(undefined)).toThrowError(
      'SAFETY REFUSAL: TEST_DATABASE_URL is required',
    );
    expect(() => validateTestDatabaseUrl('')).toThrowError(
      'SAFETY REFUSAL: TEST_DATABASE_URL is required',
    );

    // Development database target refused
    expect(() =>
      validateTestDatabaseUrl('postgresql://secureflow:pass@127.0.0.1:5433/secureflow_dev'),
    ).toThrowError('SAFETY REFUSAL: TEST_DATABASE_URL must NEVER target development database');

    // Native PG 15 port 5432 refused
    expect(() =>
      validateTestDatabaseUrl('postgresql://secureflow:pass@127.0.0.1:5432/secureflow_test'),
    ).toThrowError('SAFETY REFUSAL: TEST_DATABASE_URL targets port 5432');

    // Wrong DB name refused
    expect(() =>
      validateTestDatabaseUrl('postgresql://secureflow:pass@127.0.0.1:5433/unapproved_db'),
    ).toThrowError('SAFETY REFUSAL: TEST_DATABASE_URL must target "secureflow_test"');

    // Wrong port refused
    expect(() =>
      validateTestDatabaseUrl('postgresql://secureflow:pass@127.0.0.1:9999/secureflow_test'),
    ).toThrowError('SAFETY REFUSAL: TEST_DATABASE_URL must target approved host port 5433');

    // Remote database hostname strictly refused
    expect(() =>
      validateTestDatabaseUrl('postgresql://secureflow:pass@remote.example.com:5433/secureflow_test'),
    ).toThrowError('SAFETY REFUSAL: TEST_DATABASE_URL must target an approved local loopback host');

    // Remote IP address strictly refused
    expect(() =>
      validateTestDatabaseUrl('postgresql://secureflow:pass@192.168.1.50:5433/secureflow_test'),
    ).toThrowError('SAFETY REFUSAL: TEST_DATABASE_URL must target an approved local loopback host');

    // Approved loopback formats pass
    expect(
      validateTestDatabaseUrl('postgresql://secureflow:pass@localhost:5433/secureflow_test'),
    ).toBe('postgresql://secureflow:pass@localhost:5433/secureflow_test');
    expect(
      validateTestDatabaseUrl('postgresql://secureflow:pass@127.0.0.1:5433/secureflow_test'),
    ).toBe('postgresql://secureflow:pass@127.0.0.1:5433/secureflow_test');
    expect(
      validateTestDatabaseUrl('postgresql://secureflow:pass@[::1]:5433/secureflow_test'),
    ).toBe('postgresql://secureflow:pass@[::1]:5433/secureflow_test');

    // Current environment approved connection string passes
    expect(validateTestDatabaseUrl(rawTestUrl)).toBe(rawTestUrl);
  });

  it('2. Standard Cleanup — removes registered synthetic project, members, and audit events without affecting pre-existing data', async () => {
    const initialUsersCountRes = await testDbClient.query<{ count: string }>('SELECT count(*) FROM users;');
    const initialProjectsCountRes = await testDbClient.query<{ count: string }>('SELECT count(*) FROM projects;');
    const initialUsersCount = parseInt(initialUsersCountRes.rows[0].count, 10);
    const initialProjectsCount = parseInt(initialProjectsCountRes.rows[0].count, 10);

    // 1. Create a synthetic project via API
    const createRes = await request(testApp)
      .post('/api/v1/projects')
      .send({
        name: `Cleanup Test Project ${Date.now()}`,
        description: 'Project created to verify teardown cleanup',
      });

    expect(createRes.status).toBe(201);
    const synthProjectId = createRes.body.data.id;
    testDbClient.registerSyntheticProject(synthProjectId);

    // 2. Add member
    const memberRes = await request(testApp)
      .post(`/api/v1/projects/${synthProjectId}/members`)
      .send({
        userId: analystActor.id,
        role: 'ANALYST',
      });
    expect(memberRes.status).toBe(201);

    // 3. Verify project and dependent records exist in database
    const projCheck = await testDbClient.query('SELECT id FROM projects WHERE id = $1;', [synthProjectId]);
    expect(projCheck.rows.length).toBe(1);

    const memberCheck = await testDbClient.query('SELECT id FROM project_members WHERE project_id = $1;', [synthProjectId]);
    expect(memberCheck.rows.length).toBe(1);

    const auditCheck = await testDbClient.query(
      `SELECT id FROM audit_events WHERE resource_id = $1::uuid OR (resource_type = 'ProjectMember' AND after_state->>'projectId' = $1::text);`,
      [synthProjectId],
    );
    expect(auditCheck.rows.length).toBeGreaterThanOrEqual(2);

    // 4. Execute cleanup
    await testDbClient.cleanupProjectHierarchy(synthProjectId);

    // 5. Assert synthetic records are completely removed
    const postProjCheck = await testDbClient.query('SELECT id FROM projects WHERE id = $1;', [synthProjectId]);
    expect(postProjCheck.rows.length).toBe(0);

    const postMemberCheck = await testDbClient.query('SELECT id FROM project_members WHERE project_id = $1;', [synthProjectId]);
    expect(postMemberCheck.rows.length).toBe(0);

    const postAuditCheck = await testDbClient.query(
      `SELECT id FROM audit_events WHERE resource_id = $1::uuid OR (resource_type = 'ProjectMember' AND after_state->>'projectId' = $1::text);`,
      [synthProjectId],
    );
    expect(postAuditCheck.rows.length).toBe(0);

    // 6. Assert pre-existing counts are completely preserved
    const finalUsersCountRes = await testDbClient.query<{ count: string }>('SELECT count(*) FROM users;');
    const finalProjectsCountRes = await testDbClient.query<{ count: string }>('SELECT count(*) FROM projects;');
    expect(parseInt(finalUsersCountRes.rows[0].count, 10)).toBe(initialUsersCount);
    expect(parseInt(finalProjectsCountRes.rows[0].count, 10)).toBe(initialProjectsCount);
  });

  it('3. Scenario A — Test Failure: confirms cleanup executes and purges synthetic project even upon mid-suite failure', async () => {
    const scopedClient = await createTestDatabaseClient(rawTestUrl);
    const scopedServices = createDomainServices({ connectionString: rawTestUrl });
    const scopedApp = createTestApp({ services: scopedServices, actor: () => adminActor });

    let failureSynthProjectId: string | undefined;
    let caughtSimulatedError: unknown = null;

    try {
      const res = await request(scopedApp)
        .post('/api/v1/projects')
        .send({
          name: `Scenario A Failure Project ${Date.now()}`,
          description: 'Simulated mid-suite test failure project',
        });
      expect(res.status).toBe(201);
      failureSynthProjectId = res.body.data.id;
      scopedClient.registerSyntheticProject(failureSynthProjectId);

      // Deliberate test assertion failure simulation
      throw new Error('SIMULATED_TEST_EXECUTION_FAILURE');
    } catch (err: unknown) {
      caughtSimulatedError = err;
    } finally {
      if (failureSynthProjectId) {
        await scopedClient.cleanupProjectHierarchy(failureSynthProjectId);
      }
      await scopedClient.close();
      await scopedServices.close();
    }

    expect((caughtSimulatedError as Error).message).toBe('SIMULATED_TEST_EXECUTION_FAILURE');

    // Confirm synthetic project was deleted despite the failure
    const verifyCheck = await testDbClient.query('SELECT id FROM projects WHERE id = $1;', [failureSynthProjectId]);
    expect(verifyCheck.rows.length).toBe(0);
  });

  it('4. Scenario B — Cleanup Failure: confirms transactional rollback when cleanup fails mid-transaction', async () => {
    const scopedClient = await createTestDatabaseClient(rawTestUrl);
    const scopedServices = createDomainServices({ connectionString: rawTestUrl });
    const scopedApp = createTestApp({ services: scopedServices, actor: () => adminActor });

    let synthProjectId: string | undefined;

    try {
      // 1. Create project with member and audit records
      const res = await request(scopedApp)
        .post('/api/v1/projects')
        .send({
          name: `Scenario B Rollback Project ${Date.now()}`,
          description: 'Project to test cleanup transactional rollback',
        });
      expect(res.status).toBe(201);
      synthProjectId = res.body.data.id;
      scopedClient.registerSyntheticProject(synthProjectId);

      const memberRes = await request(scopedApp)
        .post(`/api/v1/projects/${synthProjectId}/members`)
        .send({
          userId: analystActor.id,
          role: 'ANALYST',
        });
      expect(memberRes.status).toBe(201);

      // Verify records exist in database
      const initialMemberCheck = await scopedClient.query(
        'SELECT id FROM project_members WHERE project_id = $1;',
        [synthProjectId],
      );
      expect(initialMemberCheck.rows.length).toBe(1);

      const initialAuditCheck = await scopedClient.query(
        `SELECT id FROM audit_events WHERE resource_id = $1::uuid OR (resource_type = 'ProjectMember' AND after_state->>'projectId' = $1::text);`,
        [synthProjectId],
      );
      expect(initialAuditCheck.rows.length).toBeGreaterThanOrEqual(2);

      // 2. Trigger controlled cleanup failure after step 4 (audit events deletion)
      // Transaction must roll back, ensuring no partial deletion is committed!
      await expect(
        scopedClient.cleanupProjectHierarchy(synthProjectId, { injectFailureAfterStep: 4 }),
      ).rejects.toThrow('Project cleanup transaction failed: INJECTED_CLEANUP_FAILURE_AFTER_STEP_4');

      // 3. Confirm full rollback: audit events, members, and project must STILL exist
      const postRollbackAuditCheck = await scopedClient.query(
        `SELECT id FROM audit_events WHERE resource_id = $1::uuid OR (resource_type = 'ProjectMember' AND after_state->>'projectId' = $1::text);`,
        [synthProjectId],
      );
      expect(postRollbackAuditCheck.rows.length).toBe(initialAuditCheck.rows.length);

      const postRollbackMemberCheck = await scopedClient.query(
        'SELECT id FROM project_members WHERE project_id = $1;',
        [synthProjectId],
      );
      expect(postRollbackMemberCheck.rows.length).toBe(1);

      const postRollbackProjCheck = await scopedClient.query(
        'SELECT id FROM projects WHERE id = $1;',
        [synthProjectId],
      );
      expect(postRollbackProjCheck.rows.length).toBe(1);

      // 4. Perform subsequent successful scoped cleanup to leave database clean
      await scopedClient.cleanupProjectHierarchy(synthProjectId);

      const finalCheck = await scopedClient.query(
        'SELECT id FROM projects WHERE id = $1;',
        [synthProjectId],
      );
      expect(finalCheck.rows.length).toBe(0);
    } finally {
      await scopedClient.close();
      await scopedServices.close();
    }
  });

  it('5. Enforces synthetic project ownership boundary and preserves pre-existing fixtures', async () => {
    // A. Rejects cleanup of an unregistered project ID
    const unregisteredId = 'ffffffff-ffff-ffff-ffff-ffffffffffff';
    await expect(testDbClient.cleanupProjectHierarchy(unregisteredId)).rejects.toThrow(
      "SAFETY REFUSAL: Project 'ffffffff-ffff-ffff-ffff-ffffffffffff' is not registered as a synthetic test project owned by this test client.",
    );

    // B. Preserves pre-existing fixture projects — cleanup is strictly refused
    const fixtureProjectRes = await testDbClient.query<{ id: string; name: string }>(
      'SELECT id, name FROM projects ORDER BY created_at ASC LIMIT 1;',
    );
    expect(fixtureProjectRes.rows.length).toBe(1);
    const fixtureProjectId = fixtureProjectRes.rows[0].id;

    // Attempting to clean up an existing fixture project without registration fails closed
    await expect(testDbClient.cleanupProjectHierarchy(fixtureProjectId)).rejects.toThrow(
      `SAFETY REFUSAL: Project '${fixtureProjectId}' is not registered as a synthetic test project owned by this test client.`,
    );

    // Verify fixture project still exists in PostgreSQL
    const postCheck = await testDbClient.query('SELECT id FROM projects WHERE id = $1;', [fixtureProjectId]);
    expect(postCheck.rows.length).toBe(1);

    // C. Registered non-existent ID executes safely and is deregistered on commit
    const nonExistentRegisteredId = '00000000-0000-0000-0000-000000000999';
    testDbClient.registerSyntheticProject(nonExistentRegisteredId);
    await expect(testDbClient.cleanupProjectHierarchy(nonExistentRegisteredId)).resolves.not.toThrow();

    // Calling cleanup a second time rejects because it is no longer registered
    await expect(testDbClient.cleanupProjectHierarchy(nonExistentRegisteredId)).rejects.toThrow(
      `SAFETY REFUSAL: Project '${nonExistentRegisteredId}' is not registered`,
    );
  });

  it('6. Repeated execution verification — multiple consecutive runs result in zero net row accumulation', async () => {
    const baselineRes = await testDbClient.query<{ count: string }>('SELECT count(*) FROM projects;');
    const baselineCount = parseInt(baselineRes.rows[0].count, 10);

    for (let i = 0; i < 3; i++) {
      const res = await request(testApp)
        .post('/api/v1/projects')
        .send({
          name: `Accumulation Check ${i} ${Date.now()}`,
        });
      expect(res.status).toBe(201);
      const projId = res.body.data.id;
      testDbClient.registerSyntheticProject(projId);

      // Clean up immediately within transaction
      await testDbClient.cleanupProjectHierarchy(projId);
    }

    const finalRes = await testDbClient.query<{ count: string }>('SELECT count(*) FROM projects;');
    const finalCount = parseInt(finalRes.rows[0].count, 10);

    expect(finalCount).toBe(baselineCount);
  });
});
