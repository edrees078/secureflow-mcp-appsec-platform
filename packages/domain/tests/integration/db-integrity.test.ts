import path from 'node:path';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';
import pg from 'pg';

const { Client } = pg;

// Monorepo environment variable loading
const __dirname = path.dirname(fileURLToPath(import.meta.url));
dotenv.config({ path: path.resolve(__dirname, '../../../../.env') });
dotenv.config({ path: path.resolve(__dirname, '../../../.env') });

export interface IntegrityTestResult {
  testName: string;
  passed: boolean;
  details?: string;
  error?: string;
}

export async function runDatabaseIntegrityTests(): Promise<{
  allPassed: boolean;
  targetDatabase: string;
  hostPort: string;
  pgVersion: string;
  results: IntegrityTestResult[];
}> {
  const targetPort = process.env['POSTGRES_PORT'] || '5433';
  const rawUrl =
    process.env['TEST_DATABASE_URL'] ||
    `postgresql://${process.env['POSTGRES_USER'] || 'secureflow'}:${process.env['POSTGRES_PASSWORD'] || 'secureflow_dev_password_change_me'}@${process.env['POSTGRES_HOST'] || '127.0.0.1'}:${targetPort}/secureflow_test?schema=public`;

  const parsedUrl = new URL(rawUrl);
  const resolvedDbName = parsedUrl.pathname.replace(/^\//, '');
  const resolvedPort = parsedUrl.port || targetPort;

  // SAFETY ASSERTION 1: Strictly refuse to run against secureflow_dev, postgres, or any non-test DB
  if (resolvedDbName !== 'secureflow_test') {
    throw new Error(
      `SAFETY REFUSAL: Target database is '${resolvedDbName}'. Database integrity tests MUST strictly target 'secureflow_test'. Aborting.`,
    );
  }

  // SAFETY ASSERTION 2: Strictly refuse if port is not 5433 (preventing any native PG 15 connection)
  if (resolvedPort !== '5433') {
    throw new Error(
      `SAFETY REFUSAL: Target port is '${resolvedPort}'. Expected port 5433 for SecureFlow Docker PostgreSQL 17. Aborting.`,
    );
  }

  const client = new Client({
    connectionString: rawUrl,
    connectionTimeoutMillis: 5000,
  });

  await client.connect();

  // SAFETY ASSERTION 3: Verify PostgreSQL 17 at engine runtime
  const versionRes = await client.query<{ db_name: string; version: string }>(
    'SELECT current_database() AS db_name, version() AS version;',
  );
  const versionStr = versionRes.rows[0]?.version ?? '';
  const currentDb = versionRes.rows[0]?.db_name ?? '';

  if (currentDb !== 'secureflow_test') {
    await client.end();
    throw new Error(`SAFETY REFUSAL: Connected engine reports database '${currentDb}', expected 'secureflow_test'.`);
  }

  if (!versionStr.includes('PostgreSQL 17')) {
    await client.end();
    throw new Error(`SAFETY REFUSAL: Connected engine is not PostgreSQL 17 (${versionStr}).`);
  }

  const results: IntegrityTestResult[] = [];

  // Deterministic UUIDs for synthetic test data
  const testUserId = '00000000-0000-0000-0000-000000000001';
  const testUser2Id = '00000000-0000-0000-0000-000000000002';
  const testProjectId = '00000000-0000-0000-0000-000000000010';
  const testFindingId = '00000000-0000-0000-0000-000000000100';
  const testTask1Id = '00000000-0000-0000-0000-000000001001';
  const testTask2Id = '00000000-0000-0000-0000-000000001002';
  const testTask3Id = '00000000-0000-0000-0000-000000001003';
  const testTask4Id = '00000000-0000-0000-0000-000000001004';

  try {
    // Clean up any residual synthetic data before starting
    await client.query('DELETE FROM remediation_tasks WHERE finding_id = $1;', [testFindingId]);
    await client.query('DELETE FROM finding_events WHERE finding_id = $1;', [testFindingId]);
    await client.query('DELETE FROM audit_events WHERE actor_id IN ($1, $2);', [testUserId, testUser2Id]);
    await client.query('DELETE FROM findings WHERE id = $1;', [testFindingId]);
    await client.query('DELETE FROM project_members WHERE project_id = $1;', [testProjectId]);
    await client.query('DELETE FROM projects WHERE id = $1;', [testProjectId]);
    await client.query('DELETE FROM users WHERE id IN ($1, $2);', [testUserId, testUser2Id]);

    // Seed baseline synthetic user and project
    await client.query(
      `INSERT INTO users (id, sub, email, display_name, global_role, updated_at)
       VALUES ($1, 'sub_test_1', 'analyst@test.local', 'Test Analyst', 'ANALYST', NOW());`,
      [testUserId],
    );

    await client.query(
      `INSERT INTO users (id, sub, email, display_name, global_role, updated_at)
       VALUES ($1, 'sub_test_2', 'dev@test.local', 'Test Developer', 'DEVELOPER', NOW());`,
      [testUser2Id],
    );

    await client.query(
      `INSERT INTO projects (id, name, slug, created_by_id, updated_at)
       VALUES ($1, 'Test Project', 'test-project', $2, NOW());`,
      [testProjectId, testUserId],
    );

    // ------------------------------------------------------------------------
    // TEST 7: Finding.version counter initialization defaults to 1
    // ------------------------------------------------------------------------
    try {
      const res = await client.query<{ version: number }>(
        `INSERT INTO findings (id, project_id, title, description, severity, category, created_by_id, updated_at)
         VALUES ($1, $2, 'Test Finding', 'Description', 'HIGH', 'INJECTION', $3, NOW())
         RETURNING version;`,
        [testFindingId, testProjectId, testUserId],
      );
      if (res.rows[0]?.version === 1) {
        results.push({
          testName: 'Finding.version counter initialization',
          passed: true,
          details: 'Finding version initialized to 1 by default.',
        });
      } else {
        results.push({
          testName: 'Finding.version counter initialization',
          passed: false,
          error: `Expected default version 1, got ${res.rows[0]?.version}`,
        });
      }
    } catch (err: unknown) {
      results.push({
        testName: 'Finding.version counter initialization',
        passed: false,
        error: String(err),
      });
    }

    // ------------------------------------------------------------------------
    // TEST 1: Duplicate active remediation task rejection (Partial Unique Index)
    // ------------------------------------------------------------------------
    try {
      // First active task (PENDING)
      await client.query(
        `INSERT INTO remediation_tasks (id, finding_id, assigned_to_id, assigned_by_id, description, status, updated_at)
         VALUES ($1, $2, $3, $4, 'First Active Task', 'PENDING', NOW());`,
        [testTask1Id, testFindingId, testUser2Id, testUserId],
      );

      // Attempt second active task (IN_PROGRESS) for the same finding
      let duplicateRejected = false;
      try {
        await client.query(
          `INSERT INTO remediation_tasks (id, finding_id, assigned_to_id, assigned_by_id, description, status, updated_at)
           VALUES ($1, $2, $3, $4, 'Second Active Task', 'IN_PROGRESS', NOW());`,
          [testTask2Id, testFindingId, testUser2Id, testUserId],
        );
      } catch (err: unknown) {
        const pgErr = err as { code?: string; constraint?: string };
        if (pgErr.code === '23505' && pgErr.constraint === 'one_active_remediation_task_per_finding') {
          duplicateRejected = true;
        } else {
          throw err;
        }
      }

      if (duplicateRejected) {
        results.push({
          testName: 'Duplicate active remediation-task rejection',
          passed: true,
          details: 'Partial unique index correctly rejected second active task with code 23505.',
        });
      } else {
        results.push({
          testName: 'Duplicate active remediation-task rejection',
          passed: false,
          error: 'Second active remediation task was unexpectedly accepted.',
        });
      }
    } catch (err: unknown) {
      results.push({
        testName: 'Duplicate active remediation-task rejection',
        passed: false,
        error: String(err),
      });
    }

    // ------------------------------------------------------------------------
    // TEST 2: Replacement task creation after terminal task status
    // ------------------------------------------------------------------------
    try {
      // Transition Task 1 to VERIFIED (terminal status)
      await client.query(`UPDATE remediation_tasks SET status = 'VERIFIED', updated_at = NOW() WHERE id = $1;`, [testTask1Id]);

      // Now inserting a replacement active task must SUCCEED
      await client.query(
        `INSERT INTO remediation_tasks (id, finding_id, assigned_to_id, assigned_by_id, description, status, updated_at)
         VALUES ($1, $2, $3, $4, 'Replacement Task after Verified', 'PENDING', NOW());`,
        [testTask3Id, testFindingId, testUser2Id, testUserId],
      );

      // Transition Task 3 to REJECTED (terminal status)
      await client.query(`UPDATE remediation_tasks SET status = 'REJECTED', updated_at = NOW() WHERE id = $1;`, [testTask3Id]);

      // Inserting another replacement task must also SUCCEED
      await client.query(
        `INSERT INTO remediation_tasks (id, finding_id, assigned_to_id, assigned_by_id, description, status, updated_at)
         VALUES ($1, $2, $3, $4, 'Replacement Task after Rejected', 'PENDING', NOW());`,
        [testTask4Id, testFindingId, testUser2Id, testUserId],
      );

      results.push({
        testName: 'Replacement task creation after terminal statuses',
        passed: true,
        details: 'Tasks created successfully after parent finding tasks entered VERIFIED and REJECTED states.',
      });
    } catch (err: unknown) {
      results.push({
        testName: 'Replacement task creation after terminal statuses',
        passed: false,
        error: String(err),
      });
    }

    // ------------------------------------------------------------------------
    // TEST 3: Rejection of CVSS scores outside 0.0–10.0 (CHECK constraint)
    // ------------------------------------------------------------------------
    try {
      let rejectedAbove = false;
      let rejectedBelow = false;

      try {
        await client.query(
          `INSERT INTO findings (project_id, title, description, severity, category, cvss_score, created_by_id, updated_at)
           VALUES ($1, 'Invalid CVSS High', 'Desc', 'CRITICAL', 'INJECTION', 10.1, $2, NOW());`,
          [testProjectId, testUserId],
        );
      } catch (err: unknown) {
        const pgErr = err as { code?: string; constraint?: string };
        if (pgErr.code === '23514' && pgErr.constraint === 'check_cvss_score_range') {
          rejectedAbove = true;
        }
      }

      try {
        await client.query(
          `INSERT INTO findings (project_id, title, description, severity, category, cvss_score, created_by_id, updated_at)
           VALUES ($1, 'Invalid CVSS Low', 'Desc', 'LOW', 'INJECTION', -0.1, $2, NOW());`,
          [testProjectId, testUserId],
        );
      } catch (err: unknown) {
        const pgErr = err as { code?: string; constraint?: string };
        if (pgErr.code === '23514' && pgErr.constraint === 'check_cvss_score_range') {
          rejectedBelow = true;
        }
      }

      if (rejectedAbove && rejectedBelow) {
        results.push({
          testName: 'Rejection of CVSS scores outside 0.0-10.0',
          passed: true,
          details: 'CHECK constraint check_cvss_score_range rejected 10.1 and -0.1 with code 23514.',
        });
      } else {
        results.push({
          testName: 'Rejection of CVSS scores outside 0.0-10.0',
          passed: false,
          error: `Rejected above: ${rejectedAbove}, Rejected below: ${rejectedBelow}`,
        });
      }
    } catch (err: unknown) {
      results.push({
        testName: 'Rejection of CVSS scores outside 0.0-10.0',
        passed: false,
        error: String(err),
      });
    }

    // ------------------------------------------------------------------------
    // TEST 4: Acceptance of valid and nullable CVSS values
    // ------------------------------------------------------------------------
    try {
      const validValues = [0.0, 5.5, 10.0, null];
      for (const val of validValues) {
        await client.query(
          `INSERT INTO findings (project_id, title, description, severity, category, cvss_score, created_by_id, updated_at)
           VALUES ($1, $2, 'Desc', 'MEDIUM', 'INJECTION', $3, $4, NOW());`,
          [testProjectId, `Finding CVSS ${val}`, val, testUserId],
        );
      }
      results.push({
        testName: 'Acceptance of valid and nullable CVSS values',
        passed: true,
        details: 'Successfully stored CVSS values: 0.0, 5.5, 10.0, and NULL.',
      });
    } catch (err: unknown) {
      results.push({
        testName: 'Acceptance of valid and nullable CVSS values',
        passed: false,
        error: String(err),
      });
    }

    // ------------------------------------------------------------------------
    // TEST 5: Foreign-key restrictions on prohibited parent deletion (ON DELETE RESTRICT)
    // ------------------------------------------------------------------------
    try {
      let projectDeletionBlocked = false;
      let userDeletionBlocked = false;

      // Attempt to delete project that has findings
      try {
        await client.query(`DELETE FROM projects WHERE id = $1;`, [testProjectId]);
      } catch (err: unknown) {
        const pgErr = err as { code?: string };
        if (pgErr.code === '23503') {
          projectDeletionBlocked = true;
        }
      }

      // Attempt to delete user that has created findings/projects
      try {
        await client.query(`DELETE FROM users WHERE id = $1;`, [testUserId]);
      } catch (err: unknown) {
        const pgErr = err as { code?: string };
        if (pgErr.code === '23503') {
          userDeletionBlocked = true;
        }
      }

      if (projectDeletionBlocked && userDeletionBlocked) {
        results.push({
          testName: 'Foreign-key restrictions on prohibited parent deletion',
          passed: true,
          details: 'ON DELETE RESTRICT prevented deletion of active parent project and user records (code 23503).',
        });
      } else {
        results.push({
          testName: 'Foreign-key restrictions on prohibited parent deletion',
          passed: false,
          error: `Project deletion blocked: ${projectDeletionBlocked}, User deletion blocked: ${userDeletionBlocked}`,
        });
      }
    } catch (err: unknown) {
      results.push({
        testName: 'Foreign-key restrictions on prohibited parent deletion',
        passed: false,
        error: String(err),
      });
    }

    // ------------------------------------------------------------------------
    // TEST 6: IPv4 and IPv6 INET storage in audit_events
    // ------------------------------------------------------------------------
    try {
      const ipv4 = '192.168.1.100';
      const ipv6 = '2001:db8::1';

      const res4 = await client.query<{ ip_address: string }>(
        `INSERT INTO audit_events (actor_id, event_category, event_type, ip_address)
         VALUES ($1, 'AUTH', 'user.login', $2)
         RETURNING ip_address;`,
        [testUserId, ipv4],
      );

      const res6 = await client.query<{ ip_address: string }>(
        `INSERT INTO audit_events (actor_id, event_category, event_type, ip_address)
         VALUES ($1, 'AUTH', 'user.login', $2)
         RETURNING ip_address;`,
        [testUserId, ipv6],
      );

      if (res4.rows[0]?.ip_address === ipv4 && res6.rows[0]?.ip_address === ipv6) {
        results.push({
          testName: 'IPv4 and IPv6 INET storage',
          passed: true,
          details: `Successfully stored and round-tripped IPv4 (${ipv4}) and IPv6 (${ipv6}) network addresses.`,
        });
      } else {
        results.push({
          testName: 'IPv4 and IPv6 INET storage',
          passed: false,
          error: `Retrieved IPv4: ${res4.rows[0]?.ip_address}, IPv6: ${res6.rows[0]?.ip_address}`,
        });
      }
    } catch (err: unknown) {
      results.push({
        testName: 'IPv4 and IPv6 INET storage',
        passed: false,
        error: String(err),
      });
    }

    // ------------------------------------------------------------------------
    // TEST 8: Audit event creation and timestamp behavior
    // ------------------------------------------------------------------------
    try {
      const res = await client.query<{ created_at: Date }>(
        `INSERT INTO audit_events (actor_id, event_category, event_type, resource_type)
         VALUES ($1, 'FINDING', 'finding.created', 'finding')
         RETURNING created_at;`,
        [testUserId],
      );

      const createdAt = res.rows[0]?.created_at;
      if (createdAt instanceof Date && !isNaN(createdAt.getTime())) {
        results.push({
          testName: 'Audit event creation and timestamp behavior',
          passed: true,
          details: `Audit event created with valid TIMESTAMPTZ(6): ${createdAt.toISOString()}`,
        });
      } else {
        results.push({
          testName: 'Audit event creation and timestamp behavior',
          passed: false,
          error: `Invalid or missing created_at: ${String(createdAt)}`,
        });
      }
    } catch (err: unknown) {
      results.push({
        testName: 'Audit event creation and timestamp behavior',
        passed: false,
        error: String(err),
      });
    }

    // Clean up synthetic test records
    await client.query('DELETE FROM remediation_tasks WHERE finding_id = $1;', [testFindingId]);
    await client.query('DELETE FROM findings WHERE id = $1;', [testFindingId]);
    await client.query('DELETE FROM findings WHERE project_id = $1;', [testProjectId]);
    await client.query('DELETE FROM audit_events WHERE actor_id IN ($1, $2);', [testUserId, testUser2Id]);
    await client.query('DELETE FROM projects WHERE id = $1;', [testProjectId]);
    await client.query('DELETE FROM users WHERE id IN ($1, $2);', [testUserId, testUser2Id]);
  } finally {
    await client.end();
  }

  const allPassed = results.every((r) => r.passed);
  return {
    allPassed,
    targetDatabase: currentDb,
    hostPort: String(resolvedPort),
    pgVersion: versionStr,
    results,
  };
}

// Standalone CLI execution
if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  runDatabaseIntegrityTests()
    .then((outcome) => {
      console.log('==================================================');
      console.log('SecureFlow — Database Integrity Test Suite');
      console.log('==================================================');
      console.log(`Target Database: ${outcome.targetDatabase}`);
      console.log(`Host Port:       ${outcome.hostPort}`);
      console.log(`PostgreSQL:      ${outcome.pgVersion.split(' on ')[0]}`);
      console.log('--------------------------------------------------');
      for (const res of outcome.results) {
        const icon = res.passed ? '✅ PASS' : '❌ FAIL';
        console.log(`${icon}: ${res.testName}`);
        if (res.details) console.log(`   ${res.details}`);
        if (res.error) console.log(`   ERROR: ${res.error}`);
      }
      console.log('==================================================');
      console.log(`Summary: ${outcome.results.filter((r) => r.passed).length}/${outcome.results.length} tests passed.`);
      process.exit(outcome.allPassed ? 0 : 1);
    })
    .catch((err) => {
      console.error('FATAL TEST RUNNER ERROR:', err.message);
      process.exit(1);
    });
}
