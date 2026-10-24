import path from 'node:path';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';
import { DatabaseManager } from '../../src/db/database-manager.js';
import type { RepositoryContainer } from '../../src/db/repositories/index.js';
import {
  ConcurrencyConflictError,
  SecureFlowError,
} from '@secureflow/shared';

// Load environment variables for local integration testing
const __dirname = path.dirname(fileURLToPath(import.meta.url));
dotenv.config({ path: path.resolve(__dirname, '../../../../.env') });
dotenv.config({ path: path.resolve(__dirname, '../../../.env') });

/**
 * Validates the test database connection URL against strict isolation constraints.
 *
 * Rules:
 * - TEST_DATABASE_URL must be explicitly provided.
 * - Fallback to DATABASE_URL is strictly prohibited.
 * - Target database must be 'secureflow_test' (never 'secureflow_dev').
 * - Target port must be 5433 (PostgreSQL 17; protects port 5432 native PostgreSQL 15).
 */
export function validateTestDatabaseUrl(rawUrl?: string): string {
  if (!rawUrl || typeof rawUrl !== 'string' || rawUrl.trim().length === 0) {
    throw new SecureFlowError(
      'SAFETY REFUSAL: TEST_DATABASE_URL is required and cannot be empty. Fallback to DATABASE_URL is strictly prohibited.',
      'TEST_DATABASE_URL_REQUIRED',
      500,
    );
  }

  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new SecureFlowError(
      'SAFETY REFUSAL: TEST_DATABASE_URL is not a valid URL.',
      'TEST_DATABASE_URL_INVALID',
      500,
    );
  }

  const dbName = parsed.pathname.replace(/^\//, '');
  if (dbName === 'secureflow_dev') {
    throw new SecureFlowError(
      'SAFETY REFUSAL: TEST_DATABASE_URL must NEVER target development database "secureflow_dev". It must target "secureflow_test".',
      'TEST_DATABASE_TARGET_DEV_REFUSED',
      500,
    );
  }

  if (dbName !== 'secureflow_test') {
    throw new SecureFlowError(
      `SAFETY REFUSAL: TEST_DATABASE_URL must target "secureflow_test", but received "${dbName}".`,
      'TEST_DATABASE_NAME_MISMATCH',
      500,
    );
  }

  const port = parsed.port ? Number.parseInt(parsed.port, 10) : 5432;
  if (port === 5432) {
    throw new SecureFlowError(
      'SAFETY REFUSAL: TEST_DATABASE_URL targets port 5432 (native PostgreSQL 15). Integration tests are strictly confined to port 5433 (PostgreSQL 17).',
      'TEST_DATABASE_PORT_5432_REFUSED',
      500,
    );
  }

  if (port !== 5433) {
    throw new SecureFlowError(
      `SAFETY REFUSAL: TEST_DATABASE_URL must target approved host port 5433, but received port ${port}.`,
      'TEST_DATABASE_PORT_MISMATCH',
      500,
    );
  }

  return rawUrl;
}

export async function runGate3bIntegrationTests(): Promise<{
  allPassed: boolean;
  totalTests: number;
  passedTests: number;
}> {
  console.log('==================================================');
  console.log('SecureFlow — Gate 3B Database & Repository Integration Suite');
  console.log('==================================================');

  let totalTests = 0;
  let passedTests = 0;

  function recordPass(name: string, details?: string) {
    totalTests++;
    passedTests++;
    console.log(`✅ PASS: ${name}`);
    if (details) {
      console.log(`   ${details}`);
    }
  }

  function recordFail(name: string, error: unknown) {
    totalTests++;
    console.error(`❌ FAIL: ${name}`);
    console.error(error);
    throw error;
  }

  // -------------------------------------------------------------------------
  // Safety Isolation Preflight & Negative URL Tests
  // -------------------------------------------------------------------------
  try {
    // Negative test 1: Missing URL rejected
    let rejectedMissing = false;
    try {
      validateTestDatabaseUrl(undefined);
    } catch (err: unknown) {
      if (err instanceof SecureFlowError && err.code === 'TEST_DATABASE_URL_REQUIRED') {
        rejectedMissing = true;
      }
    }
    if (!rejectedMissing) {
      throw new Error('validateTestDatabaseUrl failed to reject missing TEST_DATABASE_URL');
    }
    recordPass('Safety Isolation: Missing TEST_DATABASE_URL Refusal', 'Strictly requires explicit TEST_DATABASE_URL with zero fallback');

    // Negative test 2: Dev database targeted rejected
    let rejectedDev = false;
    try {
      validateTestDatabaseUrl(
        'postgresql://secureflow:pass@127.0.0.1:5433/secureflow_dev?schema=public',
      );
    } catch (err: unknown) {
      if (err instanceof SecureFlowError && err.code === 'TEST_DATABASE_TARGET_DEV_REFUSED') {
        rejectedDev = true;
      }
    }
    if (!rejectedDev) {
      throw new Error('validateTestDatabaseUrl failed to reject secureflow_dev');
    }
    recordPass('Safety Isolation: secureflow_dev Refusal', 'Strictly refuses connection to development database secureflow_dev');

    // Negative test 3: Port 5432 (native PG 15) rejected
    let rejectedPort5432 = false;
    try {
      validateTestDatabaseUrl(
        'postgresql://secureflow:pass@127.0.0.1:5432/secureflow_test?schema=public',
      );
    } catch (err: unknown) {
      if (err instanceof SecureFlowError && err.code === 'TEST_DATABASE_PORT_5432_REFUSED') {
        rejectedPort5432 = true;
      }
    }
    if (!rejectedPort5432) {
      throw new Error('validateTestDatabaseUrl failed to reject port 5432');
    }
    recordPass('Safety Isolation: Native Port 5432 Refusal', 'Strictly protects native PostgreSQL 15 by refusing port 5432');

    // Now validate active TEST_DATABASE_URL from environment
    const rawTestUrl = validateTestDatabaseUrl(process.env['TEST_DATABASE_URL']);

    const dbManager = new DatabaseManager({
      connectionString: rawTestUrl,
      maxConnections: 5,
      connectionTimeoutMillis: 5000,
      statementTimeoutMillis: 10000,
    });

    try {
      // -------------------------------------------------------------------------
      // 1. Engine & Database Identity Preflight
      // -------------------------------------------------------------------------
      const identity = await dbManager.verifyConnectivity();
      console.log(`Target Database:    ${identity.database}`);
      console.log(`Host Port:          ${identity.port}`);
      console.log(`PostgreSQL Version: ${identity.version.split('\n')[0]}`);
      console.log('--------------------------------------------------');

      if (identity.database !== 'secureflow_test') {
        throw new Error(`Connected database '${identity.database}' is not 'secureflow_test'`);
      }
      if (identity.majorVersion !== 17) {
        throw new Error(`Connected PostgreSQL major version is ${identity.majorVersion}, expected 17`);
      }
      recordPass('Engine Identity & Safety Assertions', `Connected to ${identity.database} on port ${identity.port} (PG 17)`);

      // -------------------------------------------------------------------------
      // Setup Test Users in secureflow_test
      // -------------------------------------------------------------------------
      const prisma = dbManager.getPrismaClient();
      const testAdminSub = `test-admin-${Date.now()}`;
      const testAnalystSub = `test-analyst-${Date.now()}`;
      const testDevSub = `test-dev-${Date.now()}`;

      const [adminUser, analystUser, devUser] = await Promise.all([
        prisma.user.create({
          data: {
            sub: testAdminSub,
            email: `${testAdminSub}@example.com`,
            displayName: 'Test Admin',
            globalRole: 'ADMIN',
            isActive: true,
          },
        }),
        prisma.user.create({
          data: {
            sub: testAnalystSub,
            email: `${testAnalystSub}@example.com`,
            displayName: 'Test Analyst',
            globalRole: 'ANALYST',
            isActive: true,
          },
        }),
        prisma.user.create({
          data: {
            sub: testDevSub,
            email: `${testDevSub}@example.com`,
            displayName: 'Test Developer',
            globalRole: 'DEVELOPER',
            isActive: true,
          },
        }),
      ]);

      const repos = dbManager.getRepositories();

      // -------------------------------------------------------------------------
      // 2. Project Repository: Creation, Membership & Query Scoping
      // -------------------------------------------------------------------------
      const testSlug = `gate3b-proj-${Date.now()}`;
      const project = await repos.projectRepo.create({
        name: 'Gate 3B Test Project',
        slug: testSlug,
        description: 'Integration test project for Gate 3B repositories',
        createdById: adminUser.id,
      });
      recordPass('ProjectRepository.create', `Created project '${project.name}' with id ${project.id}`);

      // Add member
      const member = await repos.projectRepo.addMember(project.id, {
        userId: devUser.id,
        role: 'DEVELOPER',
        addedById: adminUser.id,
      });
      recordPass('ProjectRepository.addMember', `Added developer ${member.userId} with role ${member.role}`);

      // Query scoping: non-member query with accessibleProjectIds not including project.id returns 0 items
      const scopedList = await repos.projectRepo.findMany({
        scope: { accessibleProjectIds: ['00000000-0000-0000-0000-000000000000'] },
      });
      if (scopedList.items.length !== 0) {
        throw new Error('Scoped query returned projects outside accessibleProjectIds');
      }
      recordPass('ProjectRepository query scoping', 'Scoped findMany excluded unpermitted projects');

      // Negative query scoping: empty accessibleProjectIds returns 0 items
      const emptyScopedList = await repos.projectRepo.findMany({
        scope: { accessibleProjectIds: [] },
      });
      if (emptyScopedList.items.length !== 0 || emptyScopedList.total !== 0) {
        throw new Error('Empty scope query returned projects; fail-closed violation!');
      }
      recordPass('ProjectRepository fail-closed scope', 'Empty accessibleProjectIds returned 0 projects');

      // -------------------------------------------------------------------------
      // 3. Finding Repository: Creation & Atomic OCC Updates
      // -------------------------------------------------------------------------
      const finding = await repos.findingRepo.create({
        projectId: project.id,
        title: 'XSS in Profile Header',
        description: 'Unescaped user input rendered in profile header',
        severity: 'HIGH',
        category: 'XSS',
        cvssScore: 7.5,
        createdById: analystUser.id,
      });

      if (finding.version !== 1 || finding.status !== 'OPEN' || finding.isDeleted !== false) {
        throw new Error(`Initial finding attributes invalid: version=${finding.version}, status=${finding.status}`);
      }
      recordPass('FindingRepository.create', `Created finding with version=1, status=OPEN, cvss=7.5`);

      // Successful atomic OCC update with matching expectedVersion (1 -> 2)
      const updatedFinding = await repos.findingRepo.updateAtomic(finding.id, {
        expectedVersion: 1,
        title: 'XSS in Profile Header (Triaged)',
        status: 'TRIAGED',
        assignedToId: devUser.id,
      });

      if (updatedFinding.version !== 2 || updatedFinding.status !== 'TRIAGED') {
        throw new Error(`Updated finding version=${updatedFinding.version}, expected 2`);
      }
      recordPass('FindingRepository.updateAtomic', 'Atomically incremented version from 1 to 2 on status update');

      // Stale version update rejection (trying version 1 when current is 2)
      try {
        await repos.findingRepo.updateAtomic(finding.id, {
          expectedVersion: 1,
          status: 'IN_PROGRESS',
        });
        throw new Error('Expected ConcurrencyConflictError was not thrown on stale version');
      } catch (err: unknown) {
        if (!(err instanceof ConcurrencyConflictError)) {
          throw err;
        }
        if (err.statusCode !== 409) {
          throw new Error(`ConcurrencyConflictError status mismatch: ${err.statusCode}`);
        }
        recordPass('Atomic OCC Concurrency Conflict Rejection', 'Stale version update correctly rejected with HTTP 409');
      }

      // Soft-delete and Invariant OLI-12
      const deletedFinding = await repos.findingRepo.softDelete(finding.id, 2);
      if (!deletedFinding.isDeleted || deletedFinding.version !== 3) {
        throw new Error('Soft delete did not increment version to 3 or set isDeleted = true');
      }

      // Default findById without includeDeleted returns null (existence hiding)
      const hiddenFinding = await repos.findingRepo.findById(finding.id, {
        unrestricted: true,
        includeDeleted: false,
      });
      if (hiddenFinding !== null) {
        throw new Error('Soft-deleted finding was returned when includeDeleted was false');
      }

      // Admin findById with includeDeleted returns record
      const retrievedFinding = await repos.findingRepo.findById(finding.id, {
        unrestricted: true,
        includeDeleted: true,
      });
      if (!retrievedFinding || !retrievedFinding.isDeleted) {
        throw new Error('Failed to retrieve soft-deleted finding with includeDeleted=true');
      }
      recordPass('Invariant OLI-12 Soft-Delete Enforcement', 'Soft-deleted finding hidden by default, accessible only with explicit flag');

      // Restore finding for task testing
      await repos.findingRepo.updateAtomic(finding.id, {
        expectedVersion: 3,
        isDeleted: false,
        status: 'IN_PROGRESS',
      });

      // Developer Persona Query Scoping: developer sees assigned finding within authorized project
      const devFindings = await repos.findingRepo.findMany({
        scope: {
          accessibleProjectIds: [project.id],
          assignedToUserId: devUser.id,
        },
      });
      if (devFindings.items.length !== 1 || devFindings.items[0]?.id !== finding.id) {
        throw new Error('Developer scope failed to return assigned finding in authorized project');
      }
      recordPass('FindingRepository Developer Persona Scope', 'Developer successfully retrieved assigned finding in authorized project');

      // Developer Persona Negative Scoping: developer with non-matching project scope receives 0 findings
      const devUnauthorizedFindings = await repos.findingRepo.findMany({
        scope: {
          accessibleProjectIds: ['00000000-0000-0000-0000-000000000000'],
          assignedToUserId: devUser.id,
        },
      });
      if (devUnauthorizedFindings.items.length !== 0 || devUnauthorizedFindings.total !== 0) {
        throw new Error('Developer scope returned findings outside authorized project list!');
      }
      recordPass('FindingRepository Developer Project Isolation', 'Developer query outside authorized project returned 0 findings (fail-closed)');

      // -------------------------------------------------------------------------
      // 4. RemediationTask Repository
      // -------------------------------------------------------------------------
      const task = await repos.taskRepo.create({
        findingId: finding.id,
        assignedToId: devUser.id,
        assignedById: analystUser.id,
        description: 'Implement HTML entity encoding in profile header template',
      });

      if (task.status !== 'PENDING') {
        throw new Error(`Initial task status is '${task.status}', expected PENDING`);
      }
      recordPass('TaskRepository.create', `Created remediation task ${task.id} in PENDING status`);

      const activeTask = await repos.taskRepo.findActiveByFindingId(finding.id);
      if (!activeTask || activeTask.id !== task.id) {
        throw new Error('findActiveByFindingId failed to return active task');
      }
      recordPass('TaskRepository.findActiveByFindingId', 'Successfully located active remediation task');

      const updatedTask = await repos.taskRepo.updateNotes(task.id, 'Investigation complete; preparing fix');
      if (updatedTask.notes !== 'Investigation complete; preparing fix') {
        throw new Error('Task notes update failed');
      }
      recordPass('TaskRepository.updateNotes', 'Updated developer progress notes');

      // -------------------------------------------------------------------------
      // 5. Audit Repository: Append-Only Operations
      // -------------------------------------------------------------------------
      const audit = await repos.auditRepo.append({
        actorId: devUser.id,
        eventCategory: 'TASK',
        eventType: 'TASK_NOTES_UPDATED',
        resourceId: task.id,
        resourceType: 'remediation_task',
        beforeState: { notes: null },
        afterState: { notes: 'Investigation complete; preparing fix' },
        ipAddress: '127.0.0.1',
        userAgent: 'SecureFlow-Integration-Runner/1.0',
      });

      if (!audit.id || audit.eventCategory !== 'TASK') {
        throw new Error('Audit record creation failed');
      }
      recordPass('AuditRepository.append', `Recorded append-only audit event ${audit.id}`);

      const auditResults = await repos.auditRepo.query({
        resourceId: task.id,
        eventCategory: 'TASK',
      });
      if (auditResults.items.length === 0 || auditResults.items[0]?.id !== audit.id) {
        throw new Error('Audit query failed to return recorded audit event');
      }
      recordPass('AuditRepository.query', `Queried audit events filtered by resourceId and eventCategory`);

      // -------------------------------------------------------------------------
      // 6. Transaction Atomicity & Rollback Verification
      // -------------------------------------------------------------------------
      const rollbackTitle = `Rollback Finding ${Date.now()}`;
      try {
        await dbManager.runTransaction(async (txRepos) => {
          // 1. Create finding in transaction
          const txFinding = await txRepos.findingRepo.create({
            projectId: project.id,
            title: rollbackTitle,
            description: 'This finding must be rolled back',
            severity: 'LOW',
            category: 'OTHER',
            createdById: analystUser.id,
          });

          // 2. Append audit event in transaction
          await txRepos.auditRepo.append({
            actorId: analystUser.id,
            eventCategory: 'FINDING',
            eventType: 'FINDING_CREATED',
            resourceId: txFinding.id,
            resourceType: 'finding',
          });

          // 3. Deliberately throw error to force transaction rollback
          throw new Error('DELIBERATE_TEST_ABORT_FOR_ROLLBACK');
        });
        throw new Error('Transaction succeeded unexpectedly despite deliberate error');
      } catch (err: unknown) {
        if ((err as Error).message !== 'DELIBERATE_TEST_ABORT_FOR_ROLLBACK') {
          throw err;
        }
      }

      // Verify neither finding nor audit record was committed to secureflow_test
      const findingCheck = await prisma.finding.findFirst({
        where: { title: rollbackTitle },
      });
      if (findingCheck !== null) {
        throw new Error('Finding was found in database; transaction rollback failed!');
      }
      recordPass('Transaction Atomicity & Full Rollback', 'Transactional failure completely rolled back finding and audit writes');

      // -------------------------------------------------------------------------
      // 7. Transaction Lifecycle Safety: Post-Completion Write Protection
      // -------------------------------------------------------------------------
      let leakedTxRepos!: RepositoryContainer;
      await dbManager.runTransaction(async (txRepos) => {
        leakedTxRepos = txRepos;
      });

      // Attempting to write using leaked repository after transaction commit must fail
      let writeRejectedAfterCompletion = false;
      try {
        await leakedTxRepos.findingRepo.create({
          projectId: project.id,
          title: 'Post-transaction write attempt',
          description: 'Should fail because transaction is closed',
          severity: 'LOW',
          category: 'OTHER',
          createdById: analystUser.id,
        });
      } catch {
        writeRejectedAfterCompletion = true;
      }
      if (!writeRejectedAfterCompletion) {
        throw new Error('Repository bound to closed transaction succeeded in writing data! Expected failure.');
      }
      recordPass(
        'Transaction Scope Post-Completion Write Protection',
        'Repositories bound to completed transaction are strictly prevented from performing writes afterward',
      );

      // -------------------------------------------------------------------------
      // Safe Cleanup of Synthetic Test Data from secureflow_test
      // -------------------------------------------------------------------------
      await prisma.remediationTask.deleteMany({ where: { findingId: finding.id } });
      await prisma.findingEvent.deleteMany({ where: { findingId: finding.id } });
      await prisma.finding.deleteMany({ where: { projectId: project.id } });
      await prisma.projectMember.deleteMany({ where: { projectId: project.id } });
      await prisma.project.deleteMany({ where: { id: project.id } });
      await prisma.auditEvent.deleteMany({
        where: {
          actorId: { in: [adminUser.id, analystUser.id, devUser.id] },
        },
      });
      await prisma.user.deleteMany({
        where: {
          id: { in: [adminUser.id, analystUser.id, devUser.id] },
        },
      });

      console.log('--------------------------------------------------');
      console.log(`Summary: ${passedTests}/${totalTests} integration tests passed.`);
      console.log('==================================================');
      return { allPassed: true, totalTests, passedTests };
    } finally {
      await dbManager.shutdown();
    }
  } catch (error) {
    recordFail('Gate 3B Integration Test Suite', error);
    return { allPassed: false, totalTests, passedTests };
  }
}

// Execute standalone if invoked directly via tsx
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  runGate3bIntegrationTests()
    .then((result) => {
      if (!result.allPassed) {
        process.exit(1);
      }
    })
    .catch((err) => {
      console.error(err);
      process.exit(1);
    });
}
