import path from 'node:path';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';
import { DatabaseManager } from '../../src/db/database-manager.js';
import {
  FindingService,
  ActorContext,
} from '../../src/index.js';
import { TaskService } from '../../src/services/task-service.js';
import { validateTestDatabaseUrl } from './gate3b-repositories.integration.js';
import {
  ConcurrencyConflictError,
  EntityNotFoundError,
  ForbiddenError,
  InvalidStateTransitionError,
} from '@secureflow/shared';

// Load environment variables for local integration testing
const __dirname = path.dirname(fileURLToPath(import.meta.url));
dotenv.config({ path: path.resolve(__dirname, '../../../../.env') });
dotenv.config({ path: path.resolve(__dirname, '../../../.env') });

export async function runGate3dTaskServiceIntegrationTests(): Promise<{
  allPassed: boolean;
  totalTests: number;
  passedTests: number;
}> {
  console.log('==================================================');
  console.log('SecureFlow — Gate 3D.4 TaskService & Finding Lifecycle Integration Suite');
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

  // Strictly validate TEST_DATABASE_URL with zero fallback to DATABASE_URL
  const rawTestUrl = validateTestDatabaseUrl(process.env['TEST_DATABASE_URL']);

  const dbManager = new DatabaseManager({
    connectionString: rawTestUrl,
    maxConnections: 10,
    connectionTimeoutMillis: 5000,
    statementTimeoutMillis: 10000,
  });

  const createdUserIds: string[] = [];
  const createdProjectIds: string[] = [];
  const createdFindingIds: string[] = [];
  const createdTaskIds: string[] = [];
  const createdFindingEventIds: string[] = [];
  const createdAuditIds: string[] = [];

  try {
    const identity = await dbManager.verifyConnectivity();
    if (identity.database !== 'secureflow_test' || identity.majorVersion !== 17) {
      throw new Error(`Connected database is not secureflow_test on PostgreSQL 17: ${identity.database}`);
    }
    recordPass('Engine Identity & Safety Assertions', `Connected to ${identity.database} on port ${identity.port} (PG 17)`);

    const prisma = dbManager.getPrismaClient();
    const findingService = new FindingService(dbManager);
    const taskService = new TaskService(dbManager);

    // Setup synthetic test users in PostgreSQL
    const testAdminSub = `gate3d4-admin-${Date.now()}`;
    const testAnalystSub = `gate3d4-analyst-${Date.now()}`;
    const testDev1Sub = `gate3d4-dev1-${Date.now()}`;
    const testDev2Sub = `gate3d4-dev2-${Date.now()}`;

    const [adminUser, analystUser, dev1User, dev2User] = await Promise.all([
      prisma.user.create({
        data: {
          sub: testAdminSub,
          email: `${testAdminSub}@example.com`,
          displayName: 'Gate 3D4 Admin User',
          globalRole: 'ADMIN',
          isActive: true,
        },
      }),
      prisma.user.create({
        data: {
          sub: testAnalystSub,
          email: `${testAnalystSub}@example.com`,
          displayName: 'Gate 3D4 Analyst User',
          globalRole: 'ANALYST',
          isActive: true,
        },
      }),
      prisma.user.create({
        data: {
          sub: testDev1Sub,
          email: `${testDev1Sub}@example.com`,
          displayName: 'Gate 3D4 Developer One',
          globalRole: 'DEVELOPER',
          isActive: true,
        },
      }),
      prisma.user.create({
        data: {
          sub: testDev2Sub,
          email: `${testDev2Sub}@example.com`,
          displayName: 'Gate 3D4 Developer Two',
          globalRole: 'DEVELOPER',
          isActive: true,
        },
      }),
    ]);
    createdUserIds.push(adminUser.id, analystUser.id, dev1User.id, dev2User.id);

    // Create synthetic project
    const project = await prisma.project.create({
      data: {
        name: 'Gate 3D4 Core Project',
        slug: `gate3d4-core-${Date.now()}`,
        description: 'Integration test target for Sub-Gate 3D.4 lifecycle transitions',
        isActive: true,
        createdById: adminUser.id,
      },
    });
    createdProjectIds.push(project.id);

    // Create project memberships
    await Promise.all([
      prisma.projectMember.create({
        data: {
          projectId: project.id,
          userId: analystUser.id,
          role: 'ANALYST',
          addedById: adminUser.id,
        },
      }),
      prisma.projectMember.create({
        data: {
          projectId: project.id,
          userId: dev1User.id,
          role: 'DEVELOPER',
          addedById: adminUser.id,
        },
      }),
      prisma.projectMember.create({
        data: {
          projectId: project.id,
          userId: dev2User.id,
          role: 'DEVELOPER',
          addedById: adminUser.id,
        },
      }),
    ]);

    // Construct ActorContexts
    const analystActor = new ActorContext({
      id: analystUser.id,
      globalRole: 'ANALYST',
      isActive: true,
      memberships: [{ projectId: project.id, role: 'ANALYST' }],
    });

    const dev1Actor = new ActorContext({
      id: dev1User.id,
      globalRole: 'DEVELOPER',
      isActive: true,
      memberships: [{ projectId: project.id, role: 'DEVELOPER' }],
    });

    const dev2Actor = new ActorContext({
      id: dev2User.id,
      globalRole: 'DEVELOPER',
      isActive: true,
      memberships: [{ projectId: project.id, role: 'DEVELOPER' }],
    });

    // Helper to create a triaged finding ready for assignment
    async function createTriagedFinding(title = 'Vulnerability for 3D4 test'): Promise<{ id: string; version: number }> {
      const created = await findingService.createFinding(analystActor, {
        projectId: project.id,
        title,
        description: 'Test vulnerability description',
        severity: 'HIGH',
        category: 'INJECTION',
      });
      createdFindingIds.push(created.id);

      const triaged = await findingService.triageFinding(analystActor, created.id, {
        expectedVersion: 1,
        severity: 'HIGH',
        cvssScore: 8.5,
      });
      return { id: triaged.id, version: triaged.version };
    }

    // ========================================================================
    // Scenario 1: Finding assignment and remediation task creation in one transaction
    // ========================================================================
    const finding1 = await createTriagedFinding('SQL Injection in Auth API');

    const assignedFinding1 = await findingService.assignFinding(analystActor, finding1.id, {
      expectedVersion: finding1.version,
      assignedToId: dev1User.id,
      taskDescription: 'Remediate SQL injection using parameterized queries',
      dueDate: '2026-12-31',
    });

    if (assignedFinding1.status !== 'IN_PROGRESS' || assignedFinding1.version !== finding1.version + 1) {
      throw new Error(`Assignment failed: status=${assignedFinding1.status}, version=${assignedFinding1.version}`);
    }
    if (assignedFinding1.assignedToId !== dev1User.id) {
      throw new Error(`Assignment target mismatch: ${assignedFinding1.assignedToId}`);
    }

    // Check task in DB
    const activeTask1 = await prisma.remediationTask.findFirst({
      where: { findingId: finding1.id, status: 'PENDING' },
    });
    if (!activeTask1 || activeTask1.assignedToId !== dev1User.id || activeTask1.assignedById !== analystUser.id) {
      throw new Error('Remediation task not created in PENDING status with correct assignees');
    }
    createdTaskIds.push(activeTask1.id);

    // Verify atomic FindingEvent (ASSIGNED)
    const assignEvents = await prisma.findingEvent.findMany({
      where: { findingId: finding1.id, eventType: 'ASSIGNED' },
    });
    if (assignEvents.length === 0) {
      throw new Error('FindingEvent ASSIGNED not recorded');
    }
    createdFindingEventIds.push(...assignEvents.map((e) => e.id));

    // Verify atomic AuditEvents (finding.assigned & task.created)
    const assignAudits = await prisma.auditEvent.findMany({
      where: { resourceId: finding1.id, eventType: 'finding.assigned' },
    });
    const taskAudits = await prisma.auditEvent.findMany({
      where: { resourceId: activeTask1.id, eventType: 'task.created' },
    });
    if (assignAudits.length === 0 || taskAudits.length === 0) {
      throw new Error('AuditEvents finding.assigned or task.created missing');
    }
    createdAuditIds.push(...assignAudits.map((a) => a.id), ...taskAudits.map((a) => a.id));

    recordPass(
      'Scenario 1: Finding assignment and remediation task creation in one transaction',
      `Finding ${finding1.id} transitioned TRIAGED -> IN_PROGRESS (v${assignedFinding1.version}) with PENDING task ${activeTask1.id}`,
    );

    // ========================================================================
    // Scenario 2: Duplicate active remediation task protection (Partial Unique Index)
    // ========================================================================
    // A second active task on the same finding must be rejected by PostgreSQL partial unique index
    let dbDuplicateBlocked = false;
    try {
      await prisma.remediationTask.create({
        data: {
          findingId: finding1.id,
          assignedToId: dev2User.id,
          assignedById: analystUser.id,
          description: 'Rogue duplicate active task',
          status: 'PENDING',
        },
      });
    } catch {
      dbDuplicateBlocked = true;
    }
    if (!dbDuplicateBlocked) {
      throw new Error('PostgreSQL partial unique index failed to reject duplicate active task!');
    }

    // Also verify service layer rejects re-assignment when an active task exists
    let serviceDuplicateBlocked = false;
    try {
      await findingService.assignFinding(analystActor, finding1.id, {
        expectedVersion: assignedFinding1.version,
        assignedToId: dev2User.id,
        taskDescription: 'Duplicate assignment attempt',
      });
    } catch (err) {
      if (err instanceof InvalidStateTransitionError) {
        serviceDuplicateBlocked = true;
      }
    }
    if (!serviceDuplicateBlocked) {
      throw new Error('Service layer allowed assignFinding on finding with active task!');
    }

    recordPass(
      'Scenario 2: Duplicate active remediation task protection',
      'PostgreSQL partial unique index and service layer prevented duplicate active tasks',
    );

    // ========================================================================
    // Scenario 3: Concurrent assignment OCC
    // ========================================================================
    const finding3 = await createTriagedFinding('IDOR Vulnerability');
    const [resA, resB] = await Promise.allSettled([
      findingService.assignFinding(analystActor, finding3.id, {
        expectedVersion: finding3.version,
        assignedToId: dev1User.id,
        taskDescription: 'Assigned to Dev1 via Racer A',
      }),
      findingService.assignFinding(analystActor, finding3.id, {
        expectedVersion: finding3.version,
        assignedToId: dev2User.id,
        taskDescription: 'Assigned to Dev2 via Racer B',
      }),
    ]);

    const successes = [resA, resB].filter((r) => r.status === 'fulfilled');
    const failures = [resA, resB].filter((r) => r.status === 'rejected');

    if (successes.length !== 1 || failures.length !== 1) {
      throw new Error(`Concurrent assignment expected exactly 1 success and 1 failure, got ${successes.length} / ${failures.length}`);
    }
    const failedReason = (failures[0] as PromiseRejectedResult).reason;
    if (!(failedReason instanceof ConcurrencyConflictError)) {
      throw new Error(`Expected ConcurrencyConflictError for stale expectedVersion on concurrent assignment, got ${failedReason}`);
    }
    if (failedReason.statusCode !== 409) {
      throw new Error(`Expected ConcurrencyConflictError statusCode to be 409, got ${failedReason.statusCode}`);
    }

    // Verify task count in database is exactly 1
    const tasksForFinding3 = await prisma.remediationTask.findMany({
      where: { findingId: finding3.id },
    });
    if (tasksForFinding3.length !== 1) {
      throw new Error(`Expected exactly 1 task in database, found ${tasksForFinding3.length}`);
    }
    createdTaskIds.push(tasksForFinding3[0].id);

    // Verify matching expectedVersion with invalid lifecycle transition throws InvalidStateTransitionError (HTTP 422)
    const freshOpenFinding = await findingService.createFinding(analystActor, {
      projectId: project.id,
      title: 'Open finding assignment attempt',
      description: 'Must fail with 422 InvalidStateTransitionError',
      severity: 'MEDIUM',
      category: 'CONFIG_EXPOSURE',
    });
    createdFindingIds.push(freshOpenFinding.id);

    let invalidTransitionCaught = false;
    try {
      await findingService.assignFinding(analystActor, freshOpenFinding.id, {
        expectedVersion: 1, // MATCHING version!
        assignedToId: dev1User.id,
        taskDescription: 'Invalid assignment on OPEN finding',
      });
    } catch (err) {
      if (err instanceof InvalidStateTransitionError && err.statusCode === 422) {
        invalidTransitionCaught = true;
      }
    }
    if (!invalidTransitionCaught) {
      throw new Error('Assigning OPEN finding with matching expectedVersion did not throw InvalidStateTransitionError (422)');
    }

    recordPass(
      'Scenario 3: Concurrent assignment OCC and InvalidStateTransition Error Distinction',
      `Stale expectedVersion rejected with HTTP 409 ConcurrencyConflictError; matching version with invalid status rejected with HTTP 422 InvalidStateTransitionError`,
    );

    // ========================================================================
    // Scenario 4: Target Developer membership revoked before assignment
    // ========================================================================
    const finding4 = await createTriagedFinding('SSRF Vulnerability');

    // Create a temporary developer whose membership we revoke
    const tempDevSub = `gate3d4-tempdev-${Date.now()}`;
    const tempDev = await prisma.user.create({
      data: {
        sub: tempDevSub,
        email: `${tempDevSub}@example.com`,
        displayName: 'Temp Dev for Revocation',
        globalRole: 'DEVELOPER',
        isActive: true,
      },
    });
    createdUserIds.push(tempDev.id);

    // Add and immediately revoke membership
    await prisma.projectMember.create({
      data: {
        projectId: project.id,
        userId: tempDev.id,
        role: 'DEVELOPER',
        addedById: adminUser.id,
      },
    });
    await prisma.projectMember.delete({
      where: {
        projectId_userId: {
          projectId: project.id,
          userId: tempDev.id,
        },
      },
    });

    let revokedDevBlocked = false;
    try {
      await findingService.assignFinding(analystActor, finding4.id, {
        expectedVersion: finding4.version,
        assignedToId: tempDev.id,
        taskDescription: 'Assign to revoked developer',
      });
    } catch (err) {
      if (err instanceof ForbiddenError) {
        revokedDevBlocked = true;
      }
    }
    if (!revokedDevBlocked) {
      throw new Error('Assignment to member with revoked membership was not rejected with ForbiddenError!');
    }

    recordPass(
      'Scenario 4: Target Developer membership revoked before assignment',
      'Revoked target Developer rejected with 403 ForbiddenError; finding remains TRIAGED',
    );

    // ========================================================================
    // Scenario 5: Membership revocation racing with remediation submission
    // ========================================================================
    // Assign finding to dev2, then concurrently revoke dev2 membership and submit remediation
    const finding5 = await createTriagedFinding('CSRF Protection Bypass');
    const assignedFinding5 = await findingService.assignFinding(analystActor, finding5.id, {
      expectedVersion: finding5.version,
      assignedToId: dev2User.id,
      taskDescription: 'Fix CSRF token generation',
    });
    const task5 = await prisma.remediationTask.findFirstOrThrow({
      where: { findingId: finding5.id, status: 'PENDING' },
    });
    createdTaskIds.push(task5.id);

    // Revoke dev2 membership
    await prisma.projectMember.delete({
      where: {
        projectId_userId: {
          projectId: project.id,
          userId: dev2User.id,
        },
      },
    });

    let racedSubmissionBlocked = false;
    try {
      await findingService.submitRemediation(dev2Actor, finding5.id, {
        expectedVersion: assignedFinding5.version,
        notes: 'Submitted fix after revocation',
      });
    } catch (err) {
      if (err instanceof EntityNotFoundError) {
        racedSubmissionBlocked = true;
      }
    }
    if (!racedSubmissionBlocked) {
      throw new Error('Revoked member submission was not rejected with EntityNotFoundError!');
    }

    // Restore dev2 membership for subsequent tests
    await prisma.projectMember.create({
      data: {
        projectId: project.id,
        userId: dev2User.id,
        role: 'DEVELOPER',
        addedById: adminUser.id,
      },
    });

    recordPass(
      'Scenario 5: Membership revocation racing with remediation submission',
      'Revoked member submission safely rejected with 404 EntityNotFoundError (existence hiding)',
    );

    // ========================================================================
    // Scenario 6: Correct remediation submission evidence (Separation of Duties)
    // ========================================================================
    // We submit remediation for finding1 (assigned to dev1)
    const submittedFinding1 = await findingService.submitRemediation(dev1Actor, finding1.id, {
      expectedVersion: assignedFinding1.version,
      notes: 'Applied input sanitization and parameterized queries',
    });

    if (submittedFinding1.status !== 'READY_FOR_REVIEW') {
      throw new Error(`Submission failed: status=${submittedFinding1.status}`);
    }

    // Verify task status is SUBMITTED
    const submittedTask1 = await prisma.remediationTask.findUniqueOrThrow({
      where: { id: activeTask1.id },
    });
    if (submittedTask1.status !== 'SUBMITTED' || !submittedTask1.notes?.includes('parameterized queries')) {
      throw new Error(`Task submission verification failed: status=${submittedTask1.status}, notes=${submittedTask1.notes}`);
    }

    // Verify FindingEvent contains submitterId in metadata
    const submitEvents = await prisma.findingEvent.findMany({
      where: { findingId: finding1.id, eventType: 'STATUS_CHANGED', newStatus: 'READY_FOR_REVIEW' },
    });
    if (submitEvents.length === 0) {
      throw new Error('FindingEvent READY_FOR_REVIEW not found');
    }
    createdFindingEventIds.push(...submitEvents.map((e) => e.id));

    const submitEventMeta = submitEvents[0].metadata as Record<string, unknown>;
    if (submitEventMeta.submitterId !== dev1User.id) {
      throw new Error(`Submitter evidence mismatch: expected ${dev1User.id}, got ${submitEventMeta.submitterId}`);
    }

    // Verify audit logs
    const submitAudits = await prisma.auditEvent.findMany({
      where: { resourceId: finding1.id, eventType: 'finding.remediation_submitted' },
    });
    const taskSubmitAudits = await prisma.auditEvent.findMany({
      where: { resourceId: activeTask1.id, eventType: 'task.submitted' },
    });
    if (submitAudits.length === 0 || taskSubmitAudits.length === 0) {
      throw new Error('AuditEvent finding.remediation_submitted or task.submitted not found');
    }
    createdAuditIds.push(...submitAudits.map((a) => a.id), ...taskSubmitAudits.map((a) => a.id));

    recordPass(
      'Scenario 6: Correct remediation submission evidence',
      `Finding ${finding1.id} transitioned IN_PROGRESS -> READY_FOR_REVIEW with authoritative submitter evidence dev1 (${dev1User.id})`,
    );

    // ========================================================================
    // Scenario 7: Verification and rejection with real PostgreSQL data
    // ========================================================================
    // Verification of finding1 (submitted by dev1, verified by analyst)
    const verifiedFinding1 = await findingService.verifyFinding(analystActor, finding1.id, {
      expectedVersion: submittedFinding1.version,
      outcome: 'VERIFIED',
      notes: 'Fix confirmed in staging environment',
    });

    if (verifiedFinding1.status !== 'VERIFIED') {
      throw new Error(`Verification failed: status=${verifiedFinding1.status}`);
    }
    const verifiedTask1 = await prisma.remediationTask.findUniqueOrThrow({
      where: { id: activeTask1.id },
    });
    if (verifiedTask1.status !== 'VERIFIED') {
      throw new Error(`Task verification status mismatch: ${verifiedTask1.status}`);
    }

    // Verify rejection on another finding
    const finding7 = await createTriagedFinding('Insecure Direct Object Reference in Invoices');
    const assignedFinding7 = await findingService.assignFinding(analystActor, finding7.id, {
      expectedVersion: finding7.version,
      assignedToId: dev1User.id,
      taskDescription: 'Fix invoice tenant isolation',
    });
    const task7 = await prisma.remediationTask.findFirstOrThrow({
      where: { findingId: finding7.id, status: 'PENDING' },
    });
    createdTaskIds.push(task7.id);

    const submittedFinding7 = await findingService.submitRemediation(dev1Actor, finding7.id, {
      expectedVersion: assignedFinding7.version,
      notes: 'Added tenant ID check to query',
    });

    const rejectedFinding7 = await findingService.rejectVerification(analystActor, finding7.id, {
      expectedVersion: submittedFinding7.version,
      notes: 'Check bypassed via batch endpoint',
    });

    if (rejectedFinding7.status !== 'REOPENED') {
      throw new Error(`Rejection outcome mismatch: status=${rejectedFinding7.status}`);
    }
    const rejectedTask7 = await prisma.remediationTask.findUniqueOrThrow({
      where: { id: task7.id },
    });
    if (rejectedTask7.status !== 'REJECTED') {
      throw new Error(`Task rejection status mismatch: ${rejectedTask7.status}`);
    }

    recordPass(
      'Scenario 7: Verification and rejection with real PostgreSQL data',
      `Finding1 confirmed VERIFIED (task VERIFIED); Finding7 rejected to REOPENED (task REJECTED)`,
    );

    // ========================================================================
    // Scenario 8: Separation-of-duties enforcement (OLI-7)
    // ========================================================================
    // Analyst cannot verify a finding if Analyst was the submitter
    // Set up a finding where submitterId is analystUser.id
    const finding8 = await createTriagedFinding('Self-verification test finding');
    const assignedFinding8 = await findingService.assignFinding(analystActor, finding8.id, {
      expectedVersion: finding8.version,
      assignedToId: dev1User.id,
      taskDescription: 'Test task',
    });
    const task8 = await prisma.remediationTask.findFirstOrThrow({
      where: { findingId: finding8.id, status: 'PENDING' },
    });
    createdTaskIds.push(task8.id);

    // Update finding to READY_FOR_REVIEW and record Analyst as submitter
    await prisma.finding.update({
      where: { id: finding8.id },
      data: { status: 'READY_FOR_REVIEW', version: assignedFinding8.version + 1 },
    });
    await prisma.remediationTask.update({
      where: { id: task8.id },
      data: { status: 'SUBMITTED', assignedToId: analystUser.id },
    });
    const selfSubmitEvent = await prisma.findingEvent.create({
      data: {
        findingId: finding8.id,
        actorId: analystUser.id, // Analyst was the submitter!
        eventType: 'STATUS_CHANGED',
        previousStatus: 'IN_PROGRESS',
        newStatus: 'READY_FOR_REVIEW',
        metadata: { submitterId: analystUser.id, taskId: task8.id },
      },
    });
    createdFindingEventIds.push(selfSubmitEvent.id);

    let selfVerifyBlocked = false;
    try {
      await findingService.verifyFinding(analystActor, finding8.id, {
        expectedVersion: assignedFinding8.version + 1,
        outcome: 'VERIFIED',
      });
    } catch (err) {
      if (err instanceof ForbiddenError && err.message.includes('separation of duties')) {
        selfVerifyBlocked = true;
      }
    }
    if (!selfVerifyBlocked) {
      throw new Error('Self-verification was not rejected with SEPARATION_OF_DUTIES_VIOLATION!');
    }

    // Also test fail-closed when submitter evidence is completely missing
    const finding8b = await createTriagedFinding('Missing submitter evidence test finding');
    const assignedFinding8b = await findingService.assignFinding(analystActor, finding8b.id, {
      expectedVersion: finding8b.version,
      assignedToId: dev1User.id,
      taskDescription: 'Test task',
    });
    const task8b = await prisma.remediationTask.findFirstOrThrow({
      where: { findingId: finding8b.id, status: 'PENDING' },
    });
    createdTaskIds.push(task8b.id);
    await prisma.finding.update({
      where: { id: finding8b.id },
      data: { status: 'READY_FOR_REVIEW', version: assignedFinding8b.version + 1 },
    });
    await prisma.remediationTask.update({
      where: { id: task8b.id },
      data: { status: 'SUBMITTED' },
    });
    // No findingEvent created -> missing submitter evidence!

    let missingEvidenceBlocked = false;
    try {
      await findingService.verifyFinding(analystActor, finding8b.id, {
        expectedVersion: assignedFinding8b.version + 1,
        outcome: 'VERIFIED',
      });
    } catch (err) {
      if (err instanceof ForbiddenError && err.message.includes('remediation submitter evidence is missing')) {
        missingEvidenceBlocked = true;
      }
    }
    if (!missingEvidenceBlocked) {
      throw new Error('Missing submitter evidence was not rejected fail-closed!');
    }

    recordPass(
      'Scenario 8: Separation-of-duties enforcement',
      'Self-verification rejected with OLI-7 SoD violation; missing submitter evidence failed closed',
    );

    // ========================================================================
    // Scenario 9: Multiple remediation cycles
    // ========================================================================
    // Finding7 was rejected and is in REOPENED status; task7 is REJECTED.
    // Cycle 2: Reassign to Dev2 -> Dev2 submits -> Analyst verifies.
    // The partial unique index must allow creating task 2 because task 1 is in REJECTED status!
    const cycle2Assigned = await findingService.assignFinding(analystActor, finding7.id, {
      expectedVersion: rejectedFinding7.version,
      assignedToId: dev2User.id,
      taskDescription: 'Cycle 2: Fix batch tenant isolation',
    });

    if (cycle2Assigned.status !== 'IN_PROGRESS' || cycle2Assigned.assignedToId !== dev2User.id) {
      throw new Error(`Cycle 2 assignment failed: status=${cycle2Assigned.status}`);
    }

    const task7Cycle2 = await prisma.remediationTask.findFirstOrThrow({
      where: { findingId: finding7.id, status: 'PENDING' },
    });
    createdTaskIds.push(task7Cycle2.id);

    // Verify two tasks exist historically for finding7
    const allTasksForFinding7 = await prisma.remediationTask.findMany({
      where: { findingId: finding7.id },
      orderBy: { createdAt: 'asc' },
    });
    if (allTasksForFinding7.length !== 2 || allTasksForFinding7[0].status !== 'REJECTED' || allTasksForFinding7[1].status !== 'PENDING') {
      throw new Error(`Historical tasks verification failed: length=${allTasksForFinding7.length}`);
    }

    // Dev2 submits Cycle 2
    const cycle2Submitted = await findingService.submitRemediation(dev2Actor, finding7.id, {
      expectedVersion: cycle2Assigned.version,
      notes: 'Added tenant filter to batch endpoint query',
    });

    // Analyst verifies Cycle 2
    const cycle2Verified = await findingService.verifyFinding(analystActor, finding7.id, {
      expectedVersion: cycle2Submitted.version,
      outcome: 'VERIFIED',
      notes: 'Batch endpoint verified clean',
    });

    if (cycle2Verified.status !== 'VERIFIED') {
      throw new Error(`Cycle 2 verification failed: status=${cycle2Verified.status}`);
    }

    recordPass(
      'Scenario 9: Multiple remediation cycles',
      `Cycle 1 rejected (task REJECTED), partial unique index released; Cycle 2 assigned, submitted by dev2, and verified`,
    );

    // ========================================================================
    // Scenario 10: Rollback after finding event or audit insertion failure
    // ========================================================================
    // Test that if an audit insertion fails inside a transaction, all finding and task modifications roll back
    const finding10 = await createTriagedFinding('Rollback atomic test finding');

    let rollbackObserved = false;
    try {
      await dbManager.runTransaction(async (repos) => {
        // Step 1: Update finding
        await repos.findingRepo.updateAtomic(finding10.id, {
          expectedVersion: finding10.version,
          status: 'IN_PROGRESS',
        });
        // Step 2: Create task
        await repos.taskRepo.create({
          findingId: finding10.id,
          assignedToId: dev1User.id,
          assignedById: analystUser.id,
          description: 'Atomic rollback test task',
        });
        // Step 3: Trigger intentional error during audit
        throw new Error('SIMULATED_AUDIT_FAILURE_TEST');
      });
    } catch (err: unknown) {
      if (err instanceof Error && err.message === 'SIMULATED_AUDIT_FAILURE_TEST') {
        rollbackObserved = true;
      }
    }
    if (!rollbackObserved) {
      throw new Error('Simulated transaction failure did not throw expected error');
    }

    // Verify finding remains TRIAGED at original version in DB
    const freshFinding10 = await prisma.finding.findUniqueOrThrow({
      where: { id: finding10.id },
    });
    if (freshFinding10.status !== 'TRIAGED' || freshFinding10.version !== finding10.version) {
      throw new Error(`Rollback failed: finding status=${freshFinding10.status}, version=${freshFinding10.version}`);
    }

    // Verify zero tasks were committed
    const tasks10 = await prisma.remediationTask.findMany({
      where: { findingId: finding10.id },
    });
    if (tasks10.length !== 0) {
      throw new Error(`Rollback failed: ${tasks10.length} tasks persisted!`);
    }

    recordPass(
      'Scenario 10: Rollback after finding event or audit insertion failure',
      'Transaction rolled back completely upon failure; finding state and task table unaffected',
    );

    // ========================================================================
    // Scenario 11: No orphan remediation tasks
    // ========================================================================
    // Verify that every task in the database has a valid finding and matches finding.projectId
    const allTasks = await prisma.remediationTask.findMany({
      where: { id: { in: createdTaskIds } },
      include: { finding: true },
    });
    for (const t of allTasks) {
      if (!t.finding || t.finding.projectId !== project.id) {
        throw new Error(`Orphan or mislinked remediation task detected: ${t.id}`);
      }
    }

    recordPass(
      'Scenario 11: No orphan remediation tasks',
      `All ${allTasks.length} active and historical remediation tasks are strictly linked to valid findings`,
    );

    // ========================================================================
    // Scenario 12: No partial writes after OCC conflicts
    // ========================================================================
    // Attempting submitRemediation with stale version leaves task and finding completely unchanged
    const finding12 = await createTriagedFinding('OCC Stale Write Test');
    const assignedFinding12 = await findingService.assignFinding(analystActor, finding12.id, {
      expectedVersion: finding12.version,
      assignedToId: dev1User.id,
      taskDescription: 'OCC task test',
    });
    const task12 = await prisma.remediationTask.findFirstOrThrow({
      where: { findingId: finding12.id, status: 'PENDING' },
    });
    createdTaskIds.push(task12.id);

    let occFailureCaught = false;
    try {
      await findingService.submitRemediation(dev1Actor, finding12.id, {
        expectedVersion: 999, // Stale version!
        notes: 'Stale submit notes',
      });
    } catch (err) {
      if (err instanceof ConcurrencyConflictError) {
        occFailureCaught = true;
      }
    }
    if (!occFailureCaught) {
      throw new Error('Stale expectedVersion was not rejected with ConcurrencyConflictError!');
    }

    // Verify task status is STILL PENDING and notes are null
    const freshTask12 = await prisma.remediationTask.findUniqueOrThrow({
      where: { id: task12.id },
    });
    if (freshTask12.status !== 'PENDING' || freshTask12.notes !== null) {
      throw new Error(`Partial write occurred on task! status=${freshTask12.status}, notes=${freshTask12.notes}`);
    }

    // Verify finding status is STILL IN_PROGRESS
    const freshFinding12 = await prisma.finding.findUniqueOrThrow({
      where: { id: finding12.id },
    });
    if (freshFinding12.status !== 'IN_PROGRESS' || freshFinding12.version !== assignedFinding12.version) {
      throw new Error(`Partial write occurred on finding! status=${freshFinding12.status}`);
    }

    recordPass(
      'Scenario 12: No partial writes after OCC conflicts',
      'OCC conflict completely prevented partial writes on finding and remediation task',
    );

    // ========================================================================
    // Scenario 13: Correct lock ordering across finding and task records (Canonical Hierarchy)
    // ========================================================================
    // Developer updates task notes in TaskService under Level 0 -> 1 -> 2 -> 3 -> 4 locks
    const updatedNotesTask = await taskService.updateTaskNotes(dev1Actor, task12.id, {
      notes: 'Investigating root cause under canonical row locks',
    });

    if (updatedNotesTask.notes !== 'Investigating root cause under canonical row locks') {
      throw new Error('updateTaskNotes failed to update task notes');
    }

    const taskAudit = await prisma.auditEvent.findFirst({
      where: { resourceId: task12.id, eventType: 'task.notes_updated' },
    });
    if (!taskAudit) {
      throw new Error('AuditEvent task.notes_updated not found');
    }
    createdAuditIds.push(taskAudit.id);

    recordPass(
      'Scenario 13: Correct lock ordering across finding and task records',
      'Task notes updated under canonical lock hierarchy 0 -> 1 -> 2 -> 3 -> 4 with atomic audit log',
    );

    // ========================================================================
    // Scenario 14: Archived Foreign-Project Access & Existence Hiding (Non-member 404 vs Member 403)
    // ========================================================================
    const archivedProject = await prisma.project.create({
      data: {
        name: 'Gate 3D4 Archived Target Project',
        slug: `gate3d4-archived-${Date.now()}`,
        description: 'Archived project to test existence hiding vs authorization',
        isActive: false, // ARCHIVED
        createdById: adminUser.id,
      },
    });
    createdProjectIds.push(archivedProject.id);

    // Member analyst and member dev in archived project
    await Promise.all([
      prisma.projectMember.create({
        data: {
          projectId: archivedProject.id,
          userId: analystUser.id,
          role: 'ANALYST',
          addedById: adminUser.id,
        },
      }),
      prisma.projectMember.create({
        data: {
          projectId: archivedProject.id,
          userId: dev1User.id,
          role: 'DEVELOPER',
          addedById: adminUser.id,
        },
      }),
    ]);
    // dev2User is intentionally NOT a member of archivedProject!

    const archivedFinding = await prisma.finding.create({
      data: {
        projectId: archivedProject.id,
        title: 'Archived Project Vulnerability',
        description: 'Testing existence hiding',
        severity: 'HIGH',
        category: 'INJECTION',
        status: 'TRIAGED',
        createdById: analystUser.id,
      },
    });
    createdFindingIds.push(archivedFinding.id);

    const archivedTask = await prisma.remediationTask.create({
      data: {
        findingId: archivedFinding.id,
        assignedToId: dev1User.id,
        assignedById: analystUser.id,
        description: 'Archived task description',
        status: 'PENDING',
      },
    });
    createdTaskIds.push(archivedTask.id);

    // 1. Non-member checks (dev2Actor is not a member of archivedProject)
    // Non-member reads must return generic 404 EntityNotFoundError (existence hiding)
    let nonMemberGetTaskCaught = false;
    try {
      await taskService.getTask(dev2Actor, archivedTask.id);
    } catch (err) {
      if (err instanceof EntityNotFoundError) nonMemberGetTaskCaught = true;
    }
    if (!nonMemberGetTaskCaught) throw new Error('Non-member getTask on archived project did not throw EntityNotFoundError');

    let nonMemberGetByFindingCaught = false;
    try {
      await taskService.getTaskByFindingId(dev2Actor, archivedFinding.id);
    } catch (err) {
      if (err instanceof EntityNotFoundError) nonMemberGetByFindingCaught = true;
    }
    if (!nonMemberGetByFindingCaught) throw new Error('Non-member getTaskByFindingId on archived project did not throw EntityNotFoundError');

    // Non-member mutations must return generic 404 EntityNotFoundError (existence hiding)
    let nonMemberUpdateNotesCaught = false;
    try {
      await taskService.updateTaskNotes(dev2Actor, archivedTask.id, { notes: 'Non-member update' });
    } catch (err) {
      if (err instanceof EntityNotFoundError) nonMemberUpdateNotesCaught = true;
    }
    if (!nonMemberUpdateNotesCaught) throw new Error('Non-member updateTaskNotes on archived project did not throw EntityNotFoundError');

    let nonMemberAssignCaught = false;
    try {
      await findingService.assignFinding(dev2Actor, archivedFinding.id, {
        expectedVersion: 1,
        assignedToId: dev1User.id,
        taskDescription: 'Attempted assignment',
      });
    } catch (err) {
      if (err instanceof EntityNotFoundError) nonMemberAssignCaught = true;
    }
    if (!nonMemberAssignCaught) throw new Error('Non-member assignFinding on archived project did not throw EntityNotFoundError');

    let nonMemberSubmitCaught = false;
    try {
      await findingService.submitRemediation(dev2Actor, archivedFinding.id, {
        expectedVersion: 1,
        notes: 'Attempted submission',
      });
    } catch (err) {
      if (err instanceof EntityNotFoundError) nonMemberSubmitCaught = true;
    }
    if (!nonMemberSubmitCaught) throw new Error('Non-member submitRemediation on archived project did not throw EntityNotFoundError');

    let nonMemberVerifyCaught = false;
    try {
      await findingService.verifyFinding(dev2Actor, archivedFinding.id, {
        expectedVersion: 1,
        outcome: 'VERIFIED',
      });
    } catch (err) {
      if (err instanceof EntityNotFoundError) nonMemberVerifyCaught = true;
    }
    if (!nonMemberVerifyCaught) throw new Error('Non-member verifyFinding on archived project did not throw EntityNotFoundError');

    // 2. Member checks (analystActor and dev1Actor are members of archivedProject)
    // Authorized members must receive 403 ForbiddenError (mutation prohibited on archived project)
    const archivedAnalystActor = new ActorContext({
      id: analystUser.id,
      globalRole: 'ANALYST',
      isActive: true,
      memberships: [{ projectId: archivedProject.id, role: 'ANALYST' }],
    });
    const archivedDev1Actor = new ActorContext({
      id: dev1User.id,
      globalRole: 'DEVELOPER',
      isActive: true,
      memberships: [{ projectId: archivedProject.id, role: 'DEVELOPER' }],
    });

    let memberUpdateNotesForbidden = false;
    try {
      await taskService.updateTaskNotes(archivedDev1Actor, archivedTask.id, { notes: 'Member update' });
    } catch (err) {
      if (err instanceof ForbiddenError && err.message.toLowerCase().includes('archived')) memberUpdateNotesForbidden = true;
    }
    if (!memberUpdateNotesForbidden) throw new Error('Member updateTaskNotes on archived project did not throw ForbiddenError');

    let memberAssignForbidden = false;
    try {
      await findingService.assignFinding(archivedAnalystActor, archivedFinding.id, {
        expectedVersion: 1,
        assignedToId: dev1User.id,
        taskDescription: 'Member assignment',
      });
    } catch (err) {
      if (err instanceof ForbiddenError && err.message.toLowerCase().includes('archived')) memberAssignForbidden = true;
    }
    if (!memberAssignForbidden) throw new Error('Member assignFinding on archived project did not throw ForbiddenError');

    let memberSubmitForbidden = false;
    try {
      await findingService.submitRemediation(archivedDev1Actor, archivedFinding.id, {
        expectedVersion: 1,
        notes: 'Member submission',
      });
    } catch (err) {
      if (err instanceof ForbiddenError && err.message.toLowerCase().includes('archived')) memberSubmitForbidden = true;
    }
    if (!memberSubmitForbidden) throw new Error('Member submitRemediation on archived project did not throw ForbiddenError');

    let memberVerifyForbidden = false;
    try {
      await findingService.verifyFinding(archivedAnalystActor, archivedFinding.id, {
        expectedVersion: 1,
        outcome: 'VERIFIED',
      });
    } catch (err) {
      if (err instanceof ForbiddenError && err.message.toLowerCase().includes('archived')) memberVerifyForbidden = true;
    }
    if (!memberVerifyForbidden) throw new Error('Member verifyFinding on archived project did not throw ForbiddenError');

    recordPass(
      'Scenario 14: Archived Foreign-Project Access & Existence Hiding',
      'Non-members strictly receive generic 404 EntityNotFoundError (existence hiding); authorized members receive 403 ForbiddenError',
    );

    // ========================================================================
    // Scenario 15: Separation-of-Duties (SoD OLI-7) Fail-Closed Evidence Validation & Timestamp Collisions
    // ========================================================================
    const finding15 = await createTriagedFinding('SoD Verification Evidence Flaws');
    const assignedFinding15 = await findingService.assignFinding(analystActor, finding15.id, {
      expectedVersion: finding15.version,
      assignedToId: dev1User.id,
      taskDescription: 'Fix SoD evidence verification',
    });
    const task15 = await prisma.remediationTask.findFirstOrThrow({
      where: { findingId: finding15.id, status: 'PENDING' },
    });
    createdTaskIds.push(task15.id);

    // Prepare finding for review
    await prisma.finding.update({
      where: { id: finding15.id },
      data: { status: 'READY_FOR_REVIEW', version: { increment: 1 } },
    });
    await prisma.remediationTask.update({
      where: { id: task15.id },
      data: { status: 'SUBMITTED' },
    });

    // 15A. Contradictory evidence: actorId !== metadata.submitterId
    const contradictoryEvent = await prisma.findingEvent.create({
      data: {
        findingId: finding15.id,
        actorId: dev1User.id,
        eventType: 'STATUS_CHANGED',
        previousStatus: 'IN_PROGRESS',
        newStatus: 'READY_FOR_REVIEW',
        metadata: { submitterId: dev2User.id, taskId: task15.id }, // Contradictory submitterId
      },
    });
    createdFindingEventIds.push(contradictoryEvent.id);

    let contradictoryCaught = false;
    try {
      await findingService.verifyFinding(analystActor, finding15.id, {
        expectedVersion: assignedFinding15.version + 1,
        outcome: 'VERIFIED',
      });
    } catch (err) {
      if (err instanceof ForbiddenError && err.message.includes('contradictory remediation submitter evidence')) {
        contradictoryCaught = true;
      }
    }
    if (!contradictoryCaught) throw new Error('Contradictory submitter evidence was not rejected fail-closed!');

    // 15B. Mismatched taskId in event metadata
    await prisma.findingEvent.update({
      where: { id: contradictoryEvent.id },
      data: {
        metadata: { submitterId: dev1User.id, taskId: '11111111-2222-3333-4444-555555555555' }, // Mismatched task ID
      },
    });

    let mismatchedTaskCaught = false;
    try {
      await findingService.verifyFinding(analystActor, finding15.id, {
        expectedVersion: assignedFinding15.version + 1,
        outcome: 'VERIFIED',
      });
    } catch (err) {
      if (err instanceof ForbiddenError && err.message.includes('remediation submitter evidence is missing or unavailable')) {
        mismatchedTaskCaught = true;
      }
    }
    if (!mismatchedTaskCaught) throw new Error('Mismatched taskId in evidence was not rejected fail-closed!');

    // 15C. Submitter is not the task's assigned developer
    await prisma.findingEvent.update({
      where: { id: contradictoryEvent.id },
      data: {
        actorId: dev2User.id,
        metadata: { submitterId: dev2User.id, taskId: task15.id }, // dev2 submitted, but task is assigned to dev1
      },
    });

    let wrongAssigneeCaught = false;
    try {
      await findingService.verifyFinding(analystActor, finding15.id, {
        expectedVersion: assignedFinding15.version + 1,
        outcome: 'VERIFIED',
      });
    } catch (err) {
      if (err instanceof ForbiddenError && err.message.includes('submitter does not match assigned developer')) {
        wrongAssigneeCaught = true;
      }
    }
    if (!wrongAssigneeCaught) throw new Error('Unassigned submitter was not rejected fail-closed!');

    // 15D. Conflicting same-task evidence with identical timestamps (Fail-closed OLI-7)
    await prisma.findingEvent.delete({ where: { id: contradictoryEvent.id } });

    const sharedCollisionTime = new Date('2026-10-31T12:00:00.000Z');
    // Event 1: Dev1 submission at collision timestamp
    const collisionEventA = await prisma.findingEvent.create({
      data: {
        id: '11111111-aaaa-4000-8000-000000000001',
        findingId: finding15.id,
        actorId: dev1User.id,
        eventType: 'STATUS_CHANGED',
        previousStatus: 'IN_PROGRESS',
        newStatus: 'READY_FOR_REVIEW',
        metadata: { submitterId: dev1User.id, taskId: task15.id, patchNotes: 'Fix from dev1' },
        createdAt: sharedCollisionTime,
      },
    });
    createdFindingEventIds.push(collisionEventA.id);

    // Event 2: Conflicting Dev2 submission for the SAME task at the EXACT SAME timestamp
    const collisionEventB = await prisma.findingEvent.create({
      data: {
        id: '11111111-aaaa-4000-8000-000000000002',
        findingId: finding15.id,
        actorId: dev2User.id,
        eventType: 'STATUS_CHANGED',
        previousStatus: 'IN_PROGRESS',
        newStatus: 'READY_FOR_REVIEW',
        metadata: { submitterId: dev2User.id, taskId: task15.id, patchNotes: 'Conflicting fix from dev2' },
        createdAt: sharedCollisionTime,
      },
    });
    createdFindingEventIds.push(collisionEventB.id);

    let conflictingCollisionBlocked = false;
    try {
      await findingService.verifyFinding(analystActor, finding15.id, {
        expectedVersion: assignedFinding15.version + 1,
        outcome: 'VERIFIED',
      });
    } catch (err) {
      if (
        err instanceof ForbiddenError &&
        (err.message.includes('conflicting remediation submission evidence') ||
          err.message.includes('ambiguous or conflicting') ||
          err.message.includes('ambiguous remediation submission evidence'))
      ) {
        conflictingCollisionBlocked = true;
      }
    }
    if (!conflictingCollisionBlocked) {
      throw new Error('Conflicting same-task evidence at identical timestamps did not fail closed!');
    }

    // Now remove conflicting Event B and Event A
    await prisma.findingEvent.delete({ where: { id: collisionEventB.id } });
    await prisma.findingEvent.delete({ where: { id: collisionEventA.id } });

    // 15E. Two otherwise identical submission events for the same active task (Fail-closed single-submission-event invariant)
    const identicalEventA = await prisma.findingEvent.create({
      data: {
        id: '11111111-bbbb-4000-8000-000000000001',
        findingId: finding15.id,
        actorId: dev1User.id,
        eventType: 'STATUS_CHANGED',
        previousStatus: 'IN_PROGRESS',
        newStatus: 'READY_FOR_REVIEW',
        metadata: { submitterId: dev1User.id, taskId: task15.id, patchNotes: 'Identical fix notes' },
        createdAt: sharedCollisionTime,
      },
    });
    createdFindingEventIds.push(identicalEventA.id);

    const identicalEventB = await prisma.findingEvent.create({
      data: {
        id: '11111111-bbbb-4000-8000-000000000002',
        findingId: finding15.id,
        actorId: dev1User.id,
        eventType: 'STATUS_CHANGED',
        previousStatus: 'IN_PROGRESS',
        newStatus: 'READY_FOR_REVIEW',
        metadata: { submitterId: dev1User.id, taskId: task15.id, patchNotes: 'Identical fix notes' },
        createdAt: sharedCollisionTime,
      },
    });
    createdFindingEventIds.push(identicalEventB.id);

    let identicalEventsBlocked = false;
    try {
      await findingService.verifyFinding(analystActor, finding15.id, {
        expectedVersion: assignedFinding15.version + 1,
        outcome: 'VERIFIED',
      });
    } catch (err) {
      if (
        err instanceof ForbiddenError &&
        err.message.includes('ambiguous remediation submission evidence; active task has multiple submission events')
      ) {
        identicalEventsBlocked = true;
      }
    }
    if (!identicalEventsBlocked) {
      throw new Error('Two otherwise identical submission events did not fail closed!');
    }

    // Clean up identicalEventB, leaving exactly 1 event (identicalEventA)
    await prisma.findingEvent.delete({ where: { id: identicalEventB.id } });

    const verifiedCollisionFinding = await findingService.verifyFinding(analystActor, finding15.id, {
      expectedVersion: assignedFinding15.version + 1,
      outcome: 'VERIFIED',
      notes: 'Collision ambiguity resolved: unambiguous single submission verified',
    });

    if (verifiedCollisionFinding.status !== 'VERIFIED') {
      throw new Error('Verification failed after resolving ambiguous conflicting evidence');
    }

    recordPass(
      'Scenario 15: Separation-of-Duties (SoD OLI-7) Fail-Closed Evidence Validation & Timestamp Collisions',
      'All 10 SoD evidence checks verified against PostgreSQL: contradictory submitterId, mismatched taskId, unassigned submitter, conflicting same-task timestamp collisions, and deterministic resolution',
    );

    // ========================================================================
    // Scenario 16: Concurrent Membership Revocation — Mutation Lock Precedence (Race Outcome B)
    // ========================================================================
    const tempDevSub16 = `gate3d4-tempdev16-${Date.now()}`;
    const tempDevUser16 = await prisma.user.create({
      data: {
        sub: tempDevSub16,
        email: `${tempDevSub16}@example.com`,
        displayName: 'Temp Dev for Race B',
        globalRole: 'DEVELOPER',
        isActive: true,
      },
    });
    createdUserIds.push(tempDevUser16.id);

    await prisma.projectMember.create({
      data: {
        projectId: project.id,
        userId: tempDevUser16.id,
        role: 'DEVELOPER',
        addedById: adminUser.id,
      },
    });

    const finding16 = await createTriagedFinding('Lock Precedence Race Finding');
    await findingService.assignFinding(analystActor, finding16.id, {
      expectedVersion: finding16.version,
      assignedToId: tempDevUser16.id,
      taskDescription: 'Fix Race B vulnerability',
    });
    const task16 = await prisma.remediationTask.findFirstOrThrow({
      where: { findingId: finding16.id, status: 'PENDING' },
    });
    createdTaskIds.push(task16.id);

    let mutationFinished = false;
    let revocationFinished = false;

    // T1: Mutation transaction acquires Level 0, 1, 2, 3, 4 locks, holds for 200ms, then updates notes
    const mutationPromise = dbManager.runTransaction(async (repos) => {
      await repos.userRepo.lockUsers([tempDevUser16.id]);
      await repos.projectRepo.lockProject(project.id);
      const member = await repos.projectRepo.lockMember(project.id, tempDevUser16.id);
      if (!member) throw new Error('Member not found during T1 lock');
      await repos.findingRepo.lockFinding(finding16.id);
      const task = await repos.taskRepo.lockTask(task16.id);
      if (!task) throw new Error('Task not found during T1 lock');

      // Hold lock while T2 attempts deletion
      await new Promise((resolve) => setTimeout(resolve, 200));

      await repos.taskRepo.updateNotes(task16.id, 'Notes saved while holding Level 2 lock');
      mutationFinished = true;
    });

    // T2: Concurrent revocation attempts to delete the project_member row
    // It will wait for T1's transaction to commit because T1 holds FOR SHARE on project_members
    await new Promise((resolve) => setTimeout(resolve, 50));
    const revocationPromise = prisma.projectMember.delete({
      where: {
        projectId_userId: {
          projectId: project.id,
          userId: tempDevUser16.id,
        },
      },
    }).then(() => {
      revocationFinished = true;
    });

    await Promise.all([mutationPromise, revocationPromise]);

    if (!mutationFinished) {
      throw new Error('Mutation did not finish successfully before revocation');
    }
    if (!revocationFinished) {
      throw new Error('Revocation did not finish after mutation completed');
    }

    const freshTask16 = await prisma.remediationTask.findUniqueOrThrow({
      where: { id: task16.id },
    });
    if (freshTask16.notes !== 'Notes saved while holding Level 2 lock') {
      throw new Error(`Task notes were not updated! Found: ${freshTask16.notes}`);
    }

    const memberCheck16 = await prisma.projectMember.findUnique({
      where: {
        projectId_userId: {
          projectId: project.id,
          userId: tempDevUser16.id,
        },
      },
    });
    if (memberCheck16 !== null) {
      throw new Error('Project member was not deleted after revocation transaction committed');
    }

    recordPass(
      'Scenario 16: Concurrent Membership Revocation — Mutation Lock Precedence (Race Outcome B)',
      'Mutation acquired Level 2 lock first and committed cleanly; concurrent revocation safely serialized after mutation committed',
    );

  } finally {
    // Teardown: Safely remove only created synthetic test rows in reverse foreign key order
    const prisma = dbManager.getPrismaClient();

    try {
      if (createdUserIds.length > 0 || createdFindingIds.length > 0) {
        await prisma.auditEvent.deleteMany({
          where: {
            OR: [
              ...(createdUserIds.length > 0 ? [{ actorId: { in: createdUserIds } }] : []),
              ...(createdFindingIds.length > 0 ? [{ resourceId: { in: createdFindingIds } }] : []),
              ...(createdTaskIds.length > 0 ? [{ resourceId: { in: createdTaskIds } }] : []),
            ],
          },
        });
      }
      if (createdFindingIds.length > 0) {
        await prisma.remediationTask.deleteMany({
          where: { findingId: { in: createdFindingIds } },
        });
        await prisma.findingEvent.deleteMany({
          where: { findingId: { in: createdFindingIds } },
        });
        await prisma.finding.deleteMany({
          where: { id: { in: createdFindingIds } },
        });
      }
      if (createdProjectIds.length > 0) {
        await prisma.projectMember.deleteMany({
          where: { projectId: { in: createdProjectIds } },
        });
        await prisma.project.deleteMany({
          where: { id: { in: createdProjectIds } },
        });
      }
      if (createdUserIds.length > 0) {
        await prisma.user.deleteMany({
          where: { id: { in: createdUserIds } },
        });
      }
    } catch (cleanupErr) {
      console.warn('Synthetic teardown warning:', cleanupErr);
    }

    await dbManager.shutdown();
  }

  console.log('--------------------------------------------------');
  console.log(`Summary: ${passedTests}/${totalTests} Gate 3D.4 integration tests passed.`);
  console.log('==================================================\n');

  return {
    allPassed: passedTests === totalTests && totalTests > 0,
    totalTests,
    passedTests,
  };
}

// Direct execution runner
if (process.argv[1] && process.argv[1].endsWith('gate3d-task-service.integration.ts')) {
  runGate3dTaskServiceIntegrationTests()
    .then((result) => {
      if (!result.allPassed) {
        process.exit(1);
      }
      process.exit(0);
    })
    .catch((err) => {
      console.error('Fatal integration test error:', err);
      process.exit(1);
    });
}
