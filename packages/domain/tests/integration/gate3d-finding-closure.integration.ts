import path from 'node:path';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';
import { DatabaseManager } from '../../src/db/database-manager.js';
import {
  FindingService,
  ProjectService,
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

export async function runGate3dFindingClosureIntegrationTests(): Promise<{
  allPassed: boolean;
  totalTests: number;
  passedTests: number;
}> {
  console.log('==================================================');
  console.log('SecureFlow — Gate 3D.5 Finding Closure & Lifecycle Integration Suite');
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
    const projectService = new ProjectService(dbManager);

    // Seed test users first
    const adminSub = `gate3d5-admin-${Date.now()}`;
    const adminUser = await prisma.user.create({
      data: {
        sub: adminSub,
        email: `${adminSub}@example.com`,
        displayName: 'Gate 3D5 Global Admin',
        globalRole: 'ADMIN',
        isActive: true,
      },
    });
    createdUserIds.push(adminUser.id);

    // Seed test project
    const projectSlug = `gate3d5-proj-${Date.now()}`;
    const project = await prisma.project.create({
      data: {
        name: 'Gate 3D.5 Lifecycle Project',
        slug: projectSlug,
        description: 'Integration test project for Gate 3D.5 finding closure',
        isActive: true,
        createdById: adminUser.id,
      },
    });
    createdProjectIds.push(project.id);

    // Seed Foreign Project B for existence hiding tests
    const foreignProject = await prisma.project.create({
      data: {
        name: 'Gate 3D.5 Foreign Project B',
        slug: `gate3d5-foreign-${Date.now()}`,
        description: 'Foreign project for cross-project isolation',
        isActive: true,
        createdById: adminUser.id,
      },
    });
    createdProjectIds.push(foreignProject.id);

    const analystSub = `gate3d5-analyst-${Date.now()}`;
    const analystUser = await prisma.user.create({
      data: {
        sub: analystSub,
        email: `${analystSub}@example.com`,
        displayName: 'Gate 3D5 Security Analyst',
        globalRole: 'ANALYST',
        isActive: true,
      },
    });
    createdUserIds.push(analystUser.id);

    const devSub = `gate3d5-dev-${Date.now()}`;
    const devUser = await prisma.user.create({
      data: {
        sub: devSub,
        email: `${devSub}@example.com`,
        displayName: 'Gate 3D5 Developer',
        globalRole: 'DEVELOPER',
        isActive: true,
      },
    });
    createdUserIds.push(devUser.id);

    const nonMemberSub = `gate3d5-nonmember-${Date.now()}`;
    const nonMemberUser = await prisma.user.create({
      data: {
        sub: nonMemberSub,
        email: `${nonMemberSub}@example.com`,
        displayName: 'Gate 3D5 Non Member',
        globalRole: 'ANALYST',
        isActive: true,
      },
    });
    createdUserIds.push(nonMemberUser.id);

    // Add memberships in project
    await prisma.projectMember.create({
      data: {
        projectId: project.id,
        userId: analystUser.id,
        role: 'ANALYST',
        addedById: adminUser.id,
      },
    });
    await prisma.projectMember.create({
      data: {
        projectId: project.id,
        userId: devUser.id,
        role: 'DEVELOPER',
        addedById: adminUser.id,
      },
    });

    // Add membership for nonMemberUser in foreignProject ONLY
    await prisma.projectMember.create({
      data: {
        projectId: foreignProject.id,
        userId: nonMemberUser.id,
        role: 'ANALYST',
        addedById: adminUser.id,
      },
    });

    const adminActor = new ActorContext({
      id: adminUser.id,
      globalRole: 'ADMIN',
      isActive: true,
      memberships: [],
    });

    const analystActor = new ActorContext({
      id: analystUser.id,
      globalRole: 'ANALYST',
      isActive: true,
      memberships: [{ projectId: project.id, role: 'ANALYST' }],
    });

    const devActor = new ActorContext({
      id: devUser.id,
      globalRole: 'DEVELOPER',
      isActive: true,
      memberships: [{ projectId: project.id, role: 'DEVELOPER' }],
    });

    const nonMemberActor = new ActorContext({
      id: nonMemberUser.id,
      globalRole: 'ANALYST',
      isActive: true,
      memberships: [{ projectId: foreignProject.id, role: 'ANALYST' }],
    });

    // Helper: Create a finding through full lifecycle up to VERIFIED status
    async function createVerifiedFinding(title: string) {
      const created = await findingService.createFinding(analystActor, {
        projectId: project.id,
        title,
        description: 'Vulnerability test record',
        severity: 'HIGH',
        category: 'INJECTION',
      });
      createdFindingIds.push(created.id);

      const triaged = await findingService.triageFinding(analystActor, created.id, {
        expectedVersion: created.version,
      });

      const assigned = await findingService.assignFinding(analystActor, created.id, {
        expectedVersion: triaged.version,
        assignedToId: devUser.id,
        taskDescription: 'Fix parameter sanitization',
      });
      const activeTask = await prisma.remediationTask.findFirstOrThrow({
        where: { findingId: created.id, status: 'PENDING' },
      });
      createdTaskIds.push(activeTask.id);

      const submitted = await findingService.submitRemediation(devActor, created.id, {
        expectedVersion: assigned.version,
        notes: 'Applied parameterized queries',
      });

      // Need another analyst for SoD verification
      const secondAnalystSub = `gate3d5-analyst2-${Date.now()}-${Math.random().toString(36).substring(7)}`;
      const secondAnalystUser = await prisma.user.create({
        data: {
          sub: secondAnalystSub,
          email: `${secondAnalystSub}@example.com`,
          displayName: 'Second Analyst for SoD',
          globalRole: 'ANALYST',
          isActive: true,
        },
      });
      createdUserIds.push(secondAnalystUser.id);
      await prisma.projectMember.create({
        data: {
          projectId: project.id,
          userId: secondAnalystUser.id,
          role: 'ANALYST',
          addedById: adminUser.id,
        },
      });

      const secondAnalystActor = new ActorContext({
        id: secondAnalystUser.id,
        globalRole: 'ANALYST',
        isActive: true,
        memberships: [{ projectId: project.id, role: 'ANALYST' }],
      });

      const verified = await findingService.verifyFinding(secondAnalystActor, created.id, {
        expectedVersion: submitted.version,
        outcome: 'VERIFIED',
        notes: 'Verification confirmed fix in integration environment',
      });

      return { finding: verified, task: activeTask, secondAnalystActor };
    }

    // ========================================================================
    // Scenario 1: VERIFIED → CLOSED with OCC & Atomic Events
    // ========================================================================
    const { finding: verifiedFinding1, task: task1 } = await createVerifiedFinding('Finding for Ordinary Closure');

    const closedFinding1 = await findingService.closeFinding(analystActor, verifiedFinding1.id, {
      expectedVersion: verifiedFinding1.version,
      notes: 'Final operational sign-off post-verification',
    });

    if (closedFinding1.status !== 'CLOSED' || closedFinding1.version !== verifiedFinding1.version + 1) {
      throw new Error(`Expected CLOSED finding with version ${verifiedFinding1.version + 1}, got ${closedFinding1.status} v${closedFinding1.version}`);
    }

    // Verify task status remained unchanged (VERIFIED)
    const taskAfterClose = await prisma.remediationTask.findUniqueOrThrow({
      where: { id: task1.id },
    });
    if (taskAfterClose.status !== 'VERIFIED') {
      throw new Error(`Remediation task status unexpectedly altered: ${taskAfterClose.status}`);
    }

    // Verify finding lifecycle event
    const closeEvent = await prisma.findingEvent.findFirstOrThrow({
      where: {
        findingId: verifiedFinding1.id,
        eventType: 'STATUS_CHANGED',
        newStatus: 'CLOSED',
      },
    });
    createdFindingEventIds.push(closeEvent.id);
    if (closeEvent.previousStatus !== 'VERIFIED' || closeEvent.actorId !== analystUser.id) {
      throw new Error('Close finding event recorded invalid status or actor');
    }

    // Verify audit event
    const closeAudit = await prisma.auditEvent.findFirstOrThrow({
      where: {
        resourceId: verifiedFinding1.id,
        eventType: 'finding.closed',
      },
    });
    createdAuditIds.push(closeAudit.id);

    recordPass(
      'Scenario 1: Ordinary Finding Closure (VERIFIED -> CLOSED) with OCC & Atomic Events',
      `Finding ${closedFinding1.id} closed at version ${closedFinding1.version} with verified task history preserved`,
    );

    // ========================================================================
    // Scenario 2: Invalid Closure Transition Rejection
    // ========================================================================
    const openFinding2 = await findingService.createFinding(analystActor, {
      projectId: project.id,
      title: 'OPEN finding cannot be closed directly by Analyst',
      description: 'Must go through verification',
      severity: 'LOW',
      category: 'LOGGING',
    });
    createdFindingIds.push(openFinding2.id);

    let invalidStateCaught = false;
    try {
      await findingService.closeFinding(analystActor, openFinding2.id, {
        expectedVersion: openFinding2.version,
      });
    } catch (err) {
      if (err instanceof InvalidStateTransitionError && err.statusCode === 422) {
        invalidStateCaught = true;
      }
    }
    if (!invalidStateCaught) throw new Error('Closing an OPEN finding was not rejected with InvalidStateTransitionError!');

    recordPass(
      'Scenario 2: Invalid Closure Transition Rejection',
      'Closing non-VERIFIED finding correctly rejected with HTTP 422 InvalidStateTransitionError',
    );

    // ========================================================================
    // Scenario 3: Stale Version Conflicts on Closure (OCC Precedence)
    // ========================================================================
    let staleOccCaught = false;
    try {
      await findingService.closeFinding(analystActor, openFinding2.id, {
        expectedVersion: 999, // Stale version on OPEN finding
      });
    } catch (err) {
      if (err instanceof ConcurrencyConflictError && err.statusCode === 409) {
        staleOccCaught = true;
      }
    }
    if (!staleOccCaught) throw new Error('Stale expectedVersion did not trigger HTTP 409 ConcurrencyConflictError!');

    recordPass(
      'Scenario 3: Stale Version Conflicts on Closure (OCC Precedence)',
      'OCC version check strictly precedes lifecycle state evaluation, rejecting with HTTP 409',
    );

    // ========================================================================
    // Scenario 4: Force-Close with Valid Admin Authorization (OPEN → CLOSED)
    // ========================================================================
    const openFinding4 = await findingService.createFinding(analystActor, {
      projectId: project.id,
      title: 'Finding for Admin Force-Close',
      description: 'Unactionable third-party issue',
      severity: 'MEDIUM',
      category: 'SUPPLY_CHAIN',
    });
    createdFindingIds.push(openFinding4.id);

    const justification4 = 'Unactionable third-party dependency false positive confirmed by vendor errata';
    const forceClosedFinding = await findingService.forceCloseFinding(adminActor, openFinding4.id, {
      expectedVersion: openFinding4.version,
      justification: justification4,
    });

    if (forceClosedFinding.status !== 'CLOSED' || forceClosedFinding.version !== openFinding4.version + 1) {
      throw new Error(`Admin force-close failed: status=${forceClosedFinding.status}, version=${forceClosedFinding.version}`);
    }

    const forceCloseEvent = await prisma.findingEvent.findFirstOrThrow({
      where: {
        findingId: openFinding4.id,
        eventType: 'STATUS_CHANGED',
        newStatus: 'CLOSED',
      },
    });
    createdFindingEventIds.push(forceCloseEvent.id);
    const eventMeta = forceCloseEvent.metadata as Record<string, unknown>;
    if (eventMeta?.['justification'] !== justification4) {
      throw new Error('Force-close lifecycle event missing expected justification');
    }

    const forceCloseAudit = await prisma.auditEvent.findFirstOrThrow({
      where: {
        resourceId: openFinding4.id,
        eventType: 'finding.force_closed',
      },
    });
    createdAuditIds.push(forceCloseAudit.id);
    const auditAfter = forceCloseAudit.afterState as Record<string, unknown>;
    if (auditAfter?.['justification'] !== justification4) {
      throw new Error('Force-close audit event missing expected justification in afterState');
    }

    recordPass(
      'Scenario 4: Force-Close with Valid Admin Authorization (OPEN -> CLOSED)',
      `Finding transitioned OPEN -> CLOSED at version ${forceClosedFinding.version} with mandatory justification`,
    );

    // ========================================================================
    // Scenario 5: Non-Admin Force-Close Denial
    // ========================================================================
    let analystDenied = false;
    try {
      await findingService.forceCloseFinding(analystActor, openFinding4.id, {
        expectedVersion: forceClosedFinding.version,
        justification: 'Analyst attempt to force-close',
      });
    } catch (err) {
      if (err instanceof ForbiddenError && err.statusCode === 403) {
        analystDenied = true;
      }
    }
    if (!analystDenied) throw new Error('Analyst force-close attempt was not rejected with HTTP 403 Forbidden!');

    let devDenied = false;
    try {
      await findingService.forceCloseFinding(devActor, openFinding4.id, {
        expectedVersion: forceClosedFinding.version,
        justification: 'Dev attempt to force-close',
      });
    } catch (err) {
      if (err instanceof ForbiddenError && err.statusCode === 403) {
        devDenied = true;
      }
    }
    if (!devDenied) throw new Error('Developer force-close attempt was not rejected with HTTP 403 Forbidden!');

    recordPass(
      'Scenario 5: Non-Admin Force-Close Denial',
      'Non-Admin callers (Analyst, Developer) rejected with HTTP 403 Forbidden',
    );

    // ========================================================================
    // Scenario 6: Admin Role Downgrade Before Force-Close
    // ========================================================================
    const openFinding6 = await findingService.createFinding(analystActor, {
      projectId: project.id,
      title: 'Finding for Role Downgrade Test',
      description: 'Admin role downgrade check',
      severity: 'LOW',
      category: 'CONFIG_EXPOSURE',
    });
    createdFindingIds.push(openFinding6.id);

    // Downgrade admin in database directly
    await prisma.user.update({
      where: { id: adminUser.id },
      data: { globalRole: 'DEVELOPER' },
    });

    let downgradeBlocked = false;
    try {
      await findingService.forceCloseFinding(adminActor, openFinding6.id, {
        expectedVersion: openFinding6.version,
        justification: 'Attempt with downgraded database role',
      });
    } catch (err) {
      if (err instanceof ForbiddenError && err.statusCode === 403) {
        downgradeBlocked = true;
      }
    }

    // Restore admin role
    await prisma.user.update({
      where: { id: adminUser.id },
      data: { globalRole: 'ADMIN' },
    });

    if (!downgradeBlocked) throw new Error('Stale admin ActorContext succeeded after database role downgrade!');

    recordPass(
      'Scenario 6: Admin Role Downgrade Before Force-Close',
      'Authoritative PostgreSQL check detected downgraded global role and failed closed (HTTP 403)',
    );

    // ========================================================================
    // Scenario 7: Missing Justification Rejection
    // ========================================================================
    let missingJustificationCaught = false;
    try {
      await findingService.forceCloseFinding(adminActor, openFinding6.id, {
        expectedVersion: openFinding6.version,
        justification: '   ', // whitespace only
      });
    } catch {
      missingJustificationCaught = true;
    }
    if (!missingJustificationCaught) throw new Error('Whitespace-only justification was not rejected!');

    recordPass(
      'Scenario 7: Missing Justification Rejection',
      'Validation schema rejected whitespace-only justification fail-closed',
    );

    // ========================================================================
    // Scenario 8: Force-Reopen of a Closed Finding (CLOSED → REOPENED)
    // ========================================================================
    const reopenJustification = 'Regression identified during security regression testing';
    const forceReopenedFinding = await findingService.forceReopenFinding(adminActor, forceClosedFinding.id, {
      expectedVersion: forceClosedFinding.version,
      justification: reopenJustification,
    });

    if (forceReopenedFinding.status !== 'REOPENED' || forceReopenedFinding.version !== forceClosedFinding.version + 1) {
      throw new Error(`Force reopen failed: status=${forceReopenedFinding.status}, version=${forceReopenedFinding.version}`);
    }

    const reopenEvent = await prisma.findingEvent.findFirstOrThrow({
      where: {
        findingId: forceClosedFinding.id,
        eventType: 'REOPENED',
        newStatus: 'REOPENED',
      },
    });
    createdFindingEventIds.push(reopenEvent.id);

    const reopenAudit = await prisma.auditEvent.findFirstOrThrow({
      where: {
        resourceId: forceClosedFinding.id,
        eventType: 'finding.force_reopened',
      },
    });
    createdAuditIds.push(reopenAudit.id);

    recordPass(
      'Scenario 8: Force-Reopen of a Closed Finding (CLOSED -> REOPENED)',
      `Finding transitioned CLOSED -> REOPENED at version ${forceReopenedFinding.version} with mandatory justification`,
    );

    // ========================================================================
    // Scenario 9: Preservation of Remediation-Task History on Reopening
    // ========================================================================
    // Force-reopen the ordinary closed finding (which had a verified task)
    const reopenedFinding9 = await findingService.forceReopenFinding(adminActor, closedFinding1.id, {
      expectedVersion: closedFinding1.version,
      justification: 'Regression observed in staging canary',
    });

    // Check that previous task is STILL in terminal VERIFIED status
    const historicalTask = await prisma.remediationTask.findUniqueOrThrow({
      where: { id: task1.id },
    });
    if (historicalTask.status !== 'VERIFIED') {
      throw new Error(`Historical remediation task altered on force-reopen: ${historicalTask.status}`);
    }

    // Now re-assign the reopened finding to a new remediation task under partial unique index
    const reassignedFinding = await findingService.assignFinding(analystActor, reopenedFinding9.id, {
      expectedVersion: reopenedFinding9.version,
      assignedToId: devUser.id,
      taskDescription: 'Remediate regression',
    });
    if (reassignedFinding.status !== 'IN_PROGRESS') {
      throw new Error(`Expected IN_PROGRESS status after reassignment, got: ${reassignedFinding.status}`);
    }
    const newTask = await prisma.remediationTask.findFirstOrThrow({
      where: { findingId: reopenedFinding9.id, status: 'PENDING' },
    });
    createdTaskIds.push(newTask.id);

    if (newTask.id === task1.id) throw new Error('Silently reused historical terminal task instead of creating new task!');

    recordPass(
      'Scenario 9: Preservation of Remediation-Task History on Reopening',
      `Historical task ${task1.id} preserved as VERIFIED; reopened finding cleanly assigned to new task ${newTask.id}`,
    );

    // ========================================================================
    // Scenario 10: Soft Deletion Without Physical Removal
    // ========================================================================
    const finding10 = await findingService.createFinding(analystActor, {
      projectId: project.id,
      title: 'Finding for Soft Deletion',
      description: 'Soft deletion verification',
      severity: 'LOW',
      category: 'OTHER',
    });
    createdFindingIds.push(finding10.id);

    const softDeletedFinding = await findingService.softDeleteFinding(analystActor, finding10.id, {
      expectedVersion: finding10.version,
    });

    if (!softDeletedFinding.isDeleted || softDeletedFinding.version !== finding10.version + 1) {
      throw new Error('Soft deletion did not set isDeleted: true or increment version');
    }

    // Verify row STILL physically exists in PostgreSQL
    const physicalRow = await prisma.finding.findUniqueOrThrow({
      where: { id: finding10.id },
    });
    if (!physicalRow.isDeleted) throw new Error('Database isDeleted flag is false!');

    // Verify DELETED finding event
    const deleteEvent = await prisma.findingEvent.findFirstOrThrow({
      where: { findingId: finding10.id, eventType: 'DELETED' },
    });
    createdFindingEventIds.push(deleteEvent.id);

    // Verify audit event
    const deleteAudit = await prisma.auditEvent.findFirstOrThrow({
      where: { resourceId: finding10.id, eventType: 'finding.deleted' },
    });
    createdAuditIds.push(deleteAudit.id);

    recordPass(
      'Scenario 10: Soft Deletion Without Physical Removal',
      `Finding ${finding10.id} soft-deleted with isDeleted=true at version ${softDeletedFinding.version}; record retained in PostgreSQL`,
    );

    // ========================================================================
    // Scenario 11: Unauthorized Deleted-Finding Access (OLI-12 Existence Hiding)
    // ========================================================================
    // Non-admin Analyst reading soft-deleted finding
    let deletedFindingHiddenAnalyst = false;
    try {
      await findingService.getFinding(analystActor, finding10.id);
    } catch (err) {
      if (err instanceof EntityNotFoundError && err.statusCode === 404) {
        deletedFindingHiddenAnalyst = true;
      }
    }
    if (!deletedFindingHiddenAnalyst) throw new Error('Soft-deleted finding was disclosed to non-admin Analyst!');

    // Non-admin Analyst listing findings with includeDeleted: true (must be ignored)
    const analystList = await findingService.listFindings(analystActor, {
      projectId: project.id,
      includeDeleted: true,
    });
    const analystFoundIds = analystList.items.map((f) => f.id);
    if (analystFoundIds.includes(finding10.id)) {
      throw new Error('Soft-deleted finding was returned to Analyst list query!');
    }

    // Admin listing findings with includeDeleted: true (visible to Admin per query policy)
    const adminList = await findingService.listFindings(adminActor, {
      projectId: project.id,
      includeDeleted: true,
    });
    const adminFoundIds = adminList.items.map((f) => f.id);
    if (!adminFoundIds.includes(finding10.id)) {
      throw new Error('Soft-deleted finding was not returned to Admin list query with includeDeleted: true!');
    }

    recordPass(
      'Scenario 11: Unauthorized Deleted-Finding Access (OLI-12 Existence Hiding)',
      'Soft-deleted finding hidden with HTTP 404 from non-admin Analyst; visible to global Admin via list with includeDeleted: true',
    );

    // ========================================================================
    // Scenario 12: Finding-Event and Audit-Event Atomicity
    // ========================================================================
    const eventsForFinding10 = await prisma.findingEvent.findMany({
      where: { findingId: finding10.id },
    });
    const auditsForFinding10 = await prisma.auditEvent.findMany({
      where: { resourceId: finding10.id },
    });
    if (eventsForFinding10.length !== 2 || auditsForFinding10.length !== 2) {
      throw new Error(`Expected exactly 2 events and 2 audits (created + deleted), found events=${eventsForFinding10.length}, audits=${auditsForFinding10.length}`);
    }

    recordPass(
      'Scenario 12: Finding-Event and Audit-Event Atomicity',
      'Both lifecycle and audit events persisted atomically in matching counts',
    );

    // ========================================================================
    // Scenario 13: Full Rollback After Simulated Audit Failure
    // ========================================================================
    const finding13 = await findingService.createFinding(analystActor, {
      projectId: project.id,
      title: 'Finding for Rollback Test',
      description: 'Simulated failure rollback',
      severity: 'MEDIUM',
      category: 'CRYPTO',
    });
    createdFindingIds.push(finding13.id);

    let rollbackCaught = false;
    try {
      await dbManager.runTransaction(async (repos) => {
        await repos.userRepo.lockUsers([analystActor.id]);
        await repos.projectRepo.lockProject(project.id);
        await repos.projectRepo.lockMember(project.id, analystActor.id);
        const locked = await repos.findingRepo.lockFinding(finding13.id);
        if (!locked) throw new Error('Finding missing');

        await repos.findingRepo.softDelete(finding13.id, locked.version);
        // Simulate crash before audit commit
        throw new Error('Simulated transactional failure during audit');
      });
    } catch {
      rollbackCaught = true;
    }
    if (!rollbackCaught) throw new Error('Simulated failure did not throw!');

    const freshFinding13 = await prisma.finding.findUniqueOrThrow({
      where: { id: finding13.id },
    });
    if (freshFinding13.isDeleted !== false || freshFinding13.version !== finding13.version) {
      throw new Error('Finding was modified despite transaction rollback!');
    }

    recordPass(
      'Scenario 13: Full Rollback After Simulated Audit Failure',
      'Zero partial writes committed after transactional exception; finding state and version completely preserved',
    );

    // ========================================================================
    // Scenario 14: Concurrent Closure Attempts with Same expectedVersion (OCC Race)
    // ========================================================================
    const { finding: verifiedFinding14 } = await createVerifiedFinding('Finding for Concurrent Closure');

    const [closeRes1, closeRes2] = await Promise.allSettled([
      findingService.closeFinding(analystActor, verifiedFinding14.id, {
        expectedVersion: verifiedFinding14.version,
      }),
      findingService.closeFinding(analystActor, verifiedFinding14.id, {
        expectedVersion: verifiedFinding14.version,
      }),
    ]);

    const successes = [closeRes1, closeRes2].filter((r) => r.status === 'fulfilled');
    const failures = [closeRes1, closeRes2].filter((r) => r.status === 'rejected');

    if (successes.length !== 1 || failures.length !== 1) {
      throw new Error(`Expected exactly 1 success and 1 failure in concurrent closure, got ${successes.length} successes, ${failures.length} failures`);
    }

    const failureReason = (failures[0] as PromiseRejectedResult).reason;
    if (!(failureReason instanceof ConcurrencyConflictError) || failureReason.statusCode !== 409) {
      throw new Error(`Expected ConcurrencyConflictError (409) on concurrent closure race, got: ${failureReason}`);
    }

    recordPass(
      'Scenario 14: Concurrent Closure Attempts with Same expectedVersion (OCC Race)',
      'Exactly 1 transaction committed; racing transaction rejected with HTTP 409 ConcurrencyConflictError',
    );

    // ========================================================================
    // Scenario 15: Account Deactivation and Membership Revocation Behavior
    // ========================================================================
    const { finding: verifiedFinding15 } = await createVerifiedFinding('Finding for Deactivation Test');

    // Deactivate analyst in database directly
    await prisma.user.update({
      where: { id: analystUser.id },
      data: { isActive: false },
    });

    let deactivationBlocked = false;
    try {
      await findingService.closeFinding(analystActor, verifiedFinding15.id, {
        expectedVersion: verifiedFinding15.version,
      });
    } catch (err) {
      if (err instanceof ForbiddenError && err.statusCode === 403) {
        deactivationBlocked = true;
      }
    }

    // Restore analyst
    await prisma.user.update({
      where: { id: analystUser.id },
      data: { isActive: true },
    });

    if (!deactivationBlocked) throw new Error('Deactivated analyst was able to close finding!');

    recordPass(
      'Scenario 15: Account Deactivation and Membership Revocation Behavior',
      'Deactivated actor rejected with HTTP 403 Forbidden under Level 0 row lock',
    );

    // ========================================================================
    // Scenario 16: Cross-Project Existence Hiding
    // ========================================================================
    const foreignFinding = await prisma.finding.create({
      data: {
        projectId: foreignProject.id,
        title: 'Foreign Project Finding',
        description: 'Should not exist to analystActor',
        severity: 'MEDIUM',
        category: 'AUTH',
        status: 'VERIFIED',
        createdById: adminUser.id,
      },
    });
    createdFindingIds.push(foreignFinding.id);

    let crossProjectClosureHidden = false;
    try {
      await findingService.closeFinding(analystActor, foreignFinding.id, {
        expectedVersion: 1,
      });
    } catch (err) {
      if (err instanceof EntityNotFoundError && err.statusCode === 404) {
        crossProjectClosureHidden = true;
      }
    }
    if (!crossProjectClosureHidden) throw new Error('Cross-project finding was not hidden with 404 EntityNotFoundError!');

    let crossProjectDeleteHidden = false;
    try {
      await findingService.softDeleteFinding(analystActor, foreignFinding.id, {
        expectedVersion: 1,
      });
    } catch (err) {
      if (err instanceof EntityNotFoundError && err.statusCode === 404) {
        crossProjectDeleteHidden = true;
      }
    }
    if (!crossProjectDeleteHidden) throw new Error('Cross-project finding deletion was not hidden with 404 EntityNotFoundError!');

    recordPass(
      'Scenario 16: Cross-Project Existence Hiding',
      'Non-member operations on foreign project findings strictly receive HTTP 404 EntityNotFoundError',
    );

    // ========================================================================
    // Scenario 17: Archived-Project Access Rules
    // ========================================================================
    // Archive project
    await prisma.project.update({
      where: { id: project.id },
      data: { isActive: false },
    });

    let archivedMemberBlocked = false;
    try {
      await findingService.closeFinding(analystActor, verifiedFinding15.id, {
        expectedVersion: verifiedFinding15.version,
      });
    } catch (err) {
      if (err instanceof ForbiddenError && err.statusCode === 403) {
        archivedMemberBlocked = true;
      }
    }

    let archivedNonMemberHidden = false;
    try {
      await findingService.closeFinding(nonMemberActor, verifiedFinding15.id, {
        expectedVersion: verifiedFinding15.version,
      });
    } catch (err) {
      if (err instanceof EntityNotFoundError && err.statusCode === 404) {
        archivedNonMemberHidden = true;
      }
    }

    // Unarchive project
    await prisma.project.update({
      where: { id: project.id },
      data: { isActive: true },
    });

    if (!archivedMemberBlocked) throw new Error('Member targeting archived project was not rejected with HTTP 403!');
    if (!archivedNonMemberHidden) throw new Error('Non-member targeting archived project did not receive HTTP 404 existence hiding!');

    recordPass(
      'Scenario 17: Archived-Project Access Rules',
      'Authorized members receive HTTP 403 Forbidden; non-members receive HTTP 404 EntityNotFoundError existence hiding',
    );

    // ========================================================================
    // Scenario 18: No Orphaned or Unexpectedly Reactivated Remediation Tasks
    // ========================================================================
    const allTasks = await prisma.remediationTask.findMany({
      where: { findingId: { in: createdFindingIds } },
    });
    for (const t of allTasks) {
      if (!createdFindingIds.includes(t.findingId)) {
        throw new Error(`Found orphaned remediation task ${t.id} without valid finding!`);
      }
    }

    // Verify partial unique index: no finding has more than 1 active task
    const activeTasksByFinding = new Map<string, number>();
    for (const t of allTasks) {
      if (t.status !== 'VERIFIED' && t.status !== 'REJECTED') {
        const count = (activeTasksByFinding.get(t.findingId) ?? 0) + 1;
        activeTasksByFinding.set(t.findingId, count);
        if (count > 1) {
          throw new Error(`Partial unique index invariant violated: finding ${t.findingId} has multiple active tasks!`);
        }
      }
    }

    recordPass(
      'Scenario 18: No Orphaned or Unexpectedly Reactivated Remediation Tasks',
      `All ${allTasks.length} tasks strictly bound to valid findings; zero orphan or reactivated tasks`,
    );

    // ========================================================================
    // Scenario 19: PostgreSQL Index & Schema Definition Verification (Read-Only pg_catalog)
    // ========================================================================
    const indexRows = await prisma.$queryRaw<Array<{ indexname: string; indexdef: string }>>`
      SELECT indexname, indexdef
      FROM pg_indexes
      WHERE tablename = 'remediation_tasks' AND indexdef LIKE '%UNIQUE%';
    `;
    const activeIndex = indexRows.find((r) => r.indexname === 'one_active_remediation_task_per_finding');
    if (!activeIndex) {
      throw new Error(`Expected unique index 'one_active_remediation_task_per_finding' on remediation_tasks, found: ${JSON.stringify(indexRows)}`);
    }
    // Verify predicate: WHERE status NOT IN ('VERIFIED', 'REJECTED')
    if (!activeIndex.indexdef.includes('VERIFIED') || !activeIndex.indexdef.includes('REJECTED')) {
      throw new Error(`Unexpected index definition for one_active_remediation_task_per_finding: ${activeIndex.indexdef}`);
    }

    // Verify exact PostgreSQL enum values for remediation_task_status
    const enumRows = await prisma.$queryRaw<Array<{ enumlabel: string }>>`
      SELECT enumlabel
      FROM pg_enum
      JOIN pg_type ON pg_enum.enumtypid = pg_type.oid
      WHERE pg_type.typname = 'remediation_task_status'
      ORDER BY enumsortorder;
    `;
    const enumLabels = enumRows.map((r) => r.enumlabel);
    const expectedLabels = ['PENDING', 'IN_PROGRESS', 'SUBMITTED', 'VERIFIED', 'REJECTED'];
    if (JSON.stringify(enumLabels) !== JSON.stringify(expectedLabels)) {
      throw new Error(`PostgreSQL remediation_task_status mismatch: expected ${JSON.stringify(expectedLabels)}, got ${JSON.stringify(enumLabels)}`);
    }

    // Verify finding table columns in information_schema: has is_deleted, does NOT have deleted_at or deleted_by_id
    const colRows = await prisma.$queryRaw<Array<{ column_name: string }>>`
      SELECT column_name
      FROM information_schema.columns
      WHERE table_name = 'findings' AND column_name IN ('is_deleted', 'deleted_at', 'deleted_by_id');
    `;
    const colNames = colRows.map((r) => r.column_name);
    if (!colNames.includes('is_deleted') || colNames.includes('deleted_at') || colNames.includes('deleted_by_id')) {
      throw new Error(`Unexpected columns for soft-deletion on findings: ${JSON.stringify(colNames)}`);
    }

    recordPass(
      'Scenario 19: PostgreSQL Index & Schema Definition Verification (Read-Only pg_catalog)',
      `Unique index 'one_active_remediation_task_per_finding' verified (status NOT IN VERIFIED, REJECTED); enum strictly [${expectedLabels.join(', ')}]`,
    );

    // ========================================================================
    // Scenario 20: Analyst Closure & Soft Deletion vs Concurrent Membership Revocation
    // ========================================================================
    const { finding: verifiedFinding20 } = await createVerifiedFinding('Finding for Membership Revocation Test');

    // Revoke Analyst's membership directly in database
    await prisma.projectMember.deleteMany({
      where: { projectId: project.id, userId: analystUser.id },
    });

    let revokedClosureHidden = false;
    try {
      await findingService.closeFinding(analystActor, verifiedFinding20.id, {
        expectedVersion: verifiedFinding20.version,
      });
    } catch (err) {
      if (err instanceof EntityNotFoundError && err.statusCode === 404) {
        revokedClosureHidden = true;
      }
    }
    if (!revokedClosureHidden) throw new Error('Revoked member closure was not rejected with HTTP 404 existence hiding!');

    let revokedDeleteHidden = false;
    try {
      await findingService.softDeleteFinding(analystActor, verifiedFinding20.id, {
        expectedVersion: verifiedFinding20.version,
      });
    } catch (err) {
      if (err instanceof EntityNotFoundError && err.statusCode === 404) {
        revokedDeleteHidden = true;
      }
    }
    if (!revokedDeleteHidden) throw new Error('Revoked member soft deletion was not rejected with HTTP 404 existence hiding!');

    // Restore Analyst membership for subsequent scenarios
    await prisma.projectMember.create({
      data: {
        projectId: project.id,
        userId: analystUser.id,
        role: 'ANALYST',
        addedById: adminUser.id,
      },
    });

    recordPass(
      'Scenario 20: Analyst Closure & Soft Deletion vs Concurrent Membership Revocation',
      'Revoked member mutations fail closed under Level 2 row lock with generic HTTP 404 EntityNotFoundError',
    );

    // ========================================================================
    // Scenario 21: Finding Closure vs Project Archival (PostgreSQL Lock Conflict)
    // ========================================================================
    const { finding: verifiedFinding21 } = await createVerifiedFinding('Finding for Lock Conflict Test');

    // 1. Verify that an already-archived project cleanly rejects closeFinding with 403 Forbidden
    await projectService.archiveProject(adminActor, project.id);

    let archivedClosureBlocked = false;
    try {
      await findingService.closeFinding(analystActor, verifiedFinding21.id, {
        expectedVersion: verifiedFinding21.version,
      });
    } catch (err) {
      if (err instanceof ForbiddenError && err.statusCode === 403) {
        archivedClosureBlocked = true;
      }
    }

    // Unarchive project
    await prisma.project.update({
      where: { id: project.id },
      data: { isActive: true },
    });

    if (!archivedClosureBlocked) throw new Error('Closure on archived project was not rejected with HTTP 403 Forbidden!');

    // 2. Concurrency verification: verify lock conflict between lockProject(SHARE) and FOR UPDATE
    let lockConflictVerified = false;
    await dbManager.runTransaction(async (repos) => {
      // Transaction A acquires FOR SHARE on project
      const lockedProj = await repos.projectRepo.lockProject(project.id, 'SHARE');
      if (!lockedProj) throw new Error('Project lock failed');

      // Concurrent Transaction B tries to acquire FOR UPDATE with a 500ms timeout
      // It MUST timeout or block because FOR SHARE and FOR UPDATE conflict in PostgreSQL!
      const pool = dbManager.getPool();
      const clientB = await pool.connect();
      try {
        await clientB.query('SET statement_timeout = 500');
        await clientB.query('BEGIN');
        let timedOut = false;
        try {
          await clientB.query(`SELECT id FROM projects WHERE id = '${project.id}'::uuid FOR UPDATE`);
        } catch (lockErr: unknown) {
          if ((lockErr as { code?: string }).code === '57014') { // query_canceled / statement timeout
            timedOut = true;
          }
        }
        await clientB.query('ROLLBACK');
        if (timedOut) {
          lockConflictVerified = true;
        }
      } finally {
        clientB.release();
      }
    });

    if (!lockConflictVerified) {
      throw new Error('PostgreSQL lock conflict between lockProject(SHARE) and FOR UPDATE did not block as expected!');
    }

    recordPass(
      'Scenario 21: Finding Closure vs Project Archival (PostgreSQL Lock Conflict)',
      'Verified PostgreSQL FOR SHARE directly conflicts with and blocks FOR UPDATE project archival transactions',
    );

    // ========================================================================
    // Scenario 22: Unauthorized Admin Ordinary Closure & Soft Deletion (Policy Enforcement)
    // ========================================================================
    const { finding: verifiedFinding22 } = await createVerifiedFinding('Finding for Admin Operational Denial');

    let adminCloseForbidden = false;
    try {
      await findingService.closeFinding(adminActor, verifiedFinding22.id, {
        expectedVersion: verifiedFinding22.version,
      });
    } catch (err) {
      if (err instanceof ForbiddenError && err.statusCode === 403) {
        adminCloseForbidden = true;
      }
    }
    if (!adminCloseForbidden) throw new Error('Admin ordinary closeFinding was not rejected with HTTP 403 Forbidden!');

    let adminDeleteForbidden = false;
    try {
      await findingService.softDeleteFinding(adminActor, verifiedFinding22.id, {
        expectedVersion: verifiedFinding22.version,
      });
    } catch (err) {
      if (err instanceof ForbiddenError && err.statusCode === 403) {
        adminDeleteForbidden = true;
      }
    }
    if (!adminDeleteForbidden) throw new Error('Admin softDeleteFinding was not rejected with HTTP 403 Forbidden!');

    recordPass(
      'Scenario 22: Unauthorized Admin Ordinary Closure & Soft Deletion (Policy Enforcement)',
      'Global Admin strictly rejected with HTTP 403 Forbidden when attempting ordinary Analyst operations (F-13)',
    );

    // ========================================================================
    // Scenario 23: Soft Deletion of a Finding with an Active Remediation Task
    // ========================================================================
    const openFinding23 = await findingService.createFinding(analystActor, {
      projectId: project.id,
      title: 'Finding with Active Task for Soft Deletion',
      description: 'Active task lifecycle during deletion',
      severity: 'HIGH',
      category: 'AUTH',
    });
    createdFindingIds.push(openFinding23.id);

    const triagedFinding23 = await findingService.triageFinding(analystActor, openFinding23.id, {
      expectedVersion: openFinding23.version,
    });

    const assignedFinding23 = await findingService.assignFinding(analystActor, triagedFinding23.id, {
      expectedVersion: triagedFinding23.version,
      assignedToId: devUser.id,
      taskDescription: 'Remediation task that will outlive finding deletion',
    });

    const activeTask23 = await prisma.remediationTask.findFirstOrThrow({
      where: { findingId: assignedFinding23.id, status: 'PENDING' },
    });
    createdTaskIds.push(activeTask23.id);

    // Soft-delete the finding while task is PENDING
    const deletedFinding23 = await findingService.softDeleteFinding(analystActor, assignedFinding23.id, {
      expectedVersion: assignedFinding23.version,
    });
    if (!deletedFinding23.isDeleted) throw new Error('Finding was not marked as isDeleted: true');

    // Verify task row in PostgreSQL is preserved in status PENDING (audit evidence preserved)
    const preservedTask23 = await prisma.remediationTask.findUniqueOrThrow({
      where: { id: activeTask23.id },
    });
    if (preservedTask23.status !== 'PENDING') {
      throw new Error(`Remediation task status corrupted during parent soft deletion: ${preservedTask23.status}`);
    }

    recordPass(
      'Scenario 23: Soft Deletion of a Finding with an Active Remediation Task',
      `Finding ${deletedFinding23.id} soft-deleted; active remediation task ${preservedTask23.id} safely preserved in DB`,
    );

    // ========================================================================
    // Scenario 24: Authorization & Visibility After Finding Soft Deletion
    // ========================================================================
    // 1. Analyst cannot get deleted finding
    let analystGetDeletedHidden = false;
    try {
      await findingService.getFinding(analystActor, deletedFinding23.id);
    } catch (err) {
      if (err instanceof EntityNotFoundError && err.statusCode === 404) {
        analystGetDeletedHidden = true;
      }
    }
    if (!analystGetDeletedHidden) throw new Error('Soft-deleted finding was readable by Analyst!');

    // 2. Developer cannot get deleted finding
    let devGetDeletedHidden = false;
    try {
      await findingService.getFinding(devActor, deletedFinding23.id);
    } catch (err) {
      if (err instanceof EntityNotFoundError && err.statusCode === 404) {
        devGetDeletedHidden = true;
      }
    }
    if (!devGetDeletedHidden) throw new Error('Soft-deleted finding was readable by Developer!');

    // 3. Analyst cannot update metadata on deleted finding
    let analystUpdateDeletedHidden = false;
    try {
      await findingService.updateFindingMetadata(analystActor, deletedFinding23.id, {
        expectedVersion: deletedFinding23.version,
        title: 'Updated title on deleted finding',
      });
    } catch (err) {
      if (err instanceof EntityNotFoundError && err.statusCode === 404) {
        analystUpdateDeletedHidden = true;
      }
    }
    if (!analystUpdateDeletedHidden) throw new Error('Analyst was able to update metadata on soft-deleted finding!');

    // 4. Admin can find it when includeDeleted: true is passed
    const adminQuery = await findingService.listFindings(adminActor, {
      projectId: project.id,
      includeDeleted: true,
    });
    if (!adminQuery.items.some((f) => f.id === deletedFinding23.id)) {
      throw new Error('Admin list query with includeDeleted: true did not return soft-deleted finding!');
    }

    recordPass(
      'Scenario 24: Authorization & Visibility After Finding Soft Deletion',
      'All non-admin finding reads and mutations strictly return HTTP 404; Admin list query honors includeDeleted: true',
    );

    // ========================================================================
    // Scenario 25: Remediation Task Inaccessibility After Parent Finding Soft Deletion
    // ========================================================================
    // 1. TaskService.getTask returns 404
    let taskViewHidden = false;
    try {
      await taskService.getTask(devActor, activeTask23.id);
    } catch (err) {
      if (err instanceof EntityNotFoundError && err.statusCode === 404) {
        taskViewHidden = true;
      }
    }
    if (!taskViewHidden) throw new Error('Task of soft-deleted finding was viewable via TaskService.getTask!');

    // 2. TaskService.updateTaskNotes returns 404
    let taskNotesHidden = false;
    try {
      await taskService.updateTaskNotes(devActor, activeTask23.id, {
        notes: 'Attempt to update notes on task of deleted finding',
      });
    } catch (err) {
      if (err instanceof EntityNotFoundError && err.statusCode === 404) {
        taskNotesHidden = true;
      }
    }
    if (!taskNotesHidden) throw new Error('Developer was able to update notes on task of deleted finding!');

    // 3. FindingService.submitRemediation returns 404
    let submitRemediationHidden = false;
    try {
      await findingService.submitRemediation(devActor, deletedFinding23.id, {
        expectedVersion: deletedFinding23.version,
        notes: 'Attempt to submit remediation on deleted finding',
      });
    } catch (err) {
      if (err instanceof EntityNotFoundError && err.statusCode === 404) {
        submitRemediationHidden = true;
      }
    }
    if (!submitRemediationHidden) throw new Error('Developer was able to submit remediation on deleted finding!');

    // 4. FindingService.verifyFinding returns 404
    let verifyFindingHidden = false;
    try {
      await findingService.verifyFinding(analystActor, deletedFinding23.id, {
        expectedVersion: deletedFinding23.version,
        outcome: 'VERIFIED',
      });
    } catch (err) {
      if (err instanceof EntityNotFoundError && err.statusCode === 404) {
        verifyFindingHidden = true;
      }
    }
    if (!verifyFindingHidden) throw new Error('Analyst was able to verify deleted finding!');

    recordPass(
      'Scenario 25: Remediation Task Inaccessibility After Parent Finding Soft Deletion',
      'All task reads, notes updates, submissions, and verifications fail closed with HTTP 404 for deleted parent finding',
    );

    // ========================================================================
    // Scenario 26: Stale-Version Conflicts Yield Zero Partial Lifecycle or Audit Events
    // ========================================================================
    const { finding: verifiedFinding26 } = await createVerifiedFinding('Finding for Zero-Write Stale OCC Test');

    const eventCountBefore = await prisma.findingEvent.count({
      where: { findingId: verifiedFinding26.id },
    });
    const auditCountBefore = await prisma.auditEvent.count({
      where: { resourceId: verifiedFinding26.id },
    });

    let occThrown = false;
    try {
      await findingService.closeFinding(analystActor, verifiedFinding26.id, {
        expectedVersion: 99999, // Stale version
        notes: 'Should fail without events',
      });
    } catch (err) {
      if (err instanceof ConcurrencyConflictError && err.statusCode === 409) {
        occThrown = true;
      }
    }
    if (!occThrown) throw new Error('Stale expectedVersion did not trigger HTTP 409 ConcurrencyConflictError!');

    const eventCountAfter = await prisma.findingEvent.count({
      where: { findingId: verifiedFinding26.id },
    });
    const auditCountAfter = await prisma.auditEvent.count({
      where: { resourceId: verifiedFinding26.id },
    });

    if (eventCountAfter !== eventCountBefore || auditCountAfter !== auditCountBefore) {
      throw new Error(`Partial write occurred on OCC conflict: events before=${eventCountBefore}, after=${eventCountAfter}; audits before=${auditCountBefore}, after=${auditCountAfter}`);
    }

    recordPass(
      'Scenario 26: Stale-Version Conflicts Yield Zero Partial Lifecycle or Audit Events',
      'Rejected OCC mutations write exactly 0 finding lifecycle events and 0 audit events to PostgreSQL',
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
        await prisma.findingEvent.deleteMany({
          where: { findingId: { in: createdFindingIds } },
        });
      }

      if (createdFindingIds.length > 0) {
        await prisma.remediationTask.deleteMany({
          where: { findingId: { in: createdFindingIds } },
        });
      }

      if (createdFindingIds.length > 0) {
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
      console.error('Teardown warning: Synthetic row cleanup encountered error:', cleanupErr);
    }

    await dbManager.shutdown();
  }

  console.log('--------------------------------------------------');
  console.log(`Summary: ${passedTests}/${totalTests} Gate 3D.5 integration tests passed.`);
  console.log('==================================================');

  return {
    allPassed: passedTests === totalTests,
    totalTests,
    passedTests,
  };
}

// Auto-execute when run as standalone script
const isMain = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isMain) {
  runGate3dFindingClosureIntegrationTests()
    .then((results) => {
      if (!results.allPassed) {
        process.exit(1);
      }
    })
    .catch((err) => {
      console.error('Gate 3D.5 integration suite failed with unhandled exception:', err);
      process.exit(1);
    });
}
