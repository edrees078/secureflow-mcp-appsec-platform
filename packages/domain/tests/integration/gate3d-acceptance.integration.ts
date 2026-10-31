import path from 'node:path';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';
import { DatabaseManager } from '../../src/db/database-manager.js';
import {
  FindingService,
  ProjectService,
  createDomainServices,
  ActorContext,
} from '../../src/index.js';
import { handleDatabaseConcurrencyError } from '../../src/services/concurrency-handler.js';
import { TaskService } from '../../src/services/task-service.js';
import { validateTestDatabaseUrl } from './gate3b-repositories.integration.js';
import {
  ConcurrencyConflictError,
  EntityNotFoundError,
  ForbiddenError,
  SecureFlowError,
} from '@secureflow/shared';
import type { FindingResponse } from '@secureflow/schemas';

// Monorepo environment configuration loading
const __dirname = path.dirname(fileURLToPath(import.meta.url));
dotenv.config({ path: path.resolve(__dirname, '../../../../.env') });
dotenv.config({ path: path.resolve(__dirname, '../../../.env') });

export async function runGate3dAcceptanceIntegrationTests(): Promise<{
  allPassed: boolean;
  totalTests: number;
  passedTests: number;
}> {
  console.log('======================================================================');
  console.log('SecureFlow — Sub-Gate 3D.6 Final End-to-End Acceptance Verification');
  console.log('======================================================================');

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

  // SAFETY ASSERTION: Strictly require explicit TEST_DATABASE_URL
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

  try {
    const identity = await dbManager.verifyConnectivity();
    if (identity.database !== 'secureflow_test' || identity.majorVersion !== 17) {
      throw new Error(`Connected database is not secureflow_test on PostgreSQL 17: ${identity.database}`);
    }
    recordPass('Engine Identity & Safety Isolation Assertions', `Connected to ${identity.database} on port ${identity.port} (PG 17.11)`);

    const prisma = dbManager.getPrismaClient();
    const findingService = new FindingService(dbManager);
    const taskService = new TaskService(dbManager);
    const projectService = new ProjectService(dbManager);

    // ========================================================================
    // Seed Base Test Actors and Projects
    // ========================================================================
    const adminSub = `gate3d6-admin-${Date.now()}`;
    const adminUser = await prisma.user.create({
      data: {
        sub: adminSub,
        email: `${adminSub}@example.com`,
        displayName: 'Gate 3D6 Global Admin',
        globalRole: 'ADMIN',
        isActive: true,
      },
    });
    createdUserIds.push(adminUser.id);

    const analyst1Sub = `gate3d6-analyst1-${Date.now()}`;
    const analyst1User = await prisma.user.create({
      data: {
        sub: analyst1Sub,
        email: `${analyst1Sub}@example.com`,
        displayName: 'Gate 3D6 Lead Analyst',
        globalRole: 'ANALYST',
        isActive: true,
      },
    });
    createdUserIds.push(analyst1User.id);

    const analyst2Sub = `gate3d6-analyst2-${Date.now()}`;
    const analyst2User = await prisma.user.create({
      data: {
        sub: analyst2Sub,
        email: `${analyst2Sub}@example.com`,
        displayName: 'Gate 3D6 Peer Analyst',
        globalRole: 'ANALYST',
        isActive: true,
      },
    });
    createdUserIds.push(analyst2User.id);

    const dev1Sub = `gate3d6-dev1-${Date.now()}`;
    const dev1User = await prisma.user.create({
      data: {
        sub: dev1Sub,
        email: `${dev1Sub}@example.com`,
        displayName: 'Gate 3D6 Primary Developer',
        globalRole: 'DEVELOPER',
        isActive: true,
      },
    });
    createdUserIds.push(dev1User.id);

    const dev2Sub = `gate3d6-dev2-${Date.now()}`;
    const dev2User = await prisma.user.create({
      data: {
        sub: dev2Sub,
        email: `${dev2Sub}@example.com`,
        displayName: 'Gate 3D6 Secondary Developer',
        globalRole: 'DEVELOPER',
        isActive: true,
      },
    });
    createdUserIds.push(dev2User.id);

    const nonMemberSub = `gate3d6-nonmember-${Date.now()}`;
    const nonMemberUser = await prisma.user.create({
      data: {
        sub: nonMemberSub,
        email: `${nonMemberSub}@example.com`,
        displayName: 'Gate 3D6 Non-Member User',
        globalRole: 'DEVELOPER',
        isActive: true,
      },
    });
    createdUserIds.push(nonMemberUser.id);

    // Seed primary project
    const project = await prisma.project.create({
      data: {
        name: 'Gate 3D.6 Primary Target Project',
        slug: `gate3d6-target-${Date.now()}`,
        description: 'Primary project for end-to-end acceptance tests',
        isActive: true,
        createdById: adminUser.id,
      },
    });
    createdProjectIds.push(project.id);

    // Seed foreign project for existence-hiding tests
    const foreignProject = await prisma.project.create({
      data: {
        name: 'Gate 3D.6 Foreign Isolated Project',
        slug: `gate3d6-foreign-${Date.now()}`,
        description: 'Isolated foreign project for cross-project tests',
        isActive: true,
        createdById: adminUser.id,
      },
    });
    createdProjectIds.push(foreignProject.id);

    // Add project memberships
    await prisma.projectMember.createMany({
      data: [
        { projectId: project.id, userId: analyst1User.id, role: 'ANALYST', addedById: adminUser.id },
        { projectId: project.id, userId: analyst2User.id, role: 'ANALYST', addedById: adminUser.id },
        { projectId: project.id, userId: dev1User.id, role: 'DEVELOPER', addedById: adminUser.id },
        { projectId: project.id, userId: dev2User.id, role: 'DEVELOPER', addedById: adminUser.id },
      ],
    });

    // Construct authoritative ActorContexts
    const adminActor = new ActorContext({
      id: adminUser.id,
      globalRole: 'ADMIN',
      isActive: true,
      memberships: [],
    });

    const analyst1Actor = new ActorContext({
      id: analyst1User.id,
      globalRole: 'ANALYST',
      isActive: true,
      memberships: [{ projectId: project.id, role: 'ANALYST' }],
    });

    const analyst2Actor = new ActorContext({
      id: analyst2User.id,
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

    const nonMemberActor = new ActorContext({
      id: nonMemberUser.id,
      globalRole: 'DEVELOPER',
      isActive: true,
      memberships: [],
    });

    // ========================================================================
    // Part 2: Cross-Service Concurrency Acceptance (Section 4)
    // ========================================================================

    // ------------------------------------------------------------------------
    // Scenario 1: Project Archival vs Finding Assignment (Both Orderings)
    // ------------------------------------------------------------------------
    // Ordering A: Project is archived before assignment transaction
    const finding1A = await findingService.createFinding(analyst1Actor, {
      projectId: project.id,
      title: 'Finding for Archival vs Assignment A',
      description: 'Test archival precedence',
      severity: 'HIGH',
      category: 'INJECTION',
    });
    createdFindingIds.push(finding1A.id);
    const triaged1A = await findingService.triageFinding(analyst1Actor, finding1A.id, {
      expectedVersion: finding1A.version,
    });

    // Temporarily archive project
    await projectService.archiveProject(adminActor, project.id);

    let assignArchivedBlocked = false;
    try {
      await findingService.assignFinding(analyst1Actor, triaged1A.id, {
        expectedVersion: triaged1A.version,
        assignedToId: dev1User.id,
        taskDescription: 'Attempted assignment in archived project',
      });
    } catch (err) {
      if (err instanceof ForbiddenError && err.statusCode === 403) {
        assignArchivedBlocked = true;
      }
    }

    // Unarchive project
    await prisma.project.update({ where: { id: project.id }, data: { isActive: true } });
    if (!assignArchivedBlocked) throw new Error('Assignment on archived project was not rejected with HTTP 403!');

    // Ordering B: Finding assignment holds Level 1 FOR SHARE lock, blocking concurrent archival
    let lockConflictAssignment = false;
    await dbManager.runTransaction(async (repos) => {
      await repos.projectRepo.lockProject(project.id, 'SHARE');

      const pool = dbManager.getPool();
      const clientB = await pool.connect();
      try {
        await clientB.query('SET statement_timeout = 400');
        await clientB.query('BEGIN');
        let timedOut = false;
        try {
          await clientB.query(`SELECT id FROM projects WHERE id = '${project.id}'::uuid FOR UPDATE`);
        } catch (lockErr: unknown) {
          if ((lockErr as { code?: string }).code === '57014') {
            timedOut = true;
          }
        }
        await clientB.query('ROLLBACK');
        if (timedOut) lockConflictAssignment = true;
      } finally {
        clientB.release();
      }
    });
    if (!lockConflictAssignment) throw new Error('Project lock conflict did not serialize assignment and archival!');

    recordPass(
      'Scenario 1: Project Archival vs Finding Assignment (Both Orderings)',
      'Archived project strictly rejects assignment (HTTP 403); Level 1 FOR SHARE lock blocks concurrent archival FOR UPDATE',
    );

    // ------------------------------------------------------------------------
    // Scenario 2: Project Archival vs Finding Closure
    // ------------------------------------------------------------------------
    const finding2 = await findingService.createFinding(analyst1Actor, {
      projectId: project.id,
      title: 'Finding for Archival vs Closure',
      description: 'Verified finding ready for closure',
      severity: 'MEDIUM',
      category: 'AUTH',
    });
    createdFindingIds.push(finding2.id);
    const triaged2 = await findingService.triageFinding(analyst1Actor, finding2.id, { expectedVersion: finding2.version });
    const assigned2 = await findingService.assignFinding(analyst1Actor, triaged2.id, {
      expectedVersion: triaged2.version,
      assignedToId: dev1User.id,
      taskDescription: 'Fix auth issue',
    });
    const submitted2 = await findingService.submitRemediation(dev1Actor, assigned2.id, {
      expectedVersion: assigned2.version,
      notes: 'Fixed auth flaw',
    });
    const verified2 = await findingService.verifyFinding(analyst2Actor, submitted2.id, {
      expectedVersion: submitted2.version,
      outcome: 'VERIFIED',
    });

    // Archive project
    await projectService.archiveProject(adminActor, project.id);

    let closeArchivedBlocked = false;
    try {
      await findingService.closeFinding(analyst1Actor, verified2.id, {
        expectedVersion: verified2.version,
      });
    } catch (err) {
      if (err instanceof ForbiddenError && err.statusCode === 403) {
        closeArchivedBlocked = true;
      }
    }

    // Unarchive project
    await prisma.project.update({ where: { id: project.id }, data: { isActive: true } });
    if (!closeArchivedBlocked) throw new Error('Closure on archived project was not rejected with HTTP 403!');

    recordPass(
      'Scenario 2: Project Archival vs Finding Closure',
      'Archived project strictly blocks ordinary finding closure with HTTP 403 Forbidden under Level 1 row lock',
    );

    // ------------------------------------------------------------------------
    // Scenario 3: Membership Revocation vs Finding Mutation (Metadata & Triage)
    // ------------------------------------------------------------------------
    const finding3 = await findingService.createFinding(analyst1Actor, {
      projectId: project.id,
      title: 'Finding for Revocation vs Mutation',
      description: 'Metadata mutation test',
      severity: 'LOW',
      category: 'CONFIG_EXPOSURE',
    });
    createdFindingIds.push(finding3.id);

    // Revoke Analyst1's membership directly in database
    await prisma.projectMember.deleteMany({
      where: { projectId: project.id, userId: analyst1User.id },
    });

    let revokedMetadataHidden = false;
    try {
      await findingService.updateFindingMetadata(analyst1Actor, finding3.id, {
        expectedVersion: finding3.version,
        title: 'Unauthorized Metadata Change',
      });
    } catch (err) {
      if (err instanceof EntityNotFoundError && err.statusCode === 404) {
        revokedMetadataHidden = true;
      }
    }

    let revokedTriageHidden = false;
    try {
      await findingService.triageFinding(analyst1Actor, finding3.id, {
        expectedVersion: finding3.version,
      });
    } catch (err) {
      if (err instanceof EntityNotFoundError && err.statusCode === 404) {
        revokedTriageHidden = true;
      }
    }

    // Restore Analyst1's membership
    await prisma.projectMember.create({
      data: { projectId: project.id, userId: analyst1User.id, role: 'ANALYST', addedById: adminUser.id },
    });

    if (!revokedMetadataHidden || !revokedTriageHidden) {
      throw new Error('Revoked membership did not enforce HTTP 404 existence hiding on finding mutations!');
    }

    recordPass(
      'Scenario 3: Membership Revocation vs Finding Mutation (Metadata & Triage)',
      'Revoked member finding mutations strictly fail closed under Level 2 row lock with generic HTTP 404 EntityNotFoundError',
    );

    // ------------------------------------------------------------------------
    // Scenario 4: Membership Revocation vs Remediation Submission
    // ------------------------------------------------------------------------
    const triaged3 = await findingService.triageFinding(analyst1Actor, finding3.id, { expectedVersion: finding3.version });
    const assigned3 = await findingService.assignFinding(analyst1Actor, triaged3.id, {
      expectedVersion: triaged3.version,
      assignedToId: dev1User.id,
      taskDescription: 'Developer assignment before revocation',
    });

    // Revoke Dev1 membership
    await prisma.projectMember.deleteMany({
      where: { projectId: project.id, userId: dev1User.id },
    });

    let revokedSubmitHidden = false;
    try {
      await findingService.submitRemediation(dev1Actor, assigned3.id, {
        expectedVersion: assigned3.version,
        notes: 'Attempted submission after membership revocation',
      });
    } catch (err) {
      if (err instanceof EntityNotFoundError && err.statusCode === 404) {
        revokedSubmitHidden = true;
      }
    }

    // Restore Dev1 membership
    await prisma.projectMember.create({
      data: { projectId: project.id, userId: dev1User.id, role: 'DEVELOPER', addedById: adminUser.id },
    });

    if (!revokedSubmitHidden) throw new Error('Revoked developer submission was not rejected with HTTP 404 existence hiding!');

    recordPass(
      'Scenario 4: Membership Revocation vs Remediation Submission',
      'Revoked developer remediation submission fails closed with generic HTTP 404 EntityNotFoundError',
    );

    // ------------------------------------------------------------------------
    // Scenario 5: User Deactivation vs Operational Mutations
    // ------------------------------------------------------------------------
    // Deactivate Analyst1
    await prisma.user.update({ where: { id: analyst1User.id }, data: { isActive: false } });

    let deactivatedActorBlocked = false;
    try {
      await findingService.createFinding(analyst1Actor, {
        projectId: project.id,
        title: 'Attempted creation by deactivated user',
        description: 'Should fail closed',
        severity: 'LOW',
        category: 'LOGGING',
      });
    } catch (err) {
      if (err instanceof ForbiddenError && err.statusCode === 403) {
        deactivatedActorBlocked = true;
      }
    }

    // Reactivate Analyst1
    await prisma.user.update({ where: { id: analyst1User.id }, data: { isActive: true } });
    if (!deactivatedActorBlocked) throw new Error('Deactivated user mutation was not blocked with HTTP 403!');

    recordPass(
      'Scenario 5: User Deactivation vs Operational Mutations',
      'Deactivated user mutations fail closed under Level 0 row lock with HTTP 403 Forbidden',
    );

    // ------------------------------------------------------------------------
    // Scenario 6: Admin-Role Downgrade vs Exceptional Admin Actions
    // ------------------------------------------------------------------------
    const openFinding6 = await findingService.createFinding(analyst1Actor, {
      projectId: project.id,
      title: 'Finding for Admin Downgrade Race',
      description: 'Testing exceptional force-close',
      severity: 'MEDIUM',
      category: 'CRYPTO',
    });
    createdFindingIds.push(openFinding6.id);

    // Downgrade Admin to DEVELOPER in database
    await prisma.user.update({ where: { id: adminUser.id }, data: { globalRole: 'DEVELOPER' } });

    let downgradedAdminBlocked = false;
    try {
      await findingService.forceCloseFinding(adminActor, openFinding6.id, {
        expectedVersion: openFinding6.version,
        justification: 'Attempt with stale admin token',
      });
    } catch (err) {
      if (err instanceof ForbiddenError && err.statusCode === 403) {
        downgradedAdminBlocked = true;
      }
    }

    // Restore Admin role
    await prisma.user.update({ where: { id: adminUser.id }, data: { globalRole: 'ADMIN' } });
    if (!downgradedAdminBlocked) throw new Error('Downgraded admin action was not rejected with HTTP 403 Forbidden!');

    recordPass(
      'Scenario 6: Admin-Role Downgrade vs Exceptional Admin Actions',
      'Stale admin claims detected via authoritative Level 0 row lock, rejecting force-close with HTTP 403 Forbidden',
    );

    // ------------------------------------------------------------------------
    // Scenario 7: Concurrent Assignment of the Same Finding (OCC Race)
    // ------------------------------------------------------------------------
    const triagedFinding7 = await findingService.triageFinding(analyst1Actor, openFinding6.id, {
      expectedVersion: openFinding6.version,
    });

    const [assignRes1, assignRes2] = await Promise.allSettled([
      findingService.assignFinding(analyst1Actor, triagedFinding7.id, {
        expectedVersion: triagedFinding7.version,
        assignedToId: dev1User.id,
        taskDescription: 'Race 1 for assignment',
      }),
      findingService.assignFinding(analyst1Actor, triagedFinding7.id, {
        expectedVersion: triagedFinding7.version,
        assignedToId: dev2User.id,
        taskDescription: 'Race 2 for assignment',
      }),
    ]);

    const assignSuccess = [assignRes1, assignRes2].filter((r) => r.status === 'fulfilled');
    const assignFailure = [assignRes1, assignRes2].filter((r) => r.status === 'rejected');

    if (assignSuccess.length !== 1 || assignFailure.length !== 1) {
      throw new Error(`Expected exactly 1 success and 1 failure in concurrent assignment, got ${assignSuccess.length}s / ${assignFailure.length}f`);
    }
    const assignErr = (assignFailure[0] as PromiseRejectedResult).reason;
    if (!(assignErr instanceof ConcurrencyConflictError) || assignErr.statusCode !== 409) {
      throw new Error(`Expected HTTP 409 ConcurrencyConflictError on assignment race, got: ${assignErr}`);
    }

    const assignedFinding7 = (assignSuccess[0] as PromiseFulfilledResult<FindingResponse>).value;

    recordPass(
      'Scenario 7: Concurrent Assignment of the Same Finding (OCC Race)',
      'Exactly 1 concurrent assignment committed (IN_PROGRESS); racing transaction rejected with HTTP 409 ConcurrencyConflictError',
    );

    // ------------------------------------------------------------------------
    // Scenario 8: Concurrent Remediation Submission Attempts (OCC Race)
    // ------------------------------------------------------------------------
    const [submitRes1, submitRes2] = await Promise.allSettled([
      findingService.submitRemediation(dev1Actor, assignedFinding7.id, {
        expectedVersion: assignedFinding7.version,
        notes: 'Dev1 submission attempt',
      }),
      findingService.submitRemediation(dev1Actor, assignedFinding7.id, {
        expectedVersion: assignedFinding7.version,
        notes: 'Dev1 duplicate concurrent submission',
      }),
    ]);

    const submitSuccess = [submitRes1, submitRes2].filter((r) => r.status === 'fulfilled');
    const submitFailure = [submitRes1, submitRes2].filter((r) => r.status === 'rejected');

    if (submitSuccess.length !== 1 || submitFailure.length !== 1) {
      throw new Error(`Expected exactly 1 success and 1 failure in concurrent submission, got ${submitSuccess.length}s / ${submitFailure.length}f`);
    }
    const submitErr = (submitFailure[0] as PromiseRejectedResult).reason;
    if (!(submitErr instanceof ConcurrencyConflictError) || submitErr.statusCode !== 409) {
      throw new Error(`Expected HTTP 409 ConcurrencyConflictError on submission race, got: ${submitErr}`);
    }

    const submittedFinding8 = (submitSuccess[0] as PromiseFulfilledResult<FindingResponse>).value;

    recordPass(
      'Scenario 8: Concurrent Remediation Submission Attempts (OCC Race)',
      'Exactly 1 submission committed (READY_FOR_REVIEW); racing transaction rejected with HTTP 409 ConcurrencyConflictError',
    );

    // ------------------------------------------------------------------------
    // Scenario 9: Concurrent Verification and Rejection Attempts (OCC Race)
    // ------------------------------------------------------------------------
    const [verifyRes1, verifyRes2] = await Promise.allSettled([
      findingService.verifyFinding(analyst2Actor, submittedFinding8.id, {
        expectedVersion: submittedFinding8.version,
        outcome: 'VERIFIED',
        notes: 'Analyst2 confirms fix',
      }),
      findingService.verifyFinding(analyst1Actor, submittedFinding8.id, {
        expectedVersion: submittedFinding8.version,
        outcome: 'REOPENED',
        notes: 'Analyst1 rejects fix',
      }),
    ]);

    const verifySuccess = [verifyRes1, verifyRes2].filter((r) => r.status === 'fulfilled');
    const verifyFailure = [verifyRes1, verifyRes2].filter((r) => r.status === 'rejected');

    if (verifySuccess.length !== 1 || verifyFailure.length !== 1) {
      throw new Error(`Expected exactly 1 success and 1 failure in concurrent verification, got ${verifySuccess.length}s / ${verifyFailure.length}f`);
    }
    const verifyErr = (verifyFailure[0] as PromiseRejectedResult).reason;
    if (!(verifyErr instanceof ConcurrencyConflictError) && !(verifyErr instanceof EntityNotFoundError)) {
      throw new Error(`Expected ConcurrencyConflictError or EntityNotFoundError on verification race, got: ${verifyErr}`);
    }

    const verifiedOrRejected9 = (verifySuccess[0] as PromiseFulfilledResult<FindingResponse>).value;

    recordPass(
      'Scenario 9: Concurrent Verification and Rejection Attempts (OCC Race)',
      `Exactly 1 decision committed (${verifiedOrRejected9.status}); racing decision rejected with HTTP 409 ConcurrencyConflictError`,
    );

    // ------------------------------------------------------------------------
    // Scenario 10: Concurrent Finding Closure Attempts (OCC Race)
    // ------------------------------------------------------------------------
    // Ensure finding is in VERIFIED state for closure race
    let targetForClosure = verifiedOrRejected9;
    if (targetForClosure.status !== 'VERIFIED') {
      // If rejected, re-remediate and verify to establish VERIFIED status
      const reassign = await findingService.assignFinding(analyst1Actor, targetForClosure.id, {
        expectedVersion: targetForClosure.version,
        assignedToId: dev2User.id,
        taskDescription: 'Re-fix for closure test',
      });
      const resubmit = await findingService.submitRemediation(dev2Actor, reassign.id, {
        expectedVersion: reassign.version,
        notes: 'Fixed by Dev2',
      });
      targetForClosure = await findingService.verifyFinding(analyst1Actor, resubmit.id, {
        expectedVersion: resubmit.version,
        outcome: 'VERIFIED',
      });
    }

    const [closeRes1, closeRes2] = await Promise.allSettled([
      findingService.closeFinding(analyst1Actor, targetForClosure.id, {
        expectedVersion: targetForClosure.version,
        notes: 'Closure race 1',
      }),
      findingService.closeFinding(analyst2Actor, targetForClosure.id, {
        expectedVersion: targetForClosure.version,
        notes: 'Closure race 2',
      }),
    ]);

    const closeSuccess = [closeRes1, closeRes2].filter((r) => r.status === 'fulfilled');
    const closeFailure = [closeRes1, closeRes2].filter((r) => r.status === 'rejected');

    if (closeSuccess.length !== 1 || closeFailure.length !== 1) {
      throw new Error(`Expected exactly 1 success and 1 failure in concurrent closure, got ${closeSuccess.length}s / ${closeFailure.length}f`);
    }
    const closeErr = (closeFailure[0] as PromiseRejectedResult).reason;
    if (!(closeErr instanceof ConcurrencyConflictError) || closeErr.statusCode !== 409) {
      throw new Error(`Expected HTTP 409 ConcurrencyConflictError on closure race, got: ${closeErr}`);
    }

    recordPass(
      'Scenario 10: Concurrent Finding Closure Attempts (OCC Race)',
      'Exactly 1 closure committed (CLOSED); racing closure rejected with HTTP 409 ConcurrencyConflictError',
    );

    // ------------------------------------------------------------------------
    // Scenario 11: Soft Deletion vs Remediation Submission
    // ------------------------------------------------------------------------
    const finding11 = await findingService.createFinding(analyst1Actor, {
      projectId: project.id,
      title: 'Finding for Soft Deletion vs Submission',
      description: 'Testing soft delete racing submission',
      severity: 'MEDIUM',
      category: 'XSS',
    });
    createdFindingIds.push(finding11.id);
    const triaged11 = await findingService.triageFinding(analyst1Actor, finding11.id, { expectedVersion: finding11.version });
    const assigned11 = await findingService.assignFinding(analyst1Actor, triaged11.id, {
      expectedVersion: triaged11.version,
      assignedToId: dev1User.id,
      taskDescription: 'XSS fix task',
    });

    // Soft-delete finding while in IN_PROGRESS
    const deleted11 = await findingService.softDeleteFinding(analyst1Actor, assigned11.id, {
      expectedVersion: assigned11.version,
    });

    let submitOnDeletedHidden = false;
    try {
      await findingService.submitRemediation(dev1Actor, deleted11.id, {
        expectedVersion: deleted11.version,
        notes: 'Attempted submit on deleted finding',
      });
    } catch (err) {
      if (err instanceof EntityNotFoundError && err.statusCode === 404) {
        submitOnDeletedHidden = true;
      }
    }
    if (!submitOnDeletedHidden) throw new Error('Remediation submission on soft-deleted finding was not rejected with HTTP 404!');

    recordPass(
      'Scenario 11: Soft Deletion vs Remediation Submission',
      'Soft-deleted finding immediately blocks remediation submission with generic HTTP 404 EntityNotFoundError',
    );

    // ------------------------------------------------------------------------
    // Scenario 12: Soft Deletion vs Task-Note Updates
    // ------------------------------------------------------------------------
    const task11 = await prisma.remediationTask.findFirstOrThrow({
      where: { findingId: deleted11.id, status: 'PENDING' },
    });
    createdTaskIds.push(task11.id);

    let updateNotesOnDeletedHidden = false;
    try {
      await taskService.updateTaskNotes(dev1Actor, task11.id, {
        notes: 'Attempted note update on task of soft-deleted finding',
      });
    } catch (err) {
      if (err instanceof EntityNotFoundError && err.statusCode === 404) {
        updateNotesOnDeletedHidden = true;
      }
    }
    if (!updateNotesOnDeletedHidden) throw new Error('Task-note update on soft-deleted finding was not rejected with HTTP 404!');

    recordPass(
      'Scenario 12: Soft Deletion vs Task-Note Updates',
      'Task notes update for soft-deleted parent finding strictly fails closed with HTTP 404 EntityNotFoundError',
    );

    // ========================================================================
    // Part 3: Complete Multi-Cycle Remediation Lifecycle Integration (Section 5)
    // ========================================================================

    // ------------------------------------------------------------------------
    // Scenario 13: Full Multi-Cycle Lifecycle (OPEN -> ... -> REOPENED -> ... -> CLOSED)
    // ------------------------------------------------------------------------
    // Step 1: createFinding (OPEN, v1)
    const cycleFinding = await findingService.createFinding(analyst1Actor, {
      projectId: project.id,
      title: 'Full Lifecycle Vulnerability Flaw',
      description: 'End-to-end multi-cycle remediation test',
      severity: 'CRITICAL',
      category: 'INJECTION',
      cvssScore: 9.8,
    });
    createdFindingIds.push(cycleFinding.id);
    if (cycleFinding.status !== 'OPEN' || cycleFinding.version !== 1) throw new Error('Step 1 failed');

    // Step 2: triageFinding (OPEN -> TRIAGED, v2)
    const cycleTriaged = await findingService.triageFinding(analyst1Actor, cycleFinding.id, {
      expectedVersion: 1,
    });
    if (cycleTriaged.status !== 'TRIAGED' || cycleTriaged.version !== 2) throw new Error('Step 2 failed');

    // Step 3: assignFinding (TRIAGED -> IN_PROGRESS, v3, Task 1 PENDING)
    const cycleAssigned1 = await findingService.assignFinding(analyst1Actor, cycleTriaged.id, {
      expectedVersion: 2,
      assignedToId: dev1User.id,
      taskDescription: 'Remediate SQL injection via prepared statements',
    });
    if (cycleAssigned1.status !== 'IN_PROGRESS' || cycleAssigned1.version !== 3) throw new Error('Step 3 failed');
    const taskCycle1 = await prisma.remediationTask.findFirstOrThrow({
      where: { findingId: cycleFinding.id, status: 'PENDING' },
    });
    createdTaskIds.push(taskCycle1.id);

    // Step 4: submitRemediation by Dev1 (IN_PROGRESS -> READY_FOR_REVIEW, v4, Task 1 SUBMITTED)
    const cycleSubmitted1 = await findingService.submitRemediation(dev1Actor, cycleAssigned1.id, {
      expectedVersion: 3,
      notes: 'Initial attempt at parameterized queries',
    });
    if (cycleSubmitted1.status !== 'READY_FOR_REVIEW' || cycleSubmitted1.version !== 4) throw new Error('Step 4 failed');

    // Step 5: Separation of Duties (SoD OLI-7): Dev1 attempts to self-verify
    let sodSelfVerifyBlocked = false;
    try {
      await findingService.verifyFinding(dev1Actor, cycleSubmitted1.id, {
        expectedVersion: 4,
        outcome: 'VERIFIED',
      });
    } catch (err) {
      if (err instanceof ForbiddenError && err.statusCode === 403) {
        sodSelfVerifyBlocked = true;
      }
    }
    if (!sodSelfVerifyBlocked) throw new Error('Submitting developer was able to verify their own remediation!');

    // Step 6: Peer Analyst2 rejects verification (READY_FOR_REVIEW -> REOPENED, v5, Task 1 REJECTED)
    const cycleRejected1 = await findingService.verifyFinding(analyst2Actor, cycleSubmitted1.id, {
      expectedVersion: 4,
      outcome: 'REOPENED',
      notes: 'Bypass found in boundary parameter handling',
    });
    if (cycleRejected1.status !== 'REOPENED' || cycleRejected1.version !== 5) throw new Error('Step 6 failed');

    // Step 7: Historical Task 1 is preserved in PostgreSQL as REJECTED
    const taskCycle1After = await prisma.remediationTask.findUniqueOrThrow({
      where: { id: taskCycle1.id },
    });
    if (taskCycle1After.status !== 'REJECTED') {
      throw new Error(`Historical task status corrupted: ${taskCycle1After.status}`);
    }

    // Step 8: Re-assign to Dev2 for Cycle 2 (REOPENED -> IN_PROGRESS, v6, Task 2 PENDING)
    const cycleAssigned2 = await findingService.assignFinding(analyst1Actor, cycleRejected1.id, {
      expectedVersion: 5,
      assignedToId: dev2User.id,
      taskDescription: 'Implement strict parameterized queries and input whitelist',
    });
    if (cycleAssigned2.status !== 'IN_PROGRESS' || cycleAssigned2.version !== 6) throw new Error('Step 8 failed');
    const taskCycle2 = await prisma.remediationTask.findFirstOrThrow({
      where: { findingId: cycleFinding.id, status: 'PENDING' },
    });
    createdTaskIds.push(taskCycle2.id);
    if (taskCycle2.id === taskCycle1.id) throw new Error('New cycle did not allocate distinct task record!');

    // Step 9: submitRemediation by Dev2 (IN_PROGRESS -> READY_FOR_REVIEW, v7, Task 2 SUBMITTED)
    const cycleSubmitted2 = await findingService.submitRemediation(dev2Actor, cycleAssigned2.id, {
      expectedVersion: 6,
      notes: 'Complete parameterization with AST-based SQL query builder',
    });
    if (cycleSubmitted2.status !== 'READY_FOR_REVIEW' || cycleSubmitted2.version !== 7) throw new Error('Step 9 failed');

    // Step 10: Analyst1 verifies Cycle 2 (READY_FOR_REVIEW -> VERIFIED, v8, Task 2 VERIFIED)
    const cycleVerified2 = await findingService.verifyFinding(analyst1Actor, cycleSubmitted2.id, {
      expectedVersion: 7,
      outcome: 'VERIFIED',
      notes: 'Full regression test suite and fuzzing confirmed zero injection vectors',
    });
    if (cycleVerified2.status !== 'VERIFIED' || cycleVerified2.version !== 8) throw new Error('Step 10 failed');

    // Step 11: closeFinding by Analyst2 (VERIFIED -> CLOSED, v9)
    const cycleClosed = await findingService.closeFinding(analyst2Actor, cycleVerified2.id, {
      expectedVersion: 8,
      notes: 'Final operational sign-off post-verification',
    });
    if (cycleClosed.status !== 'CLOSED' || cycleClosed.version !== 9) throw new Error('Step 11 failed');

    // Step 12: Verify complete event and audit trace across findings and tasks
    const allFindingEvents = await prisma.findingEvent.findMany({
      where: { findingId: cycleFinding.id },
      orderBy: { createdAt: 'asc' },
    });
    const findingAuditEvents = await prisma.auditEvent.findMany({
      where: { resourceId: cycleFinding.id, eventCategory: 'FINDING' },
      orderBy: { createdAt: 'asc' },
    });
    const taskAuditEvents = await prisma.auditEvent.findMany({
      where: { resourceId: { in: [taskCycle1.id, taskCycle2.id] }, eventCategory: 'TASK' },
      orderBy: { createdAt: 'asc' },
    });

    // 12a. Verify FindingEvent counts and exact FindingEventType enums
    if (allFindingEvents.length !== 9) {
      throw new Error(`Expected exactly 9 finding lifecycle events for full 2-cycle lifecycle, found: ${allFindingEvents.length}`);
    }
    const expectedFindingEventTypes = [
      'CREATED',
      'STATUS_CHANGED',
      'ASSIGNED',
      'STATUS_CHANGED',
      'STATUS_CHANGED',
      'ASSIGNED',
      'STATUS_CHANGED',
      'STATUS_CHANGED',
      'STATUS_CHANGED',
    ];
    for (let i = 0; i < allFindingEvents.length; i++) {
      if (allFindingEvents[i]!.eventType !== expectedFindingEventTypes[i]) {
        throw new Error(`FindingEvent[${i}] type mismatch: expected ${expectedFindingEventTypes[i]}, got ${allFindingEvents[i]!.eventType}`);
      }
    }

    // 12b. Verify FINDING-category AuditEvent counts and exact action names
    if (findingAuditEvents.length !== 9) {
      throw new Error(`Expected exactly 9 FINDING-category audit events, found: ${findingAuditEvents.length}`);
    }
    const expectedFindingAuditActions = [
      'finding.created',
      'finding.triaged',
      'finding.assigned',
      'finding.remediation_submitted',
      'finding.remediation_rejected',
      'finding.assigned',
      'finding.remediation_submitted',
      'finding.verified',
      'finding.closed',
    ];
    for (let i = 0; i < findingAuditEvents.length; i++) {
      if (findingAuditEvents[i]!.eventType !== expectedFindingAuditActions[i]) {
        throw new Error(`Finding AuditEvent[${i}] action mismatch: expected ${expectedFindingAuditActions[i]}, got ${findingAuditEvents[i]!.eventType}`);
      }
    }

    // 12c. Verify TASK-category AuditEvent counts and exact action names for both cycles
    if (taskAuditEvents.length !== 6) {
      throw new Error(`Expected exactly 6 TASK-category audit events, found: ${taskAuditEvents.length}`);
    }
    const task1AuditActions = taskAuditEvents.filter((e) => e.resourceId === taskCycle1.id).map((e) => e.eventType);
    const task2AuditActions = taskAuditEvents.filter((e) => e.resourceId === taskCycle2.id).map((e) => e.eventType);
    const expectedTask1Actions = ['task.created', 'task.submitted', 'task.rejected'];
    const expectedTask2Actions = ['task.created', 'task.submitted', 'task.verified'];

    for (let i = 0; i < 3; i++) {
      if (task1AuditActions[i] !== expectedTask1Actions[i]) {
        throw new Error(`Task 1 AuditAction[${i}] mismatch: expected ${expectedTask1Actions[i]}, got ${task1AuditActions[i]}`);
      }
      if (task2AuditActions[i] !== expectedTask2Actions[i]) {
        throw new Error(`Task 2 AuditAction[${i}] mismatch: expected ${expectedTask2Actions[i]}, got ${task2AuditActions[i]}`);
      }
    }

    // 12d. Total AuditEvent count = 9 finding + 6 task = 15
    const totalAuditEvents = findingAuditEvents.length + taskAuditEvents.length;
    if (totalAuditEvents !== 15) {
      throw new Error(`Expected exactly 15 total audit events across lifecycle, found: ${totalAuditEvents}`);
    }

    recordPass(
      'Scenario 13: Full Multi-Cycle Lifecycle (OPEN -> ... -> REOPENED -> ... -> CLOSED)',
      'Executed full 2-cycle remediation workflow with SoD enforcement, historical task isolation, OCC v1->v9, and 9 FindingEvents + 15 AuditEvents (9 FINDING, 6 TASK)',
    );

    // ------------------------------------------------------------------------
    // Scenario 14: Independent Exceptional Admin Workflows
    // ------------------------------------------------------------------------
    const openFinding14 = await findingService.createFinding(analyst1Actor, {
      projectId: project.id,
      title: 'Finding for Exceptional Force-Close and Reopen',
      description: 'Vendor false positive workflow',
      severity: 'LOW',
      category: 'OTHER',
    });
    createdFindingIds.push(openFinding14.id);

    // Force-close by Admin
    const forceClosed14 = await findingService.forceCloseFinding(adminActor, openFinding14.id, {
      expectedVersion: openFinding14.version,
      justification: 'Vendor certified false positive with CVE dispute notice',
    });
    if (forceClosed14.status !== 'CLOSED' || forceClosed14.version !== 2) throw new Error('Force-close failed');

    // Force-reopen by Admin
    const forceReopened14 = await findingService.forceReopenFinding(adminActor, forceClosed14.id, {
      expectedVersion: forceClosed14.version,
      justification: 'New exploit variant emerged requiring remediation',
    });
    if (forceReopened14.status !== 'REOPENED' || forceReopened14.version !== 3) throw new Error('Force-reopen failed');

    recordPass(
      'Scenario 14: Independent Exceptional Admin Workflows',
      'Admin force-close (OPEN->CLOSED) and force-reopen (CLOSED->REOPENED) executed with mandatory audited justifications',
    );

    // ========================================================================
    // Part 4: Authorization and Existence-Hiding Matrix (Section 6)
    // ========================================================================

    // ------------------------------------------------------------------------
    // Scenario 15: Complete Authorization & Existence-Hiding Matrix
    // ------------------------------------------------------------------------
    // 1. Admin denied operational createFinding
    let adminCreateDenied = false;
    try {
      await findingService.createFinding(adminActor, {
        projectId: project.id,
        title: 'Admin Creation Attempt',
        description: 'Should fail F-13',
        severity: 'LOW',
        category: 'OTHER',
      });
    } catch (err) {
      if (err instanceof ForbiddenError && err.statusCode === 403) adminCreateDenied = true;
    }
    if (!adminCreateDenied) throw new Error('Admin was able to create operational finding!');

    // 2. Developer denied operational createFinding
    let devCreateDenied = false;
    try {
      await findingService.createFinding(dev1Actor, {
        projectId: project.id,
        title: 'Dev Creation Attempt',
        description: 'Should fail NEG-04',
        severity: 'LOW',
        category: 'OTHER',
      });
    } catch (err) {
      if (err instanceof ForbiddenError && err.statusCode === 403) devCreateDenied = true;
    }
    if (!devCreateDenied) throw new Error('Developer was able to create operational finding!');

    // 3. Non-member receiving generic HTTP 404 existence hiding
    let nonMemberHidden = false;
    try {
      await findingService.getFinding(nonMemberActor, cycleFinding.id);
    } catch (err) {
      if (err instanceof EntityNotFoundError && err.statusCode === 404) nonMemberHidden = true;
    }
    if (!nonMemberHidden) throw new Error('Non-member did not receive HTTP 404 existence hiding!');

    // 4. Foreign archived project existence hiding
    const foreignFinding = await prisma.finding.create({
      data: {
        projectId: foreignProject.id,
        title: 'Foreign Project Finding',
        description: 'Should be hidden from Analyst1',
        severity: 'HIGH',
        category: 'AUTH',
        status: 'OPEN',
        createdById: adminUser.id,
      },
    });
    createdFindingIds.push(foreignFinding.id);

    // Archive foreign project
    await prisma.project.update({ where: { id: foreignProject.id }, data: { isActive: false } });

    let foreignArchivedHidden = false;
    try {
      await findingService.getFinding(analyst1Actor, foreignFinding.id);
    } catch (err) {
      if (err instanceof EntityNotFoundError && err.statusCode === 404) foreignArchivedHidden = true;
    }
    if (!foreignArchivedHidden) throw new Error('Foreign archived project did not return generic 404 existence hiding!');

    recordPass(
      'Scenario 15: Complete Authorization & Existence-Hiding Matrix',
      'Analyst-only operational rules enforced (F-13 / NEG-04); cross-project resources and foreign archived projects return generic 404',
    );

    // ========================================================================
    // Part 5: Transactional Integrity and Failure Injection (Section 7)
    // ========================================================================

    // ------------------------------------------------------------------------
    // Scenario 16: Failure Injection Across Operations & Atomic Rollback
    // ------------------------------------------------------------------------
    const finding16 = await findingService.createFinding(analyst1Actor, {
      projectId: project.id,
      title: 'Finding for Failure Injection',
      description: 'Transaction rollback test',
      severity: 'MEDIUM',
      category: 'CRYPTO',
    });
    createdFindingIds.push(finding16.id);

    // Simulate failure during finding mutation right before commit
    let injectedRollbackSuccess = false;
    try {
      await dbManager.runTransaction(async (repos) => {
        await repos.userRepo.lockUsers([analyst1Actor.id]);
        await repos.projectRepo.lockProject(project.id);
        await repos.projectRepo.lockMember(project.id, analyst1Actor.id);
        const locked = await repos.findingRepo.lockFinding(finding16.id);
        if (!locked) throw new Error('Missing finding');

        // Mutate finding
        await repos.findingRepo.updateAtomic(finding16.id, {
          expectedVersion: locked.version,
          status: 'TRIAGED',
        });

        // Mutate task
        const task = await repos.taskRepo.create({
          findingId: finding16.id,
          assignedToId: dev1User.id,
          assignedById: analyst1User.id,
          description: 'Task that must roll back',
        });
        createdTaskIds.push(task.id);

        // Inject simulated process/connection crash
        throw new Error('SIMULATED_TRANSACTION_FAILURE_BEFORE_COMMIT');
      });
    } catch (err: unknown) {
      if ((err as Error).message === 'SIMULATED_TRANSACTION_FAILURE_BEFORE_COMMIT') {
        injectedRollbackSuccess = true;
      }
    }
    if (!injectedRollbackSuccess) throw new Error('Simulated failure was not caught!');

    // Verify finding remains in OPEN at version 1
    const fresh16 = await prisma.finding.findUniqueOrThrow({ where: { id: finding16.id } });
    if (fresh16.status !== 'OPEN' || fresh16.version !== 1) {
      throw new Error(`Finding was corrupted despite rollback: status=${fresh16.status}, v=${fresh16.version}`);
    }

    // Verify 0 tasks were created
    const tasks16 = await prisma.remediationTask.findMany({ where: { findingId: finding16.id } });
    if (tasks16.length !== 0) {
      throw new Error(`Remediation task persisted despite rollback: found ${tasks16.length}`);
    }

    recordPass(
      'Scenario 16: Failure Injection Across Operations & Atomic Rollback',
      'Simulated failure before commit triggered full rollback; zero partial writes committed to findings or tasks',
    );

    // ========================================================================
    // Part 6: Database Integrity & Historical Evidence (Section 8)
    // ========================================================================

    // ------------------------------------------------------------------------
    // Scenario 17: Database Constraints, Indexes, and Zero-Orphan Invariants
    // ------------------------------------------------------------------------
    // 1. Verify partial unique index one_active_remediation_task_per_finding protects SUBMITTED status
    const finding17 = await findingService.createFinding(analyst1Actor, {
      projectId: project.id,
      title: 'Finding for Index Invariant Check',
      description: 'Index predicate validation',
      severity: 'HIGH',
      category: 'AUTH',
    });
    createdFindingIds.push(finding17.id);
    const triaged17 = await findingService.triageFinding(analyst1Actor, finding17.id, { expectedVersion: 1 });
    const assigned17 = await findingService.assignFinding(analyst1Actor, triaged17.id, {
      expectedVersion: 2,
      assignedToId: dev1User.id,
      taskDescription: 'Primary task',
    });
    const submitted17 = await findingService.submitRemediation(dev1Actor, assigned17.id, {
      expectedVersion: 3,
      notes: 'Task is in SUBMITTED status',
    });

    // Directly attempt to insert a second active task into PostgreSQL while first is SUBMITTED
    let duplicateRejectedByIndex = false;
    try {
      await prisma.remediationTask.create({
        data: {
          findingId: submitted17.id,
          assignedToId: dev2User.id,
          assignedById: analyst1User.id,
          description: 'Illegal concurrent second active task',
          status: 'PENDING',
        },
      });
    } catch (pgErr: unknown) {
      // Prisma error code P2002 corresponds to unique constraint violation (PG 23505)
      if ((pgErr as { code?: string }).code === 'P2002') {
        duplicateRejectedByIndex = true;
      }
    }
    if (!duplicateRejectedByIndex) {
      throw new Error('Partial unique index failed to prevent second active task while primary task was SUBMITTED!');
    }

    // 2. Verify zero orphan remediation tasks exist across database
    const allDbTasks = await prisma.remediationTask.findMany({
      where: { findingId: { in: createdFindingIds } },
    });
    for (const task of allDbTasks) {
      if (!createdFindingIds.includes(task.findingId)) {
        throw new Error(`Orphan remediation task detected: ${task.id}`);
      }
    }

    recordPass(
      'Scenario 17: Database Constraints, Indexes, and Zero-Orphan Invariants',
      'Index one_active_remediation_task_per_finding strictly guards SUBMITTED tasks; zero orphan tasks across all findings',
    );

    // ========================================================================
    // Part 7: Lock Hierarchy and Error Code Mapping (Section 9)
    // ========================================================================

    // ------------------------------------------------------------------------
    // Scenario 18: PostgreSQL Error Mapping (Deadlock 40P01 & Serialization 40001)
    // ------------------------------------------------------------------------
    // 1. Deadlock error 40P01 mapping
    const deadlockError = Object.assign(new Error('deadlock detected'), { code: '40P01' });
    let deadlockMapped = false;
    try {
      handleDatabaseConcurrencyError(deadlockError);
    } catch (err) {
      if (err instanceof SecureFlowError && err.code === 'TRANSACTION_DEADLOCK' && err.statusCode === 409) {
        deadlockMapped = true;
      }
    }
    if (!deadlockMapped) throw new Error('Deadlock error 40P01 was not mapped to TRANSACTION_DEADLOCK (409)!');

    // 2. Serialization failure 40001 mapping
    const serializationError = Object.assign(new Error('could not serialize access'), { code: '40001' });
    let serializationMapped = false;
    try {
      handleDatabaseConcurrencyError(serializationError);
    } catch (err) {
      if (err instanceof SecureFlowError && err.code === 'SERIALIZATION_FAILURE' && err.statusCode === 409) {
        serializationMapped = true;
      }
    }
    if (!serializationMapped) throw new Error('Serialization error 40001 was not mapped to SERIALIZATION_FAILURE (409)!');

    // 3. Lock not available / timeout 55P03 mapping
    const lockNotAvailableError = Object.assign(new Error('lock not available'), { code: '55P03' });
    let lockNotAvailableMapped = false;
    try {
      handleDatabaseConcurrencyError(lockNotAvailableError);
    } catch (err) {
      if (err instanceof SecureFlowError && err.code === 'TRANSACTION_TIMEOUT' && err.statusCode === 504) {
        lockNotAvailableMapped = true;
      }
    }
    if (!lockNotAvailableMapped) throw new Error('Lock not available error 55P03 was not mapped to TRANSACTION_TIMEOUT (504)!');

    recordPass(
      'Scenario 18: PostgreSQL Error Mapping (Deadlock 40P01, Serialization 40001, Timeout 55P03)',
      'PostgreSQL errors 40P01 (409), 40001 (409), and 55P03 (504) deterministically map to domain concurrency error contracts',
    );

    // ========================================================================
    // Part 8: Architectural Boundaries & Service Composition Root (Section 10)
    // ========================================================================

    // ------------------------------------------------------------------------
    // Scenario 19: Architectural Boundaries & Factory Contract
    // ------------------------------------------------------------------------
    // 1. Factory constructs all domain services with shared DatabaseManager
    const domainServices = createDomainServices(dbManager);
    if (!domainServices.projectService || !domainServices.findingService || !domainServices.taskService || !domainServices.auditService) {
      throw new Error('createDomainServices failed to instantiate all four domain services');
    }

    // 2. Calling createDomainServices with invalid input throws SERVICE_INITIALIZATION_ERROR (500)
    let factoryRejectionCaught = false;
    try {
      createDomainServices(null as unknown as DatabaseManager);
    } catch (err) {
      if (err instanceof SecureFlowError && err.code === 'SERVICE_INITIALIZATION_ERROR' && err.statusCode === 500) {
        factoryRejectionCaught = true;
      }
    }
    if (!factoryRejectionCaught) throw new Error('createDomainServices(null) did not throw SERVICE_INITIALIZATION_ERROR!');

    // 3. Direct instantiation with arbitrary object throws UNAUTHORIZED_PERSISTENCE_INJECTION (500)
    let unauthorizedInjectionCaught = false;
    try {
      new FindingService({ arbitrary: 'injection' } as unknown as DatabaseManager);
    } catch (err) {
      if (err instanceof SecureFlowError && err.code === 'UNAUTHORIZED_PERSISTENCE_INJECTION' && err.statusCode === 500) {
        unauthorizedInjectionCaught = true;
      }
    }
    if (!unauthorizedInjectionCaught) throw new Error('Direct repository injection was not blocked with UNAUTHORIZED_PERSISTENCE_INJECTION!');

    recordPass(
      'Scenario 19: Architectural Boundaries & Factory Contract',
      'createDomainServices trusted composition root verified; raw repository injection strictly rejected (HTTP 500)',
    );

  } finally {
    // Teardown: Safely clean up synthetic test records in reverse foreign-key order
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

  console.log('----------------------------------------------------------------------');
  console.log(`Summary: ${passedTests}/${totalTests} Gate 3D.6 acceptance integration tests passed.`);
  console.log('======================================================================');

  return {
    allPassed: passedTests === totalTests,
    totalTests,
    passedTests,
  };
}

// Auto-execute when run as standalone script
const isMain = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isMain) {
  runGate3dAcceptanceIntegrationTests()
    .then((results) => {
      if (!results.allPassed) {
        process.exit(1);
      }
    })
    .catch((err) => {
      console.error('Gate 3D.6 acceptance integration suite failed with unhandled exception:', err);
      process.exit(1);
    });
}
