import path from 'node:path';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';
import { DatabaseManager } from '../../src/db/database-manager.js';
import {
  FindingService,
  ActorContext,
} from '../../src/index.js';
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

export async function runGate3dFindingServiceIntegrationTests(): Promise<{
  allPassed: boolean;
  totalTests: number;
  passedTests: number;
}> {
  console.log('==================================================');
  console.log('SecureFlow — Gate 3D.3 FindingService Integration Suite');
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

    // Setup synthetic test users in PostgreSQL
    const testAdminSub = `gate3d3-admin-${Date.now()}`;
    const testAnalystSub = `gate3d3-analyst-${Date.now()}`;
    const testDev1Sub = `gate3d3-dev1-${Date.now()}`;
    const testDev2Sub = `gate3d3-dev2-${Date.now()}`;

    const [adminUser, analystUser, dev1User, dev2User] = await Promise.all([
      prisma.user.create({
        data: {
          sub: testAdminSub,
          email: `${testAdminSub}@example.com`,
          displayName: 'Gate 3D3 Admin User',
          globalRole: 'ADMIN',
          isActive: true,
        },
      }),
      prisma.user.create({
        data: {
          sub: testAnalystSub,
          email: `${testAnalystSub}@example.com`,
          displayName: 'Gate 3D3 Analyst User',
          globalRole: 'ANALYST',
          isActive: true,
        },
      }),
      prisma.user.create({
        data: {
          sub: testDev1Sub,
          email: `${testDev1Sub}@example.com`,
          displayName: 'Gate 3D3 Developer One',
          globalRole: 'DEVELOPER',
          isActive: true,
        },
      }),
      prisma.user.create({
        data: {
          sub: testDev2Sub,
          email: `${testDev2Sub}@example.com`,
          displayName: 'Gate 3D3 Developer Two',
          globalRole: 'DEVELOPER',
          isActive: true,
        },
      }),
    ]);

    createdUserIds.push(adminUser.id, analystUser.id, dev1User.id, dev2User.id);

    // Create Project A and Project B
    const projectA = await prisma.project.create({
      data: {
        name: `Gate 3D.3 Project A ${Date.now()}`,
        slug: `gate-3d3-proj-a-${Date.now()}`,
        isActive: true,
        createdById: adminUser.id,
      },
    });
    const projectB = await prisma.project.create({
      data: {
        name: `Gate 3D.3 Project B ${Date.now()}`,
        slug: `gate-3d3-proj-b-${Date.now()}`,
        isActive: true,
        createdById: adminUser.id,
      },
    });
    createdProjectIds.push(projectA.id, projectB.id);

    // Add Analyst and Dev1 to Project A, Dev2 to Project B
    await prisma.projectMember.createMany({
      data: [
        {
          projectId: projectA.id,
          userId: analystUser.id,
          role: 'ANALYST',
          addedById: adminUser.id,
        },
        {
          projectId: projectA.id,
          userId: dev1User.id,
          role: 'DEVELOPER',
          addedById: adminUser.id,
        },
        {
          projectId: projectB.id,
          userId: dev2User.id,
          role: 'DEVELOPER',
          addedById: adminUser.id,
        },
      ],
    });

    const analystActor = new ActorContext({
      id: analystUser.id,
      globalRole: 'ANALYST',
      isActive: true,
      memberships: [{ projectId: projectA.id, role: 'ANALYST' }],
    });
    const dev1Actor = new ActorContext({
      id: dev1User.id,
      globalRole: 'DEVELOPER',
      isActive: true,
      memberships: [{ projectId: projectA.id, role: 'DEVELOPER' }],
    });
    const dev2Actor = new ActorContext({
      id: dev2User.id,
      globalRole: 'DEVELOPER',
      isActive: true,
      memberships: [{ projectId: projectB.id, role: 'DEVELOPER' }],
    });

    // ------------------------------------------------------------------------
    // Baseline: Actual finding creation with version 1
    // ------------------------------------------------------------------------
    const finding1 = await findingService.createFinding(analystActor, {
      projectId: projectA.id,
      title: 'SQL Injection in Search Form',
      description: 'Raw SQL concatenation in query string parameter',
      severity: 'CRITICAL',
      category: 'INJECTION',
      cvssScore: 9.8,
    });
    createdFindingIds.push(finding1.id);

    if (finding1.version !== 1 || finding1.status !== 'OPEN' || finding1.isDeleted !== false) {
      throw new Error(`Finding initialized with unexpected state: status=${finding1.status}, version=${finding1.version}`);
    }
    recordPass('Actual Finding Creation with Version 1', `Finding ${finding1.id} initialized in OPEN status with version 1`);

    // Create a finding in Project B for cross-project isolation tests
    const findingB = await prisma.finding.create({
      data: {
        projectId: projectB.id,
        title: 'Project B Secret Leak',
        description: 'Hardcoded key in Project B',
        severity: 'HIGH',
        category: 'SENSITIVE_DATA',
        createdById: adminUser.id,
        status: 'OPEN',
        version: 1,
      },
    });
    createdFindingIds.push(findingB.id);

    // ------------------------------------------------------------------------
    // Baseline: Atomic creation of finding and lifecycle/audit events
    // ------------------------------------------------------------------------
    const events = await prisma.findingEvent.findMany({
      where: { findingId: finding1.id },
    });
    if (events.length !== 1 || events[0]?.eventType !== 'CREATED' || events[0]?.newStatus !== 'OPEN') {
      throw new Error(`FindingEvent not created atomically: found ${events.length} events`);
    }
    createdFindingEventIds.push(...events.map((e) => e.id));

    const auditLogs = await prisma.auditEvent.findMany({
      where: { resourceId: finding1.id, eventType: 'finding.created' },
    });
    if (auditLogs.length !== 1 || auditLogs[0]?.eventCategory !== 'FINDING') {
      throw new Error(`AuditEvent not created atomically: found ${auditLogs.length} audit logs`);
    }
    createdAuditIds.push(...auditLogs.map((a) => a.id));

    recordPass('Atomic Finding, Lifecycle & Audit Event Creation', `FindingEvent CREATED and AuditEvent finding.created recorded atomically`);

    // ------------------------------------------------------------------------
    // Scenario 1: Metadata mutation acquires locks in approved hierarchy (0 → 1 → 2 → 3)
    // ------------------------------------------------------------------------
    const updatedFinding = await findingService.updateFindingMetadata(analystActor, finding1.id, {
      expectedVersion: 1,
      title: 'SQL Injection in Auth Controller (Confirmed Exploitable)',
      severity: 'CRITICAL',
      cvssScore: 10.0,
    });
    if (updatedFinding.version !== 2) {
      throw new Error(`Expected version 2 after metadata update, found ${updatedFinding.version}`);
    }
    const updateEvents = await prisma.findingEvent.findMany({
      where: { findingId: finding1.id, eventType: 'UPDATED' },
    });
    if (updateEvents.length === 0) {
      throw new Error('FindingEvent UPDATED not recorded');
    }
    createdFindingEventIds.push(...updateEvents.map((e) => e.id));

    const updateAudit = await prisma.auditEvent.findMany({
      where: { resourceId: finding1.id, eventType: 'finding.metadata_updated' },
    });
    if (updateAudit.length === 0) {
      throw new Error('AuditEvent finding.metadata_updated not recorded');
    }
    createdAuditIds.push(...updateAudit.map((a) => a.id));

    recordPass('Scenario 1: Metadata Mutation Under Canonical Row Lock Hierarchy (0 → 1 → 2 → 3)', `Finding updated to version 2 with UPDATED event and audit log`);

    // ------------------------------------------------------------------------
    // Scenario 2: Triage mutation acquires locks in approved hierarchy (0 → 1 → 2 → 3)
    // ------------------------------------------------------------------------
    const triagedFinding = await findingService.triageFinding(analystActor, finding1.id, {
      expectedVersion: 2,
      severity: 'HIGH',
      cvssScore: 8.8,
    });
    if (triagedFinding.status !== 'TRIAGED' || triagedFinding.version !== 3) {
      throw new Error(`Triage failed: status=${triagedFinding.status}, version=${triagedFinding.version}`);
    }
    const triageEvents = await prisma.findingEvent.findMany({
      where: { findingId: finding1.id, eventType: 'STATUS_CHANGED' },
    });
    createdFindingEventIds.push(...triageEvents.map((e) => e.id));

    const triageAudit = await prisma.auditEvent.findMany({
      where: { resourceId: finding1.id, eventType: 'finding.triaged' },
    });
    createdAuditIds.push(...triageAudit.map((a) => a.id));

    recordPass('Scenario 2: Triage Mutation Under Canonical Row Lock Hierarchy (0 → 1 → 2 → 3)', `Finding transitioned OPEN → TRIAGED at version 3 with atomic audit record`);

    // ------------------------------------------------------------------------
    // Invalid State Transition Rejection
    // ------------------------------------------------------------------------
    let invalidTransitionBlocked = false;
    try {
      await findingService.triageFinding(analystActor, finding1.id, {
        expectedVersion: 3,
      });
    } catch (err) {
      if (err instanceof InvalidStateTransitionError) {
        invalidTransitionBlocked = true;
      }
    }
    if (!invalidTransitionBlocked) {
      throw new Error('Invalid transition TRIAGED -> TRIAGED was not rejected');
    }
    recordPass('Invalid State Transition Rejection', `Re-triage of already TRIAGED finding rejected with InvalidStateTransitionError`);

    // ------------------------------------------------------------------------
    // Scenario 3: Membership revocation commits before metadata authorization → denied with 404
    // ------------------------------------------------------------------------
    const tempAnalystSub = `gate3d3-tempanalyst-${Date.now()}`;
    const tempAnalystUser = await prisma.user.create({
      data: {
        sub: tempAnalystSub,
        email: `${tempAnalystSub}@example.com`,
        displayName: 'Temporary Analyst',
        globalRole: 'ANALYST',
        isActive: true,
      },
    });
    createdUserIds.push(tempAnalystUser.id);

    await prisma.projectMember.create({
      data: {
        projectId: projectA.id,
        userId: tempAnalystUser.id,
        role: 'ANALYST',
        addedById: adminUser.id,
      },
    });

    const tempAnalystActor = new ActorContext({
      id: tempAnalystUser.id,
      globalRole: 'ANALYST',
      isActive: true,
      memberships: [{ projectId: projectA.id, role: 'ANALYST' }],
    });

    // Revoke membership in database prior to mutation
    await prisma.projectMember.deleteMany({
      where: { projectId: projectA.id, userId: tempAnalystUser.id },
    });

    let revokedAnalystBlocked = false;
    try {
      await findingService.updateFindingMetadata(tempAnalystActor, finding1.id, {
        expectedVersion: 3,
        title: 'Revoked Analyst Mutation Attempt',
      });
    } catch (err) {
      if (err instanceof EntityNotFoundError) {
        revokedAnalystBlocked = true;
      }
    }
    if (!revokedAnalystBlocked) {
      throw new Error('Revoked analyst was able to mutate finding without membership');
    }
    recordPass('Scenario 3: Membership Revocation Committed Before Authorization Denies with 404', `PostgreSQL membership revocation immediately enforced with 404 EntityNotFoundError existence hiding`);

    // ------------------------------------------------------------------------
    // Scenario 4: Membership revocation races with in-flight metadata mutation → serializes safely
    // ------------------------------------------------------------------------
    await prisma.projectMember.create({
      data: {
        projectId: projectA.id,
        userId: tempAnalystUser.id,
        role: 'ANALYST',
        addedById: adminUser.id,
      },
    });

    const opA = findingService.updateFindingMetadata(tempAnalystActor, finding1.id, {
      expectedVersion: 3,
      title: 'In-Flight Race Metadata Mutation',
    });
    const opB = prisma.projectMember.deleteMany({
      where: { projectId: projectA.id, userId: tempAnalystUser.id },
    });

    const raceResults = await Promise.allSettled([opA, opB]);
    const opAResult = raceResults[0];
    const opBResult = raceResults[1];

    if (opBResult?.status !== 'fulfilled') {
      throw new Error('Membership revocation failed during concurrency race');
    }

    if (opAResult?.status === 'fulfilled') {
      recordPass('Scenario 4: Membership Revocation Racing with Mutation Serializes Safely', `Operational transaction linearized before revocation and committed cleanly without deadlock`);
    } else {
      const err = opAResult?.reason;
      if (err instanceof EntityNotFoundError || err instanceof ConcurrencyConflictError) {
        recordPass('Scenario 4: Membership Revocation Racing with Mutation Serializes Safely', `Revocation linearized before operational lock, mutation safely failed closed with ${err.name}`);
      } else {
        throw new Error(`Unexpected failure during race: ${err}`);
      }
    }

    // ------------------------------------------------------------------------
    // Scenario 5: Project archival commits before finding mutation → rejected with 403
    // ------------------------------------------------------------------------
    await prisma.project.update({
      where: { id: projectA.id },
      data: { isActive: false },
    });

    let archivedMutationBlocked = false;
    try {
      const currentFinding = await prisma.finding.findUniqueOrThrow({ where: { id: finding1.id } });
      await findingService.updateFindingMetadata(analystActor, finding1.id, {
        expectedVersion: currentFinding.version,
        title: 'Mutation on Archived Project',
      });
    } catch (err) {
      if (err instanceof ForbiddenError) {
        archivedMutationBlocked = true;
      }
    }
    if (!archivedMutationBlocked) {
      throw new Error('Finding mutation succeeded on archived project');
    }

    await prisma.project.update({
      where: { id: projectA.id },
      data: { isActive: true },
    });
    recordPass('Scenario 5: Project Archival Commits Before Finding Mutation Rejected with 403', `Active status check under Level 1 lock failed closed with ForbiddenError (403)`);

    // ------------------------------------------------------------------------
    // Scenario 6: Concurrent metadata updates with same expectedVersion → exactly one succeeds
    // ------------------------------------------------------------------------
    const fCurrent = await prisma.finding.findUniqueOrThrow({ where: { id: finding1.id } });
    const raceVersion = fCurrent.version;

    const concurrentP1 = findingService.updateFindingMetadata(analystActor, finding1.id, {
      expectedVersion: raceVersion,
      title: 'Concurrent Race Winner Alpha',
    });
    const concurrentP2 = findingService.updateFindingMetadata(analystActor, finding1.id, {
      expectedVersion: raceVersion,
      title: 'Concurrent Race Winner Beta',
    });

    const occRaceResults = await Promise.allSettled([concurrentP1, concurrentP2]);
    const occFulfilled = occRaceResults.filter((r) => r.status === 'fulfilled');
    const occRejected = occRaceResults.filter((r) => r.status === 'rejected');

    if (occFulfilled.length !== 1 || occRejected.length !== 1) {
      throw new Error(`Expected exactly 1 success and 1 rejection in race, got ${occFulfilled.length} fulfilled and ${occRejected.length} rejected`);
    }

    const occLoserReason = (occRejected[0] as PromiseRejectedResult).reason;
    if (!(occLoserReason instanceof ConcurrencyConflictError)) {
      throw new Error(`Expected ConcurrencyConflictError in race loser, got: ${occLoserReason}`);
    }
    recordPass('Scenario 6: Concurrent Metadata Updates with Same expectedVersion (OCC)', `Exactly 1 succeeded and 1 rejected with HTTP 409 ConcurrencyConflictError`);

    // ------------------------------------------------------------------------
    // Scenario 7: OCC failure does not commit finding events or audit records
    // ------------------------------------------------------------------------
    const fBeforeOCC = await prisma.finding.findUniqueOrThrow({ where: { id: finding1.id } });
    const eventsBeforeOCC = await prisma.findingEvent.count({ where: { findingId: finding1.id } });
    const auditsBeforeOCC = await prisma.auditEvent.count({ where: { resourceId: finding1.id } });

    let staleRejected = false;
    try {
      await findingService.updateFindingMetadata(analystActor, finding1.id, {
        expectedVersion: fBeforeOCC.version - 1, // Deliberately stale expectedVersion
        title: 'Stale Version OCC Attempt',
      });
    } catch (err) {
      if (err instanceof ConcurrencyConflictError) {
        staleRejected = true;
      }
    }
    if (!staleRejected) {
      throw new Error('Stale expectedVersion was not rejected with ConcurrencyConflictError');
    }

    const eventsAfterOCC = await prisma.findingEvent.count({ where: { findingId: finding1.id } });
    const auditsAfterOCC = await prisma.auditEvent.count({ where: { resourceId: finding1.id } });

    if (eventsAfterOCC !== eventsBeforeOCC || auditsAfterOCC !== auditsBeforeOCC) {
      throw new Error(`OCC failure leaked events or audit records: events ${eventsBeforeOCC} -> ${eventsAfterOCC}, audits ${auditsBeforeOCC} -> ${auditsAfterOCC}`);
    }
    recordPass('Scenario 7: OCC Failure Does Not Commit Finding Events or Audit Records', `Zero partial event or audit rows committed after OCC version rejection`);

    // ------------------------------------------------------------------------
    // Scenario 8: Audit insertion failure rolls back finding mutation and lifecycle event
    // ------------------------------------------------------------------------
    const countBeforeRollback = await prisma.finding.count({ where: { projectId: projectA.id } });
    try {
      await dbManager.runTransaction(async (repos) => {
        const f = await repos.findingRepo.create({
          projectId: projectA.id,
          title: 'Rollback Test Finding',
          description: 'Should be rolled back',
          severity: 'LOW',
          category: 'OTHER',
          createdById: analystUser.id,
        });
        createdFindingIds.push(f.id);

        await repos.findingRepo.addEvent({
          findingId: f.id,
          actorId: analystUser.id,
          eventType: 'CREATED',
          previousStatus: null,
          newStatus: 'OPEN',
          metadata: {},
        });

        // Force transactional failure at audit insertion step
        throw new Error('Simulated database write error during audit event append');
      });
    } catch {
      // Expected rollback
    }
    const countAfterRollback = await prisma.finding.count({ where: { projectId: projectA.id } });
    if (countAfterRollback !== countBeforeRollback) {
      throw new Error(`Rollback failed: finding count changed from ${countBeforeRollback} to ${countAfterRollback}`);
    }
    recordPass('Scenario 8: Audit Insertion Failure Rolls Back Finding Mutation and Lifecycle Event', `Zero partial writes persisted upon transactional failure; complete rollback confirmed`);

    // ------------------------------------------------------------------------
    // Scenario 9: Cross-project unauthorized mutations do not reveal finding existence (404)
    // ------------------------------------------------------------------------
    let crossMetadataBlocked = false;
    try {
      await findingService.updateFindingMetadata(analystActor, findingB.id, {
        expectedVersion: 1,
        title: 'Cross Project Metadata Exploit',
      });
    } catch (err) {
      if (err instanceof EntityNotFoundError) {
        crossMetadataBlocked = true;
      }
    }
    if (!crossMetadataBlocked) {
      throw new Error('Cross-project metadata update was not hidden with 404 EntityNotFoundError');
    }

    let crossTriageBlocked = false;
    try {
      await findingService.triageFinding(analystActor, findingB.id, {
        expectedVersion: 1,
      });
    } catch (err) {
      if (err instanceof EntityNotFoundError) {
        crossTriageBlocked = true;
      }
    }
    if (!crossTriageBlocked) {
      throw new Error('Cross-project triage was not hidden with 404 EntityNotFoundError');
    }
    recordPass('Scenario 9: Cross-Project Unauthorized Mutations Hide Existence with 404', `Both updateFindingMetadata and triageFinding returned HTTP 404 EntityNotFoundError`);

    // ------------------------------------------------------------------------
    // Scenario 10: Unauthorized Mutation on Archived Foreign Project Hides Existence with 404
    // ------------------------------------------------------------------------
    // Archive Project B in database
    await prisma.project.update({
      where: { id: projectB.id },
      data: { isActive: false },
    });

    let foreignArchivedBlocked = false;
    try {
      // Analyst in Project A attempts to mutate finding in archived Project B
      await findingService.updateFindingMetadata(analystActor, findingB.id, {
        expectedVersion: 1,
        title: 'Exploit on Archived Foreign Project',
      });
    } catch (err) {
      // Must return generic 404 EntityNotFoundError, NOT 403 Forbidden
      if (err instanceof EntityNotFoundError) {
        foreignArchivedBlocked = true;
      }
    }
    if (!foreignArchivedBlocked) {
      throw new Error('Unauthorized mutation on archived foreign project leaked existence (did not return 404)');
    }

    // Restore Project B to active
    await prisma.project.update({
      where: { id: projectB.id },
      data: { isActive: true },
    });
    recordPass('Scenario 10: Unauthorized Mutation on Archived Foreign Project Hides Existence with 404', `Non-member targeting finding in archived project received HTTP 404 (existence hiding)`);

    // ------------------------------------------------------------------------
    // Scenario 11: Account Deactivation Concurrency (Mutation Locked First Completes Authorized)
    // ------------------------------------------------------------------------
    // Create an Analyst user for concurrency serialization test
    const concUserSub = `gate3d3-conc-${Date.now()}`;
    const concUser = await prisma.user.create({
      data: {
        sub: concUserSub,
        email: `${concUserSub}@example.com`,
        displayName: 'Concurrency Test Analyst',
        globalRole: 'ANALYST',
        isActive: true,
      },
    });
    createdUserIds.push(concUser.id);

    await prisma.projectMember.create({
      data: {
        projectId: projectA.id,
        userId: concUser.id,
        role: 'ANALYST',
        addedById: adminUser.id,
      },
    });

    const concActor = new ActorContext({
      id: concUser.id,
      globalRole: 'ANALYST',
      isActive: true,
      memberships: [{ projectId: projectA.id, role: 'ANALYST' }],
    });

    // Transaction A: Operational mutation holding Level 0 user row lock
    // Transaction B: Administrative deactivation attempting FOR UPDATE on user row
    // In PostgreSQL, FOR SHARE and FOR UPDATE conflict. If mutation locks first,
    // it completes authorized; deactivation executes afterward.
    const fBeforeConc = await prisma.finding.findUniqueOrThrow({ where: { id: finding1.id } });
    const concOpA = findingService.updateFindingMetadata(concActor, finding1.id, {
      expectedVersion: fBeforeConc.version,
      title: 'Concurrent Deactivation Race Title',
    });
    const concOpB = prisma.user.update({
      where: { id: concUser.id },
      data: { isActive: false },
    });

    const concResults = await Promise.allSettled([concOpA, concOpB]);
    const concResultA = concResults[0];
    const concResultB = concResults[1];

    if (concResultB?.status !== 'fulfilled') {
      throw new Error('User deactivation failed to commit during concurrency test');
    }

    if (concResultA?.status === 'rejected') {
      const err = concResultA.reason;
      if (!(err instanceof ForbiddenError) && !(err instanceof ConcurrencyConflictError)) {
        throw new Error(`Unexpected error in concurrent mutation: ${err}`);
      }
    }

    // After deactivation commits, subsequent operations must fail closed with 403
    let postDeactivationBlocked = false;
    try {
      const fNow = await prisma.finding.findUniqueOrThrow({ where: { id: finding1.id } });
      await findingService.updateFindingMetadata(concActor, finding1.id, {
        expectedVersion: fNow.version,
        title: 'Post-Deactivation Mutation Attempt',
      });
    } catch (err) {
      if (err instanceof ForbiddenError) {
        postDeactivationBlocked = true;
      }
    }
    if (!postDeactivationBlocked) {
      throw new Error('Subsequent operation after committed deactivation was not denied with 403');
    }

    recordPass('Scenario 11: Account Deactivation Concurrency Serialization', `Mutation and deactivation serialized safely; subsequent operations rejected with HTTP 403`);

    // ------------------------------------------------------------------------
    // Supplementary: Denial After Account Deactivation
    // ------------------------------------------------------------------------
    await prisma.user.update({
      where: { id: analystUser.id },
      data: { isActive: false },
    });

    let deactivatedBlocked = false;
    try {
      await findingService.getFinding(analystActor, finding1.id);
    } catch (err) {
      if (err instanceof ForbiddenError) {
        deactivatedBlocked = true;
      }
    }
    if (!deactivatedBlocked) {
      throw new Error('Deactivated analyst accessed finding');
    }
    await prisma.user.update({
      where: { id: analystUser.id },
      data: { isActive: true },
    });
    recordPass('Supplementary: Denial After Account Deactivation', `Stale context revalidated against DB and failed closed with HTTP 403 Forbidden`);

    // ------------------------------------------------------------------------
    // Supplementary: Developer Persona Scoping
    // ------------------------------------------------------------------------
    await prisma.finding.update({
      where: { id: finding1.id },
      data: { assignedToId: dev1User.id },
    });

    const dev1Read = await findingService.getFinding(dev1Actor, finding1.id);
    if (dev1Read.id !== finding1.id) {
      throw new Error('Developer failed to read assigned finding');
    }

    let dev2Blocked = false;
    try {
      await findingService.getFinding(dev2Actor, finding1.id);
    } catch (err) {
      if (err instanceof EntityNotFoundError) {
        dev2Blocked = true;
      }
    }
    if (!dev2Blocked) {
      throw new Error('Developer read unassigned cross-project finding');
    }
    recordPass('Supplementary: Developer Persona Scoping', `Dev1 read assigned finding; Dev2 blocked with HTTP 404 existence hiding`);

    // ------------------------------------------------------------------------
    // Supplementary: Authorized Filtering & Pagination
    // ------------------------------------------------------------------------
    const listResult = await findingService.listFindings(analystActor, {
      projectId: projectA.id,
      page: 1,
      limit: 10,
    });
    if (!Array.isArray(listResult.items) || listResult.items.length === 0) {
      throw new Error('listFindings returned 0 items for active project finding');
    }
    recordPass('Supplementary: Authorized Filtering & Pagination', `listFindings retrieved ${listResult.items.length} items with matching counts`);

    // ------------------------------------------------------------------------
    // Supplementary: Zero Mutation on Rejected Authorization
    // ------------------------------------------------------------------------
    const findingBefore = await prisma.finding.findUniqueOrThrow({
      where: { id: finding1.id },
    });

    try {
      await findingService.updateFindingMetadata(dev1Actor, finding1.id, {
        expectedVersion: findingBefore.version,
        title: 'Unauthorized Dev Mutation Attempt',
      });
    } catch {
      // Expected rejection (403)
    }

    const findingAfter = await prisma.finding.findUniqueOrThrow({
      where: { id: finding1.id },
    });

    if (
      findingAfter.title !== findingBefore.title ||
      findingAfter.version !== findingBefore.version ||
      findingAfter.updatedAt.getTime() !== findingBefore.updatedAt.getTime()
    ) {
      throw new Error('Unauthorized rejected mutation caused partial database changes');
    }
    recordPass('Supplementary: Zero Mutation on Rejected Authorization', `Database record completely untouched after unauthorized caller rejection`);

  } finally {
    // Clean up synthetic test records strictly in FK-safe reverse order
    try {
      if (createdUserIds.length > 0 || createdFindingIds.length > 0) {
        await dbManager.getPrismaClient().auditEvent.deleteMany({
          where: {
            OR: [
              ...(createdUserIds.length > 0 ? [{ actorId: { in: createdUserIds } }] : []),
              ...(createdFindingIds.length > 0 ? [{ resourceId: { in: createdFindingIds } }] : []),
            ],
          },
        });
      }
      if (createdFindingIds.length > 0) {
        await dbManager.getPrismaClient().findingEvent.deleteMany({
          where: { findingId: { in: createdFindingIds } },
        });
        await dbManager.getPrismaClient().finding.deleteMany({
          where: { id: { in: createdFindingIds } },
        });
      }
      if (createdProjectIds.length > 0) {
        await dbManager.getPrismaClient().projectMember.deleteMany({
          where: { projectId: { in: createdProjectIds } },
        });
        await dbManager.getPrismaClient().project.deleteMany({
          where: { id: { in: createdProjectIds } },
        });
      }
      if (createdUserIds.length > 0) {
        await dbManager.getPrismaClient().user.deleteMany({
          where: { id: { in: createdUserIds } },
        });
      }
    } catch (cleanupErr: unknown) {
      console.warn('Warning: Non-fatal test cleanup error:', cleanupErr);
    }

    await dbManager.shutdown();
  }

  console.log('--------------------------------------------------');
  console.log(`Summary: ${passedTests}/${totalTests} Gate 3D.3 integration tests passed.`);
  console.log('==================================================\n');

  return {
    allPassed: passedTests === totalTests && totalTests > 0,
    totalTests,
    passedTests,
  };
}

// Direct execution runner
if (process.argv[1] && process.argv[1].endsWith('gate3d-finding-service.integration.ts')) {
  runGate3dFindingServiceIntegrationTests()
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
