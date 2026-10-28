import path from 'node:path';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';
import { DatabaseManager } from '../../src/db/database-manager.js';
import {
  ActorContext,
  FindingPolicy,
  deriveFindingQueryScope,
  deriveProjectQueryScope,
} from '../../src/policy/index.js';
import { validateTestDatabaseUrl } from './gate3b-repositories.integration.js';

// Load environment variables for local integration testing
const __dirname = path.dirname(fileURLToPath(import.meta.url));
dotenv.config({ path: path.resolve(__dirname, '../../../../.env') });
dotenv.config({ path: path.resolve(__dirname, '../../../.env') });

export async function runGate3cAuthorizationIntegrationTests(): Promise<{
  allPassed: boolean;
  totalTests: number;
  passedTests: number;
}> {
  console.log('==================================================');
  console.log('SecureFlow — Gate 3C Authorization & Real-Time Revocation Suite');
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

  // Strictly validate TEST_DATABASE_URL with zero fallback to DATABASE_URL
  const rawTestUrl = validateTestDatabaseUrl(process.env['TEST_DATABASE_URL']);

  const dbManager = new DatabaseManager({
    connectionString: rawTestUrl,
    maxConnections: 5,
    connectionTimeoutMillis: 5000,
    statementTimeoutMillis: 10000,
  });

  try {
    const identity = await dbManager.verifyConnectivity();
    if (identity.database !== 'secureflow_test' || identity.majorVersion !== 17) {
      throw new Error(`Connected database is not secureflow_test on PostgreSQL 17: ${identity.database}`);
    }
    recordPass('Engine Identity Verification', `Connected to ${identity.database} on port ${identity.port} (PG 17)`);

    const prisma = dbManager.getPrismaClient();
    const repos = dbManager.getRepositories();

    // Setup synthetic test users
    const testAdminSub = `gate3c-admin-${Date.now()}`;
    const testAnalystSub = `gate3c-analyst-${Date.now()}`;
    const testDevSub = `gate3c-dev-${Date.now()}`;

    const [adminUser, analystUser, devUser] = await Promise.all([
      prisma.user.create({
        data: {
          sub: testAdminSub,
          email: `${testAdminSub}@example.com`,
          displayName: 'Gate 3C Admin',
          globalRole: 'ADMIN',
          isActive: true,
        },
      }),
      prisma.user.create({
        data: {
          sub: testAnalystSub,
          email: `${testAnalystSub}@example.com`,
          displayName: 'Gate 3C Analyst',
          globalRole: 'ANALYST',
          isActive: true,
        },
      }),
      prisma.user.create({
        data: {
          sub: testDevSub,
          email: `${testDevSub}@example.com`,
          displayName: 'Gate 3C Developer',
          globalRole: 'DEVELOPER',
          isActive: true,
        },
      }),
    ]);

    // Setup synthetic projects: Project 1 (Dev is member) and Project 2 (Dev is NOT member)
    const project1 = await repos.projectRepo.create({
      name: 'Gate 3C Project One',
      slug: `gate3c-p1-${Date.now()}`,
      createdById: adminUser.id,
    });

    const project2 = await repos.projectRepo.create({
      name: 'Gate 3C Project Two',
      slug: `gate3c-p2-${Date.now()}`,
      createdById: adminUser.id,
    });

    // Add memberships
    await repos.projectRepo.addMember(project1.id, {
      userId: analystUser.id,
      role: 'ANALYST',
      addedById: adminUser.id,
    });
    await repos.projectRepo.addMember(project1.id, {
      userId: devUser.id,
      role: 'DEVELOPER',
      addedById: adminUser.id,
    });

    // Create findings
    const finding1 = await repos.findingRepo.create({
      projectId: project1.id,
      title: 'Finding in Project 1 Assigned to Dev',
      description: 'SQL Injection in search API',
      severity: 'CRITICAL',
      category: 'INJECTION',
      createdById: analystUser.id,
      assignedToId: devUser.id,
    });

    const finding2 = await repos.findingRepo.create({
      projectId: project2.id,
      title: 'Finding in Project 2 (Cross Project)',
      description: 'IDOR in document viewer',
      severity: 'HIGH',
      category: 'IDOR',
      createdById: analystUser.id,
      assignedToId: null,
    });

    // Create soft-deleted finding in Project 1
    const softDeletedFinding = await repos.findingRepo.create({
      projectId: project1.id,
      title: 'Soft-deleted finding in Project 1',
      description: 'Should be hidden from developer and analyst',
      severity: 'LOW',
      category: 'OTHER',
      createdById: analystUser.id,
    });
    await repos.findingRepo.softDelete(softDeletedFinding.id, 1);

    // -------------------------------------------------------------------------
    // 1. Dynamic Membership Resolution, Stale Cache Demonstration & Revocation (OLI-10)
    // -------------------------------------------------------------------------
    // Step A: Build ActorContext from active DB state (Dev is member of project 1)
    const isMemberBefore = await repos.projectRepo.isMember(project1.id, devUser.id);
    if (!isMemberBefore) {
      throw new Error('Expected devUser to be member of project1');
    }

    const devActorBefore = new ActorContext({
      id: devUser.id,
      globalRole: 'DEVELOPER',
      isActive: true,
      memberships: [{ projectId: project1.id, role: 'DEVELOPER' }],
    });

    const decisionBefore = FindingPolicy.can(devActorBefore, 'view', {
      finding: {
        id: finding1.id,
        projectId: project1.id,
        assignedToId: finding1.assignedToId,
        isDeleted: false,
      },
    });
    if (!decisionBefore.allowed) {
      throw new Error('Expected authorized developer to have access before revocation');
    }
    recordPass('Dynamic Membership Access', 'Active developer successfully authorized to access assigned finding');

    // Step B: Revoke membership directly in PostgreSQL
    const removed = await repos.projectRepo.removeMember(project1.id, devUser.id);
    if (!removed) {
      throw new Error('Failed to remove member from database');
    }

    // Step C: Verify database state immediately reflects revocation
    const isMemberAfter = await repos.projectRepo.isMember(project1.id, devUser.id);
    if (isMemberAfter) {
      throw new Error('Database still reports user as member after removeMember');
    }
    recordPass(
      'Authoritative Database Boundary Revocation',
      'PostgreSQL project_members table immediately reflects removal (isMember returns false)',
    );

    // Step D: The Stale Context Demonstration
    // Evaluating the UNREFRESHED in-memory devActorBefore proves that ActorContext is an
    // immutable point-in-time value snapshot. It does NOT automatically push invalidation.
    const staleDecision = FindingPolicy.can(devActorBefore, 'view', {
      finding: {
        id: finding1.id,
        projectId: project1.id,
        assignedToId: finding1.assignedToId,
        isDeleted: false,
      },
    });
    if (!staleDecision.allowed) {
      throw new Error('Stale snapshot was unexpectedly modified without re-instantiation');
    }
    recordPass(
      'Stale Context Trap Demonstration',
      'Proves unrefreshed in-memory ActorContext retains static snapshot; caching across requests without DB revalidation is prohibited',
    );

    // Step E: Authoritative Dynamic Freshness Contract
    // In production (Gate 3D / Gate 4), ActorContext is reconstructed from PostgreSQL at
    // the request boundary, or verified inside the service transaction.
    const currentMembers = await repos.projectRepo.getMembers(project1.id);
    const activeMemberships = currentMembers
      .filter((m) => m.userId === devUser.id)
      .map((m) => ({ projectId: m.projectId, role: m.role }));

    const devActorFresh = new ActorContext({
      id: devUser.id,
      globalRole: 'DEVELOPER',
      isActive: true,
      memberships: activeMemberships, // Authoritative empty array from DB
    });

    const decisionAfterFresh = FindingPolicy.can(devActorFresh, 'view', {
      finding: {
        id: finding1.id,
        projectId: project1.id,
        assignedToId: finding1.assignedToId,
        isDeleted: false,
      },
    });

    if (decisionAfterFresh.allowed || decisionAfterFresh.httpStatus !== 404) {
      throw new Error(
        `Expected 404 existence hiding after fresh context derivation, received allowed=${decisionAfterFresh.allowed}, status=${decisionAfterFresh.httpStatus}`,
      );
    }
    recordPass(
      'Real-Time Revocation Enforcement (OLI-10 / NEG-14)',
      'Re-deriving ActorContext dynamically from PostgreSQL immediately returns 404 existence hiding',
    );

    // Step F: Query Scope Freshness after Revocation
    const freshScope = deriveFindingQueryScope(devActorFresh);
    const freshQueryResult = await repos.findingRepo.findMany({ scope: freshScope });
    if (freshQueryResult.total !== 0 || freshQueryResult.items.length !== 0) {
      throw new Error(`Expected 0 findings after revocation, received ${freshQueryResult.total}`);
    }
    recordPass(
      'Database Query-Scope Revocation Enforcement',
      'Derived query scope from fresh context returns 0 records from PostgreSQL (fail-closed)',
    );

    // -------------------------------------------------------------------------
    // 2. Scoped Database Queries with Derived Scopes
    // -------------------------------------------------------------------------
    // Re-add dev to project 1 for query scope testing
    await repos.projectRepo.addMember(project1.id, {
      userId: devUser.id,
      role: 'DEVELOPER',
      addedById: adminUser.id,
    });

    const devActorWithProject1 = new ActorContext({
      id: devUser.id,
      globalRole: 'DEVELOPER',
      isActive: true,
      memberships: [{ projectId: project1.id, role: 'DEVELOPER' }],
    });

    // Developer Query: derive scope and query PostgreSQL
    const devFindingScope = deriveFindingQueryScope(devActorWithProject1);
    const devQueryResult = await repos.findingRepo.findMany({ scope: devFindingScope });

    // Must see finding 1, must NOT see finding 2 (cross-project), must NOT see soft-deleted finding
    const devFoundIds = devQueryResult.items.map((f) => f.id);
    if (!devFoundIds.includes(finding1.id)) {
      throw new Error('Developer query failed to return assigned finding in authorized project');
    }
    if (devFoundIds.includes(finding2.id)) {
      throw new Error('Developer query returned finding from unauthorized Project 2 (isolation violation!)');
    }
    if (devFoundIds.includes(softDeletedFinding.id)) {
      throw new Error('Developer query returned soft-deleted finding (OLI-12 violation!)');
    }
    if (devQueryResult.total !== 1) {
      throw new Error(`Expected exactly 1 finding for developer, found total=${devQueryResult.total}`);
    }
    recordPass(
      'Developer Query Scope Database Isolation',
      'PostgreSQL query strictly isolated developer to assigned findings in permitted project (excluded cross-project and soft-deleted)',
    );

    // Admin Query: derive scope with includeDeleted
    const adminFindingScope = deriveFindingQueryScope(
      new ActorContext({ id: adminUser.id, globalRole: 'ADMIN', isActive: true }),
      { includeDeletedFindings: true },
    );
    const adminQueryResult = await repos.findingRepo.findMany({ scope: adminFindingScope });
    const adminFoundIds = adminQueryResult.items.map((f) => f.id);

    if (!adminFoundIds.includes(finding1.id) || !adminFoundIds.includes(finding2.id)) {
      throw new Error('Admin query failed to see all active findings');
    }
    if (!adminFoundIds.includes(softDeletedFinding.id)) {
      throw new Error('Admin query with includeDeleted: true failed to return soft-deleted finding');
    }
    recordPass(
      'Admin Query Scope Organization-Wide Visibility',
      'PostgreSQL query with Admin derived scope successfully returned cross-project and soft-deleted findings',
    );

    // Project Query Scope: Analyst sees only permitted project 1
    const analystActorWithP1 = new ActorContext({
      id: analystUser.id,
      globalRole: 'ANALYST',
      isActive: true,
      memberships: [{ projectId: project1.id, role: 'ANALYST' }],
    });
    const analystProjectScope = deriveProjectQueryScope(analystActorWithP1);
    const analystProjects = await repos.projectRepo.findMany({ scope: analystProjectScope });
    const analystProjectIds = analystProjects.items.map((p) => p.id);

    if (!analystProjectIds.includes(project1.id) || analystProjectIds.includes(project2.id)) {
      throw new Error('Analyst project query scope failed to isolate to authorized projects');
    }
    recordPass('Project Query Scope Isolation', 'Analyst project listing correctly confined to authorized project');

    // -------------------------------------------------------------------------
    // Safe Cleanup of Synthetic Records Only
    // -------------------------------------------------------------------------
    await prisma.findingEvent.deleteMany({
      where: { findingId: { in: [finding1.id, finding2.id, softDeletedFinding.id] } },
    });
    await prisma.finding.deleteMany({
      where: { id: { in: [finding1.id, finding2.id, softDeletedFinding.id] } },
    });
    await prisma.projectMember.deleteMany({
      where: { projectId: { in: [project1.id, project2.id] } },
    });
    await prisma.project.deleteMany({
      where: { id: { in: [project1.id, project2.id] } },
    });
    await prisma.user.deleteMany({
      where: { id: { in: [adminUser.id, analystUser.id, devUser.id] } },
    });

    console.log('--------------------------------------------------');
    console.log(`Summary: ${passedTests}/${totalTests} Gate 3C integration tests passed.`);
    console.log('==================================================');
    return { allPassed: true, totalTests, passedTests };
  } catch (error) {
    recordFail('Gate 3C Authorization Integration Suite', error);
    return { allPassed: false, totalTests, passedTests };
  } finally {
    await dbManager.shutdown();
  }
}

// Standalone execution via tsx
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  runGate3cAuthorizationIntegrationTests()
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
