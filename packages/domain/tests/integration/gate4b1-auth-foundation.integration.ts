import { randomBytes } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';
import pg from 'pg';
import { DatabaseManager } from '../../src/db/database-manager.js';
import {
  AuthService,
  ProjectService,
  hashOpaqueToken,
  generateOpaqueToken,
  ActorContext,
} from '../../src/index.js';
import { validateTestDatabaseUrl } from '../../src/testing/index.js';
import {
  ConcurrencyConflictError,
  ForbiddenError,
  UnauthorizedError,
} from '@secureflow/shared';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
dotenv.config({ path: path.resolve(__dirname, '../../../../.env') });
dotenv.config({ path: path.resolve(__dirname, '../../../.env') });

interface TableCounts {
  users: number;
  user_sessions: number;
  oidc_transactions: number;
  projects: number;
  project_members: number;
  findings: number;
  remediation_tasks: number;
  finding_events: number;
  audit_events: number;
}

async function getTableCounts(dbManager: DatabaseManager): Promise<TableCounts> {
  const prisma = dbManager.getPrismaClient();
  const [
    users,
    user_sessions,
    oidc_transactions,
    projects,
    project_members,
    findings,
    remediation_tasks,
    finding_events,
    audit_events,
  ] = await Promise.all([
    prisma.user.count(),
    prisma.userSession.count(),
    prisma.oidcTransaction.count(),
    prisma.project.count(),
    prisma.projectMember.count(),
    prisma.finding.count(),
    prisma.remediationTask.count(),
    prisma.findingEvent.count(),
    prisma.auditEvent.count(),
  ]);

  return {
    users,
    user_sessions,
    oidc_transactions,
    projects,
    project_members,
    findings,
    remediation_tasks,
    finding_events,
    audit_events,
  };
}

export async function runGate4b1AuthFoundationIntegrationTests(): Promise<{
  allPassed: boolean;
  totalTests: number;
  passedTests: number;
}> {
  console.log('==================================================');
  console.log('SecureFlow — Sub-Gate 4B.1 Authentication Database & Domain Foundation Suite');
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

  const rawTestUrl = validateTestDatabaseUrl(process.env['TEST_DATABASE_URL']);

  const dbManager = new DatabaseManager({
    connectionString: rawTestUrl,
    maxConnections: 10,
    connectionTimeoutMillis: 5000,
    statementTimeoutMillis: 10000,
  });

  const runTag = `gate4b1-${Date.now()}`;
  const createdUserIds = new Set<string>();
  const createdSessionIds = new Set<string>();
  const createdOidcTxnIds = new Set<string>();
  const createdProjectIds = new Set<string>();
  const createdAuditEventIds = new Set<string>();
  let sentinelAuditId: string | undefined;

  type PublicUserSnapshotRow = {
    id: string;
    sub: string;
    email: string;
    globalRole: string;
    isActive: boolean;
    createdAtMs: number;
    updatedAtMs: number;
  };

  async function capturePublicUsersSnapshot(): Promise<PublicUserSnapshotRow[]> {
    const rows = await dbManager.getPrismaClient().user.findMany({
      orderBy: { id: 'asc' },
      select: {
        id: true,
        sub: true,
        email: true,
        globalRole: true,
        isActive: true,
        createdAt: true,
        updatedAt: true,
      },
    });
    return rows.map((row) => ({
      id: row.id,
      sub: row.sub,
      email: row.email,
      globalRole: row.globalRole,
      isActive: row.isActive,
      createdAtMs: row.createdAt.getTime(),
      updatedAtMs: row.updatedAt.getTime(),
    }));
  }

  function assertPublicUsersSnapshotEqual(
    before: PublicUserSnapshotRow[],
    after: PublicUserSnapshotRow[],
    contextLabel: string,
  ): void {
    if (before.length !== after.length) {
      throw new Error(
        `${contextLabel}: public.users row count changed (${before.length} -> ${after.length})`,
      );
    }
    for (let i = 0; i < before.length; i++) {
      const a = before[i]!;
      const b = after[i]!;
      if (
        a.id !== b.id ||
        a.sub !== b.sub ||
        a.email !== b.email ||
        a.globalRole !== b.globalRole ||
        a.isActive !== b.isActive ||
        a.createdAtMs !== b.createdAtMs ||
        a.updatedAtMs !== b.updatedAtMs
      ) {
        throw new Error(
          `${contextLabel}: public.users row ${a.id} mutated (${JSON.stringify(a)} -> ${JSON.stringify(b)})`,
        );
      }
    }
  }

  // Track every audit_event ID written via dbManager repositories/transactions so cleanup
  // deletes strictly test-owned audit IDs without relying on broad timestamp ranges.
  const wrapAuditRepo = (repos: ReturnType<DatabaseManager['getRepositories']>) => {
    const origAppend = repos.auditRepo.append.bind(repos.auditRepo);
    repos.auditRepo.append = async (data) => {
      const appended = await origAppend(data);
      createdAuditEventIds.add(appended.id);
      return appended;
    };
    return repos;
  };

  const baseGetRepositories = dbManager.getRepositories.bind(dbManager);
  dbManager.getRepositories = () => wrapAuditRepo(baseGetRepositories());

  const baseRunTransaction = dbManager.runTransaction.bind(dbManager);
  dbManager.runTransaction = (async <T>(
    fn: Parameters<DatabaseManager['runTransaction']>[0],
    options?: Parameters<DatabaseManager['runTransaction']>[1],
  ): Promise<T> => {
    return await baseRunTransaction(async (txRepos, tx) => {
      return await fn(wrapAuditRepo(txRepos), tx);
    }, options);
  }) as DatabaseManager['runTransaction'];

  let initialCounts: TableCounts | undefined;
  let initialPublicUsersSnapshot: PublicUserSnapshotRow[] | undefined;

  try {
    // ------------------------------------------------------------------------
    // TEST 1: Engine Identity, Schema Migration Verification & Baseline Snapshot
    // ------------------------------------------------------------------------
    const identity = await dbManager.verifyConnectivity();
    if (identity.database !== 'secureflow_test' || identity.majorVersion !== 17) {
      throw new Error(
        `Connected database is not secureflow_test on PostgreSQL 17: ${identity.database}`,
      );
    }

    // Fail closed if required Prisma migrations or indexes have not been deployed out-of-band.
    const migrationCheckClient = new pg.Client({ connectionString: rawTestUrl });
    await migrationCheckClient.connect();
    try {
      const schemaRegRes = await migrationCheckClient.query<{
        user_sessions: string | null;
        oidc_transactions: string | null;
      }>(
        `SELECT
           to_regclass('public.user_sessions')::text AS user_sessions,
           to_regclass('public.oidc_transactions')::text AS oidc_transactions;`,
      );
      const regs = schemaRegRes.rows[0];
      if (!regs?.user_sessions || !regs?.oidc_transactions) {
        throw new Error(
          'FAIL-CLOSED: Required auth tables (user_sessions, oidc_transactions) are missing in secureflow_test. Run `prisma migrate deploy` against TEST_DATABASE_URL first.',
        );
      }

      const lowerEmailIndexRes = await migrationCheckClient.query<{ indexname: string }>(
        `SELECT indexname
         FROM pg_indexes
         WHERE schemaname = 'public'
           AND tablename = 'users'
           AND indexname = 'users_email_lower_key';`,
      );
      if (lowerEmailIndexRes.rowCount !== 1) {
        throw new Error(
          'FAIL-CLOSED: Missing unique index "users_email_lower_key" on public.users. Run `prisma migrate deploy` against TEST_DATABASE_URL first.',
        );
      }

      const appliedMigrationsRes = await migrationCheckClient.query<{
        migration_name: string;
        finished_at: Date | null;
        rolled_back_at: Date | null;
      }>(
        `SELECT migration_name, finished_at, rolled_back_at
         FROM public._prisma_migrations
         WHERE migration_name IN (
           '20261111180000_add_auth_sessions_and_oidc_transactions',
           '20261111202000_add_users_email_lower_unique_index'
         );`,
      );
      const finishedNames = new Set(
        appliedMigrationsRes.rows
          .filter((r) => r.finished_at !== null && r.rolled_back_at === null)
          .map((r) => r.migration_name),
      );
      if (
        !finishedNames.has('20261111180000_add_auth_sessions_and_oidc_transactions') ||
        !finishedNames.has('20261111202000_add_users_email_lower_unique_index')
      ) {
        throw new Error(
          `FAIL-CLOSED: _prisma_migrations ledger is incomplete on secureflow_test. Found finished migrations: ${[...finishedNames].join(', ')}`,
        );
      }
    } finally {
      await migrationCheckClient.end();
    }

    initialCounts = await getTableCounts(dbManager);
    initialPublicUsersSnapshot = await capturePublicUsersSnapshot();
    recordPass(
      '1. Engine Identity, Fail-Closed Migration Check & Baseline Snapshot',
      `Connected to ${identity.database} on port ${identity.port} (PG ${identity.majorVersion}); Prisma migrations and indexes verified.`,
    );

    const prisma = dbManager.getPrismaClient();
    const authService = new AuthService(dbManager);
    const projectService = new ProjectService(dbManager);

    // ------------------------------------------------------------------------
    // TEST 2: Schema & Foreign-Key ON DELETE RESTRICT Enforcement on user_sessions
    // ------------------------------------------------------------------------
    const fkTestUser = await prisma.user.create({
      data: {
        sub: `${runTag}-fk-user`,
        email: `${runTag}-fk@example.com`,
        displayName: 'FK Test User',
        globalRole: 'DEVELOPER',
        isActive: true,
      },
    });
    createdUserIds.add(fkTestUser.id);

    const fkTestSession = await prisma.userSession.create({
      data: {
        userId: fkTestUser.id,
        sessionTokenHash: hashOpaqueToken(generateOpaqueToken(32)),
        csrfToken: generateOpaqueToken(32),
        lastActiveAt: new Date(),
        idleExpiresAt: new Date(Date.now() + 1800_000),
        expiresAt: new Date(Date.now() + 28800_000),
      },
    });
    createdSessionIds.add(fkTestSession.id);

    let fkRestricted = false;
    try {
      await prisma.user.delete({ where: { id: fkTestUser.id } });
    } catch (err: unknown) {
      const code = (err as { code?: string }).code;
      if (code === 'P2003' || String(err).includes('user_sessions_user_id_fkey')) {
        fkRestricted = true;
      } else {
        throw err;
      }
    }
    if (!fkRestricted) {
      throw new Error('Expected ON DELETE RESTRICT on user_sessions.user_id to block parent User deletion');
    }
    recordPass(
      '2. Foreign-Key ON DELETE RESTRICT on user_sessions.user_id',
      'Parent User deletion blocked while UserSession row exists.',
    );

    // ------------------------------------------------------------------------
    // TEST 3: Single-Use OIDC Transaction & Concurrent 5-Way Callback Replay Race
    // ------------------------------------------------------------------------
    const createdTxn = await authService.createOidcTransaction({
      returnTo: '/findings?severity=CRITICAL',
      ttlSeconds: 300,
    });
    createdOidcTxnIds.add(createdTxn.id);

    const rawDbTxn = await prisma.oidcTransaction.findUnique({
      where: { id: createdTxn.id },
    });
    if (
      !rawDbTxn ||
      rawDbTxn.txnTokenHash !== hashOpaqueToken(createdTxn.rawTxnToken) ||
      rawDbTxn.stateHash !== hashOpaqueToken(createdTxn.state) ||
      rawDbTxn.txnTokenHash === createdTxn.rawTxnToken
    ) {
      throw new Error('OIDC transaction failed SHA-256 hashing invariant in PostgreSQL');
    }

    // Fire 5 concurrent consumeOidcTransaction calls with the exact same rawTxnToken & state
    const concurrentConsumeOutcomes = await Promise.allSettled(
      Array.from({ length: 5 }, (_, idx) =>
        authService.consumeOidcTransaction({
          rawTxnToken: createdTxn.rawTxnToken,
          state: createdTxn.state,
          ipAddress: '127.0.0.1',
          userAgent: `ConcurrentReplayWorker/${idx + 1}`,
        }),
      ),
    );

    const fulfilledConsumes = concurrentConsumeOutcomes.filter((o) => o.status === 'fulfilled');
    const rejectedConsumes = concurrentConsumeOutcomes.filter((o) => o.status === 'rejected');

    if (fulfilledConsumes.length !== 1 || rejectedConsumes.length !== 4) {
      throw new Error(
        `Expected 1 fulfilled and 4 rejected OIDC consumes, got ${fulfilledConsumes.length} fulfilled / ${rejectedConsumes.length} rejected`,
      );
    }
    for (const rej of rejectedConsumes) {
      if (!(rej.reason instanceof UnauthorizedError)) {
        throw new Error(`Expected UnauthorizedError on replay, got: ${String(rej.reason)}`);
      }
    }
    recordPass(
      '3. Atomic Single-Use OIDC Transaction Consumption (5-Way Concurrent Replay Race)',
      'Exactly 1 callback succeeded and 4 concurrent replays failed with HTTP 401.',
    );

    // ------------------------------------------------------------------------
    // TEST 4: OIDC State Mismatch & Expired Transaction Rejection
    // ------------------------------------------------------------------------
    const mismatchTxn = await authService.createOidcTransaction({ returnTo: '/projects' });
    createdOidcTxnIds.add(mismatchTxn.id);

    let stateMismatchRejected = false;
    try {
      await authService.consumeOidcTransaction({
        rawTxnToken: mismatchTxn.rawTxnToken,
        state: generateOpaqueToken(32),
        ipAddress: '127.0.0.1',
      });
    } catch (err: unknown) {
      if (err instanceof UnauthorizedError) {
        stateMismatchRejected = true;
      } else {
        throw err;
      }
    }
    if (!stateMismatchRejected) {
      throw new Error('Expected OIDC state mismatch to throw UnauthorizedError');
    }

    // Verify mismatchTxn was atomically burned (consumed_at IS NOT NULL)
    const burnedTxn = await prisma.oidcTransaction.findUnique({ where: { id: mismatchTxn.id } });
    if (!burnedTxn?.consumedAt) {
      throw new Error('Expected state-mismatched OIDC transaction to be marked consumed');
    }

    // Expired transaction test
    const pastNow = new Date(Date.now() - 600_000);
    const expiredTxn = await authService.createOidcTransaction(
      { returnTo: '/', ttlSeconds: 60 },
      pastNow,
    );
    createdOidcTxnIds.add(expiredTxn.id);

    let expiredRejected = false;
    try {
      await authService.consumeOidcTransaction({
        rawTxnToken: expiredTxn.rawTxnToken,
        state: expiredTxn.state,
      });
    } catch (err: unknown) {
      if (err instanceof UnauthorizedError) {
        expiredRejected = true;
      } else {
        throw err;
      }
    }
    if (!expiredRejected) {
      throw new Error('Expected expired OIDC transaction to throw UnauthorizedError');
    }
    recordPass(
      '4. OIDC State Mismatch Burning & Expired Transaction Rejection',
      'State mismatch burned transaction and expired transaction was rejected with HTTP 401.',
    );

    // ------------------------------------------------------------------------
    // TEST 5: Concurrent-Safe Initial Admin Bootstrap Race in Isolated Ephemeral Schema
    // ------------------------------------------------------------------------
    const bootstrapSub = `${runTag}-bootstrap-admin-sub`;
    const bootstrapEmail = `${runTag}-bootstrap-admin@example.com`;
    const expectedIssuer = 'http://localhost:8080/realms/secureflow';

    const usersBeforeBootstrapTest = await capturePublicUsersSnapshot();
    const ephemeralSchema = `sf_boot_${Date.now()}_${randomBytes(4).toString('hex')}`;
    if (!/^sf_boot_[0-9]+_[0-9a-f]{8}$/.test(ephemeralSchema) || ephemeralSchema === 'public') {
      throw new Error(`Invalid ephemeral schema identifier: ${ephemeralSchema}`);
    }

    let ephemeralDbManager: DatabaseManager | undefined;
    try {
      // Create ephemeral schema and run committed migrations inside it (zero fallback to public).
      const schemaClient = new pg.Client({ connectionString: rawTestUrl });
      await schemaClient.connect();
      try {
        await schemaClient.query(`CREATE SCHEMA "${ephemeralSchema}";`);
        await schemaClient.query(`SET search_path TO "${ephemeralSchema}";`);

        const migrationsDir = path.resolve(__dirname, '../../prisma/migrations');
        const migrationFolders = fs
          .readdirSync(migrationsDir, { withFileTypes: true })
          .filter((entry) => entry.isDirectory())
          .map((entry) => entry.name)
          .sort();

        for (const folder of migrationFolders) {
          const sqlPath = path.join(migrationsDir, folder, 'migration.sql');
          const sql = fs.readFileSync(sqlPath, 'utf8');
          if (/\b"?public"?\./i.test(sql)) {
            throw new Error(
              `Refusing ephemeral DDL: migration ${folder} references explicit "public" schema`,
            );
          }
          await schemaClient.query(`SET search_path TO "${ephemeralSchema}";`);
          await schemaClient.query(sql);
        }
      } finally {
        await schemaClient.end();
      }

      ephemeralDbManager = new DatabaseManager({
        connectionString: rawTestUrl,
        schema: ephemeralSchema,
        maxConnections: 10,
        connectionTimeoutMillis: 5000,
        statementTimeoutMillis: 10000,
      });

      // Verify both Pool connections and Prisma transactions resolve strictly inside ephemeralSchema (never public).
      const searchPathCheck = await ephemeralDbManager.runTransaction(async (_txRepos, tx) => {
        const rows = await tx.$queryRaw<Array<{ cur: string; schemas: string[] }>>`
          SELECT current_schema()::text AS cur, current_schemas(false)::text[] AS schemas;
        `;
        return rows[0];
      });
      if (
        !searchPathCheck ||
        searchPathCheck.cur !== ephemeralSchema ||
        searchPathCheck.schemas.includes('public')
      ) {
        throw new Error(
          `Ephemeral schema search_path isolation failed: cur=${searchPathCheck?.cur}, schemas=${JSON.stringify(searchPathCheck?.schemas)}`,
        );
      }

      const ephemeralAuthService = new AuthService(ephemeralDbManager);
      const ephemeralPrisma = ephemeralDbManager.getPrismaClient();

      // First verify wrong subject/issuer fails closed with 403 inside the isolated schema
      let wrongSubRejected = false;
      try {
        await ephemeralAuthService.bootstrapInitialAdmin({
          issuer: expectedIssuer,
          expectedIssuer,
          sub: 'wrong-sub',
          expectedSub: bootstrapSub,
          email: bootstrapEmail,
        });
      } catch (err: unknown) {
        if (err instanceof ForbiddenError) {
          wrongSubRejected = true;
        } else {
          throw err;
        }
      }
      if (!wrongSubRejected) {
        throw new Error('Expected bootstrap with mismatched sub to fail with ForbiddenError');
      }

      // Confirm 0 admins exist in ephemeralSchema before the race without mutating public.users
      const initialEphemeralAdmins = await ephemeralPrisma.user.count({
        where: { globalRole: 'ADMIN', isActive: true },
      });
      if (initialEphemeralAdmins !== 0) {
        throw new Error(`Expected 0 active admins in empty ephemeral schema, got ${initialEphemeralAdmins}`);
      }

      // Fire 5 concurrent bootstrapInitialAdmin calls with valid subject & issuer
      const bootstrapRaceOutcomes = await Promise.allSettled(
        Array.from({ length: 5 }, (_, idx) =>
          ephemeralAuthService.bootstrapInitialAdmin({
            issuer: expectedIssuer,
            expectedIssuer,
            sub: bootstrapSub,
            expectedSub: bootstrapSub,
            email: bootstrapEmail,
            displayName: 'Bootstrapped Initial Admin',
            justification: `Concurrent bootstrap worker ${idx + 1}`,
            ipAddress: '127.0.0.1',
          }),
        ),
      );

      const bootstrapSuccesses = bootstrapRaceOutcomes.filter(
        (
          o,
        ): o is PromiseFulfilledResult<
          Awaited<ReturnType<typeof ephemeralAuthService.bootstrapInitialAdmin>>
        > => o.status === 'fulfilled',
      );
      const bootstrapRejections = bootstrapRaceOutcomes.filter(
        (o): o is PromiseRejectedResult => o.status === 'rejected',
      );

      if (bootstrapSuccesses.length !== 1 || bootstrapRejections.length !== 4) {
        const rejectionReasons = bootstrapRejections.map((r) => String(r.reason)).join('; ');
        throw new Error(
          `Expected 1 fulfilled and 4 rejected bootstrap calls, got ${bootstrapSuccesses.length} fulfilled / ${bootstrapRejections.length} rejected (${rejectionReasons})`,
        );
      }

      const bootstrappedAdmin = bootstrapSuccesses[0]!.value;
      for (const rej of bootstrapRejections) {
        if (!(rej.reason instanceof ConcurrencyConflictError)) {
          throw new Error(
            `Expected ConcurrencyConflictError (409) for losing bootstrap callers, got: ${String(rej.reason)}`,
          );
        }
      }

      const activeAdminCountAfterBootstrap = await ephemeralPrisma.user.count({
        where: { globalRole: 'ADMIN', isActive: true },
      });
      if (activeAdminCountAfterBootstrap !== 1 || bootstrappedAdmin.globalRole !== 'ADMIN') {
        throw new Error(
          `Expected exactly 1 active ADMIN after bootstrap race, got ${activeAdminCountAfterBootstrap}`,
        );
      }
    } finally {
      await ephemeralDbManager?.shutdown();
      if (/^sf_boot_[0-9]+_[0-9a-f]{8}$/.test(ephemeralSchema) && ephemeralSchema !== 'public') {
        const dropClient = new pg.Client({ connectionString: rawTestUrl });
        await dropClient.connect();
        try {
          await dropClient.query(`DROP SCHEMA IF EXISTS "${ephemeralSchema}" CASCADE;`);
        } finally {
          await dropClient.end();
        }
      }
    }

    // Verify ephemeral schema is completely removed and public.users (including updated_at) is untouched
    const verifyCleanClient = new pg.Client({ connectionString: rawTestUrl });
    await verifyCleanClient.connect();
    try {
      const schemaExists = await verifyCleanClient.query<{ cnt: number }>(
        `SELECT COUNT(*)::int AS cnt FROM information_schema.schemata WHERE schema_name = $1;`,
        [ephemeralSchema],
      );
      if ((schemaExists.rows[0]?.cnt ?? 0) !== 0) {
        throw new Error(`Ephemeral schema ${ephemeralSchema} was not removed cleanly`);
      }
    } finally {
      await verifyCleanClient.end();
    }

    const usersAfterBootstrapTest = await capturePublicUsersSnapshot();
    assertPublicUsersSnapshotEqual(
      usersBeforeBootstrapTest,
      usersAfterBootstrapTest,
      'Test 5 ephemeral bootstrap race',
    );
    recordPass(
      '5. Concurrent-Safe Initial Admin Bootstrap Race in Isolated Ephemeral Schema',
      `1 winner + 4 HTTP 409 rejections in ephemeral schema ${ephemeralSchema}; schema dropped and public.users untouched.`,
    );

    // ------------------------------------------------------------------------
    // TEST 6: Strict Least-Privilege JIT Provisioning (Ignoring IdP Role Claims)
    // ------------------------------------------------------------------------
    const jitSub = `${runTag}-jit-dev-sub`;
    const jitEmail = `${runTag}-jit-dev@example.com`;

    const establishedJit = await authService.establishAuthenticatedSession({
      sub: jitSub,
      email: jitEmail,
      emailVerified: true,
      displayName: 'JIT Provisioned Developer',
      oidcSid: `${runTag}-oidc-sid-1`,
      realmRoles: ['ADMIN', 'ANALYST', 'GLOBAL_ADMIN'],
      ipAddress: '192.168.1.50',
      userAgent: 'IntegrationTest/1.0',
    });
    createdUserIds.add(establishedJit.user.id);
    createdSessionIds.add(establishedJit.session.id);

    const dbJitUser = await prisma.user.findUnique({
      where: { id: establishedJit.user.id },
      include: { projectMemberships: true },
    });
    const dbJitSession = await prisma.userSession.findUnique({
      where: { id: establishedJit.session.id },
    });

    if (
      !dbJitUser ||
      dbJitUser.globalRole !== 'DEVELOPER' ||
      dbJitUser.projectMemberships.length !== 0 ||
      !establishedJit.jitProvisioned ||
      !dbJitSession ||
      dbJitSession.sessionTokenHash !== hashOpaqueToken(establishedJit.rawSessionToken) ||
      dbJitSession.sessionTokenHash === establishedJit.rawSessionToken
    ) {
      throw new Error('Least-privilege JIT provisioning or session token hashing invariant failed');
    }
    recordPass(
      '6. Strict Least-Privilege JIT Provisioning & SHA-256 Session Token Hashing',
      'Unknown OIDC user with realmRoles=[ADMIN, ANALYST] provisioned strictly as DEVELOPER with 0 memberships.',
    );

    // ------------------------------------------------------------------------
    // TEST 7: Rollback & Separate Failed-Login Audit Persistence (Unverified Email & Email Conflict)
    // ------------------------------------------------------------------------
    // 7a: Unverified email
    let unverifiedFailed = false;
    try {
      await authService.establishAuthenticatedSession({
        sub: `${runTag}-unverified-sub`,
        email: `${runTag}-unverified@example.com`,
        emailVerified: false,
        ipAddress: '10.0.0.99',
      });
    } catch (err: unknown) {
      if (err instanceof ForbiddenError) {
        unverifiedFailed = true;
      } else {
        throw err;
      }
    }
    if (!unverifiedFailed) {
      throw new Error('Expected emailVerified=false to throw ForbiddenError');
    }

    const unverifiedUserRow = await prisma.user.findUnique({
      where: { sub: `${runTag}-unverified-sub` },
    });
    if (unverifiedUserRow) {
      throw new Error('Unverified email login must not persist a User row');
    }

    // 7b: Email conflict with existing user's email under a different OIDC sub
    let conflictFailed = false;
    try {
      await authService.establishAuthenticatedSession({
        sub: `${runTag}-conflicting-sub`,
        email: jitEmail, // already owned by jitSub
        emailVerified: true,
        ipAddress: '10.0.0.100',
      });
    } catch (err: unknown) {
      if (err instanceof ForbiddenError) {
        conflictFailed = true;
      } else {
        throw err;
      }
    }
    if (!conflictFailed) {
      throw new Error('Expected email conflict with different sub to throw ForbiddenError');
    }

    const conflictUserRow = await prisma.user.findUnique({
      where: { sub: `${runTag}-conflicting-sub` },
    });
    if (conflictUserRow) {
      throw new Error('Conflicting email login must roll back without creating a User row');
    }

    // Verify auth.login_failed audit events were persisted outside the rolled-back transactions
    const failedAuditRows = await prisma.auditEvent.findMany({
      where: {
        id: { in: [...createdAuditEventIds] },
        eventCategory: 'AUTH',
        eventType: 'auth.login_failed',
      },
      orderBy: { createdAt: 'asc' },
    });

    const emailNotVerifiedAudit = failedAuditRows.find(
      (e) => (e.afterState as Record<string, unknown>)?.['reason'] === 'EMAIL_NOT_VERIFIED',
    );
    const emailConflictAudit = failedAuditRows.find(
      (e) => (e.afterState as Record<string, unknown>)?.['reason'] === 'EMAIL_SUB_CONFLICT',
    );

    if (
      !emailNotVerifiedAudit ||
      emailNotVerifiedAudit.actorId !== null ||
      !emailConflictAudit ||
      emailConflictAudit.actorId !== null ||
      emailConflictAudit.resourceId !== establishedJit.user.id
    ) {
      throw new Error('Expected persistent auth.login_failed audit rows with actorId=null');
    }
    recordPass(
      '7. Rollback & Separate Failed-Login Audit Persistence',
      'Rolled-back logins created 0 User/UserSession rows while persisting auth.login_failed with actorId=null.',
    );

    // ------------------------------------------------------------------------
    // TEST 8: Live Session Resolution, Sliding Idle Timeout, Role-Update Revocation & Deactivation Revocation
    // ------------------------------------------------------------------------
    const syntheticTestAdmin = await prisma.user.create({
      data: {
        sub: `${runTag}-test-admin-sub`,
        email: `${runTag}-test-admin@example.com`,
        displayName: 'Test Admin Actor',
        globalRole: 'ADMIN',
        isActive: true,
      },
    });
    createdUserIds.add(syntheticTestAdmin.id);

    const adminActor = new ActorContext({
      id: syntheticTestAdmin.id,
      globalRole: 'ADMIN',
      isActive: true,
    });

    // Create a project and add the JIT developer as a project DEVELOPER member
    const testProject = await projectService.createProject(adminActor, {
      name: `Auth Test Project ${runTag}`,
      description: 'Project for testing fresh session ActorContext resolution',
    });
    createdProjectIds.add(testProject.id);

    await projectService.addMember(adminActor, testProject.id, {
      userId: establishedJit.user.id,
      role: 'DEVELOPER',
    });

    // Resolve session 90 seconds after login -> should return fresh project membership AND advance idleExpiresAt
    const tPlus90s = new Date(establishedJit.session.lastActivityAt.getTime() + 90_000);
    const resolved = await authService.resolveSessionActor(
      { rawSessionToken: establishedJit.rawSessionToken },
      tPlus90s,
    );

    if (
      !resolved.actor.hasProjectRole(testProject.id, 'DEVELOPER') ||
      resolved.session.lastActivityAt.getTime() !== tPlus90s.getTime() ||
      resolved.session.idleExpiresAt.getTime() <= establishedJit.session.idleExpiresAt.getTime()
    ) {
      throw new Error('resolveSessionActor failed to load fresh memberships or advance sliding idle timeout');
    }

    // Update JIT user's global role to ANALYST -> must immediately revoke active session
    await authService.updateUserGlobalRole(
      adminActor,
      establishedJit.user.id,
      {
        globalRole: 'ANALYST',
        justification: 'Promoted to Analyst during integration test',
      },
      tPlus90s,
    );

    let revokedAfterRoleChange = false;
    try {
      await authService.resolveSessionActor(
        { rawSessionToken: establishedJit.rawSessionToken },
        tPlus90s,
      );
    } catch (err: unknown) {
      if (err instanceof UnauthorizedError) {
        revokedAfterRoleChange = true;
      } else {
        throw err;
      }
    }
    if (!revokedAfterRoleChange) {
      throw new Error('Expected session to be revoked immediately after global role change');
    }

    // Re-establish session for promoted user, then deactivate account -> revokes session & blocks re-login
    const reloginSession = await authService.establishAuthenticatedSession({
      sub: jitSub,
      email: jitEmail,
      emailVerified: true,
    });
    createdSessionIds.add(reloginSession.session.id);

    if (reloginSession.actor.globalRole !== 'ANALYST') {
      throw new Error(`Expected promoted role ANALYST, got ${reloginSession.actor.globalRole}`);
    }

    await authService.deactivateUser(adminActor, establishedJit.user.id, {
      justification: 'Deactivating test user in integration suite',
    });

    let revokedAfterDeactivation = false;
    try {
      await authService.resolveSessionActor({
        rawSessionToken: reloginSession.rawSessionToken,
      });
    } catch (err: unknown) {
      if (err instanceof UnauthorizedError) {
        revokedAfterDeactivation = true;
      } else {
        throw err;
      }
    }
    if (!revokedAfterDeactivation) {
      throw new Error('Expected session to be revoked immediately after account deactivation');
    }

    // Attempt login as deactivated user -> fails with 403 and records auth.login_failed with actorId = user.id
    let deactivatedLoginBlocked = false;
    try {
      await authService.establishAuthenticatedSession({
        sub: jitSub,
        email: jitEmail,
        emailVerified: true,
      });
    } catch (err: unknown) {
      if (err instanceof ForbiddenError) {
        deactivatedLoginBlocked = true;
      } else {
        throw err;
      }
    }
    if (!deactivatedLoginBlocked) {
      throw new Error('Expected deactivated user login to fail with ForbiddenError');
    }

    const deactivatedAudit = await prisma.auditEvent.findFirst({
      where: {
        id: { in: [...createdAuditEventIds] },
        eventCategory: 'AUTH',
        eventType: 'auth.login_failed',
        actorId: establishedJit.user.id,
      },
    });
    if (!deactivatedAudit) {
      throw new Error('Expected auth.login_failed with actorId set for deactivated existing user');
    }

    recordPass(
      '8. Live Session Resolution, Sliding Idle Timeout, Role-Change Revocation & Deactivation Enforcement',
      'Fresh DB memberships resolved, sliding window updated, and role/deactivation transitions revoked active sessions.',
    );

    // ------------------------------------------------------------------------
    // TEST 9: PostgreSQL Transaction Rollback on Audit-Append Failure & Failure-Audit Resilience
    // ------------------------------------------------------------------------
    const rollbackSub = `${runTag}-audit-rollback-sub`;
    const rollbackEmail = `${runTag}-audit-rollback@example.com`;

    // 9a: Simulate a failure on the auth.login_succeeded audit write inside a real PostgreSQL transaction:
    // verify that both the JIT-created user row and the user_sessions row roll back atomically.
    let auditSuccessWriteRolledBack = false;
    try {
      await dbManager.runTransaction(async (txRepos) => {
        const originalAppend = txRepos.auditRepo.append.bind(txRepos.auditRepo);
        txRepos.auditRepo.append = async (data) => {
          if (data.eventType === 'auth.login_succeeded') {
            throw new Error('SIMULATED_PG_AUDIT_APPEND_FAILURE');
          }
          return await originalAppend(data);
        };

        const createdUser = await txRepos.userRepo.createUser!({
          sub: rollbackSub,
          email: rollbackEmail,
          displayName: 'Audit Rollback Test User',
          globalRole: 'DEVELOPER',
          isActive: true,
        });
        await txRepos.sessionRepo!.create({
          userId: createdUser.id,
          tokenHash: hashOpaqueToken(generateOpaqueToken(32)),
          lastActivityAt: new Date(),
          idleExpiresAt: new Date(Date.now() + 1800_000),
          expiresAt: new Date(Date.now() + 28800_000),
        });
        await txRepos.auditRepo.append({
          actorId: createdUser.id,
          eventCategory: 'AUTH',
          eventType: 'auth.login_succeeded',
          resourceId: createdUser.id,
          resourceType: 'UserSession',
        });
      });
    } catch (err: unknown) {
      if (String(err).includes('SIMULATED_PG_AUDIT_APPEND_FAILURE')) {
        auditSuccessWriteRolledBack = true;
      } else {
        throw err;
      }
    }

    const rolledBackUserRow = await prisma.user.findUnique({ where: { sub: rollbackSub } });
    if (!auditSuccessWriteRolledBack || rolledBackUserRow !== null) {
      throw new Error(
        'Expected PostgreSQL transaction to roll back user and session rows when auth.login_succeeded audit write fails',
      );
    }

    // 9b: Verify that if recordAuthenticationFailure fails, the failed login still throws and never authorizes access
    const originalGetRepos = dbManager.getRepositories.bind(dbManager);
    dbManager.getRepositories = () => {
      const repos = originalGetRepos();
      return {
        ...repos,
        auditRepo: {
          ...repos.auditRepo,
          append: async () => {
            throw new Error('SIMULATED_FAILURE_AUDIT_UNAVAILABLE');
          },
        },
      };
    };

    let rejectedDespiteAuditOutage = false;
    try {
      await authService.establishAuthenticatedSession({
        sub: `${runTag}-outage-sub`,
        email: `${runTag}-outage@example.com`,
        emailVerified: false,
      });
    } catch (err: unknown) {
      if (err instanceof ForbiddenError) {
        rejectedDespiteAuditOutage = true;
      } else {
        throw err;
      }
    } finally {
      dbManager.getRepositories = originalGetRepos;
    }

    if (!rejectedDespiteAuditOutage) {
      throw new Error('Expected failed login to remain rejected even when failure-audit write throws');
    }

    recordPass(
      '9. PostgreSQL Audit-Failure Resilience (Atomic Rollback on Success Audit Failure & Fail-Closed Login Rejection)',
      'Failed success-audit rolled back User + UserSession; failed failure-audit still rejected login.',
    );

    // ------------------------------------------------------------------------
    // TEST 10: Case-Insensitive Email Uniqueness & Concurrent JIT Provisioning Races
    // ------------------------------------------------------------------------
    // 10a: Direct PostgreSQL unique index enforcement on users(LOWER(email))
    const caseOwnerEmail = `${runTag}-case-owner@example.com`;
    const caseOwner = await prisma.user.create({
      data: {
        sub: `${runTag}-case-owner-sub`,
        email: caseOwnerEmail,
        displayName: 'Case Email Owner',
        globalRole: 'DEVELOPER',
        isActive: true,
      },
    });
    createdUserIds.add(caseOwner.id);

    const caseProbeClient = new pg.Client({ connectionString: rawTestUrl });
    await caseProbeClient.connect();
    let lowerEmailConstraintTriggered = false;
    try {
      await caseProbeClient.query(
        `INSERT INTO public.users (id, sub, email, display_name, global_role, is_active, created_at, updated_at)
         VALUES (gen_random_uuid(), $1, $2, 'Case Variant Bypass', 'DEVELOPER', true, NOW(), NOW());`,
        [`${runTag}-case-bypass-sub`, `${runTag}-CASE-OWNER@Example.COM`],
      );
    } catch (err: unknown) {
      const pgErr = err as { code?: string; constraint?: string; message?: string };
      if (
        pgErr.code === '23505' &&
        (pgErr.constraint === 'users_email_lower_key' ||
          String(pgErr.message).includes('users_email_lower_key'))
      ) {
        lowerEmailConstraintTriggered = true;
      } else {
        throw err;
      }
    } finally {
      await caseProbeClient.end();
    }
    if (!lowerEmailConstraintTriggered) {
      throw new Error(
        'Expected PostgreSQL users_email_lower_key unique index to block case-variant duplicate email',
      );
    }

    // 10b: Concurrent 5-way same-sub JIT provisioning race (must succeed idempotently 5/5)
    const sameSubRaceId = `${runTag}-jit-same-sub-race`;
    const sameSubVariants = [
      `${runTag}-samesub@example.com`,
      `${runTag}-SAMESUB@example.com`,
      `${runTag}-SameSub@Example.COM`,
      `${runTag}-samesub@EXAMPLE.com`,
      `${runTag}-SaMeSuB@eXaMpLe.CoM`,
    ];
    const sameSubOutcomes = await Promise.all(
      sameSubVariants.map((emailVariant, idx) =>
        authService.establishAuthenticatedSession({
          sub: sameSubRaceId,
          email: emailVariant,
          emailVerified: true,
          displayName: `Concurrent Same Sub ${idx + 1}`,
          realmRoles: ['ADMIN'],
          ipAddress: '198.51.100.10',
        }),
      ),
    );
    const sameSubWinnerId = sameSubOutcomes[0]!.user.id;
    createdUserIds.add(sameSubWinnerId);
    for (const outcome of sameSubOutcomes) {
      createdSessionIds.add(outcome.session.id);
      if (outcome.user.id !== sameSubWinnerId || outcome.actor.globalRole !== 'DEVELOPER') {
        throw new Error('Same-sub concurrent JIT race returned inconsistent user ID or role');
      }
    }
    const jitProvisionedWinners = sameSubOutcomes.filter((o) => o.jitProvisioned);
    if (jitProvisionedWinners.length !== 1) {
      throw new Error(
        `Expected exactly 1 jitProvisioned=true across 5 concurrent same-sub logins, got ${jitProvisionedWinners.length}`,
      );
    }
    const sameSubDbUsersCount = await prisma.user.count({ where: { sub: sameSubRaceId } });
    const sameSubDbSessionsCount = await prisma.userSession.count({
      where: { userId: sameSubWinnerId, revokedAt: null },
    });
    if (sameSubDbUsersCount !== 1 || sameSubDbSessionsCount !== 5) {
      throw new Error(
        `Same-sub race invariant failed: users=${sameSubDbUsersCount}, sessions=${sameSubDbSessionsCount}`,
      );
    }

    // 10c: Concurrent 5-way different-sub case-equivalent email JIT race (1 winner, 4 generic 403 + persisted audit)
    const diffSubEmailVariants = [
      `${runTag}-diffrace@example.com`,
      `${runTag}-DIFFRACE@example.com`,
      `${runTag}-DiffRace@Example.COM`,
      `${runTag}-diffrace@EXAMPLE.com`,
      `${runTag}-dIfFrAcE@eXaMpLe.cOm`,
    ];
    const diffSubRaceOutcomes = await Promise.allSettled(
      diffSubEmailVariants.map((emailVariant, idx) =>
        authService.establishAuthenticatedSession({
          sub: `${runTag}-diff-race-sub-${idx}`,
          email: emailVariant,
          emailVerified: true,
          displayName: `Competing User ${idx}`,
          ipAddress: '198.51.100.20',
          userAgent: `DiffSubRaceWorker/${idx}`,
        }),
      ),
    );

    const diffFulfilled = diffSubRaceOutcomes.filter(
      (
        o,
      ): o is PromiseFulfilledResult<
        Awaited<ReturnType<typeof authService.establishAuthenticatedSession>>
      > => o.status === 'fulfilled',
    );
    const diffRejected = diffSubRaceOutcomes.filter(
      (o): o is PromiseRejectedResult => o.status === 'rejected',
    );
    if (diffFulfilled.length !== 1 || diffRejected.length !== 4) {
      throw new Error(
        `Expected 1 fulfilled and 4 rejected in different-sub email race, got ${diffFulfilled.length} fulfilled / ${diffRejected.length} rejected`,
      );
    }
    const diffWinner = diffFulfilled[0]!.value;
    createdUserIds.add(diffWinner.user.id);
    createdSessionIds.add(diffWinner.session.id);

    for (const rej of diffRejected) {
      if (!(rej.reason instanceof ForbiddenError)) {
        throw new Error(
          `Expected ForbiddenError (403) in different-sub email race, got: ${String(rej.reason)}`,
        );
      }
      if (/23505|P2002|users_email_lower_key|users_email_key|unique constraint/i.test(rej.reason.message)) {
        throw new Error(`Constraint details leaked to caller: ${rej.reason.message}`);
      }
      if (rej.reason.details !== undefined) {
        throw new Error('Expected ForbiddenError.details to remain undefined');
      }
    }

    const diffWinnerCount = await prisma.user.count({
      where: { sub: { startsWith: `${runTag}-diff-race-sub-` } },
    });
    const diffConflictAudits = await prisma.auditEvent.count({
      where: {
        id: { in: [...createdAuditEventIds] },
        eventCategory: 'AUTH',
        eventType: 'auth.login_failed',
        actorId: null,
        resourceId: diffWinner.user.id,
      },
    });
    if (diffWinnerCount !== 1 || diffConflictAudits !== 4) {
      throw new Error(
        `Different-sub email race persistence mismatch: users=${diffWinnerCount}, conflictAudits=${diffConflictAudits}`,
      );
    }

    recordPass(
      '10. Case-Insensitive Email Uniqueness & Concurrent JIT Provisioning Races',
      'PG rejected direct case-variant insert (users_email_lower_key); 5/5 same-sub race succeeded; 1/5 diff-sub race admitted & 4/5 rejected cleanly.',
    );

    // ------------------------------------------------------------------------
    // TEST 11: Out-of-Band User Deactivation in resolveSessionActor
    // ------------------------------------------------------------------------
    const oobEstablished = await authService.establishAuthenticatedSession({
      sub: `${runTag}-oob-deact-sub`,
      email: `${runTag}-oob-deact@example.com`,
      emailVerified: true,
      displayName: 'OOB Deactivated User',
      ipAddress: '198.51.100.30',
    });
    createdUserIds.add(oobEstablished.user.id);
    createdSessionIds.add(oobEstablished.session.id);

    const loginSuccessCountBeforeOob = await prisma.auditEvent.count({
      where: {
        actorId: oobEstablished.user.id,
        eventCategory: 'AUTH',
        eventType: 'auth.login_succeeded',
      },
    });

    // Deactivate user out-of-band directly in PostgreSQL without pre-revoking sessions
    await prisma.user.update({
      where: { id: oobEstablished.user.id },
      data: { isActive: false },
    });

    let oobRejectedWithForbidden = false;
    try {
      await authService.resolveSessionActor({
        rawSessionToken: oobEstablished.rawSessionToken,
      });
    } catch (err: unknown) {
      if (err instanceof ForbiddenError) {
        oobRejectedWithForbidden = true;
      } else {
        throw err;
      }
    }
    if (!oobRejectedWithForbidden) {
      throw new Error('Expected resolveSessionActor to throw ForbiddenError for out-of-band deactivated user');
    }

    const oobSessionRow = await prisma.userSession.findUnique({
      where: { id: oobEstablished.session.id },
    });
    const loginSuccessCountAfterOob = await prisma.auditEvent.count({
      where: {
        actorId: oobEstablished.user.id,
        eventCategory: 'AUTH',
        eventType: 'auth.login_succeeded',
      },
    });

    if (
      !oobSessionRow?.revokedAt ||
      oobSessionRow.revokeReason !== 'USER_DEACTIVATED' ||
      loginSuccessCountAfterOob !== loginSuccessCountBeforeOob
    ) {
      throw new Error(
        `Out-of-band deactivation revocation mismatch: revokedAt=${oobSessionRow?.revokedAt}, reason=${oobSessionRow?.revokeReason}, loginSucceededBefore=${loginSuccessCountBeforeOob}, after=${loginSuccessCountAfterOob}`,
      );
    }

    recordPass(
      '11. Out-of-Band User Deactivation in resolveSessionActor',
      'Returned HTTP 403, persisted revoked_at with USER_DEACTIVATED, and emitted 0 additional auth.login_succeeded.',
    );

    // Insert an unrelated AUTH sentinel audit row outside createdAuditEventIds to verify in finally
    // that test-owned cleanup never sweeps unrelated AUTH audit history created in the suite window.
    const sentinelAudit = await prisma.auditEvent.create({
      data: {
        actorId: null,
        eventCategory: 'AUTH',
        eventType: 'auth.sentinel_cleanup_isolation_probe',
        resourceType: 'System',
        afterState: { sentinelRunTag: runTag },
      },
    });
    sentinelAuditId = sentinelAudit.id;
  } finally {
    // Clean up strictly test-owned records in reverse FK dependency order using exact captured IDs
    const prisma = dbManager.getPrismaClient();
    const userIdList = [...createdUserIds];
    const projectIdList = [...createdProjectIds];
    const sessionIdList = [...createdSessionIds];
    const oidcTxnIdList = [...createdOidcTxnIds];
    const auditEventIdList = [...createdAuditEventIds];

    if (auditEventIdList.length > 0) {
      await prisma.auditEvent.deleteMany({
        where: { id: { in: auditEventIdList } },
      });
    }

    if (sentinelAuditId) {
      const preservedSentinel = await prisma.auditEvent.findUnique({
        where: { id: sentinelAuditId },
      });
      if (!preservedSentinel) {
        throw new Error(
          'Cleanup isolation regression: unrelated AUTH sentinel event created during suite window was deleted!',
        );
      }
      recordPass(
        '12. Exact Audit ID Cleanup & Unrelated AUTH Event Preservation',
        `Preserved unrelated AUTH sentinel event ${sentinelAuditId} after deleting ${auditEventIdList.length} tracked suite audit events.`,
      );
      await prisma.auditEvent.delete({
        where: { id: sentinelAuditId },
      });
    }

    if (sessionIdList.length > 0 || userIdList.length > 0) {
      await prisma.userSession.deleteMany({
        where: {
          OR: [
            ...(sessionIdList.length > 0 ? [{ id: { in: sessionIdList } }] : []),
            ...(userIdList.length > 0 ? [{ userId: { in: userIdList } }] : []),
          ],
        },
      });
    }

    if (oidcTxnIdList.length > 0) {
      await prisma.oidcTransaction.deleteMany({
        where: { id: { in: oidcTxnIdList } },
      });
    }

    if (projectIdList.length > 0) {
      await prisma.projectMember.deleteMany({
        where: { projectId: { in: projectIdList } },
      });
      await prisma.project.deleteMany({
        where: { id: { in: projectIdList } },
      });
    }

    if (userIdList.length > 0) {
      await prisma.user.deleteMany({
        where: { id: { in: userIdList } },
      });
    }

    if (initialPublicUsersSnapshot) {
      const finalPublicUsersSnapshot = await capturePublicUsersSnapshot();
      assertPublicUsersSnapshotEqual(
        initialPublicUsersSnapshot,
        finalPublicUsersSnapshot,
        'Suite teardown',
      );
    }

    if (initialCounts) {
      const finalCounts = await getTableCounts(dbManager);
      const mismatches: string[] = [];
      for (const key of Object.keys(initialCounts) as Array<keyof TableCounts>) {
        if (initialCounts[key] !== finalCounts[key]) {
          mismatches.push(`${key}: before=${initialCounts[key]}, after=${finalCounts[key]}`);
        }
      }
      if (mismatches.length > 0) {
        throw new Error(
          `Zero net row accumulation check failed: ${mismatches.join('; ')}`,
        );
      }
      recordPass(
        '13. Deterministic Cleanup & Zero Net Row Accumulation Across All 9 Tables',
        `All 9 tables restored to exact baseline counts (${JSON.stringify(finalCounts)}).`,
      );
    }

    await dbManager.shutdown();
  }

  console.log('==================================================');
  console.log(`Summary: ${passedTests}/${totalTests} tests passed.`);
  console.log('==================================================');

  return {
    allPassed: passedTests === totalTests && totalTests > 0,
    totalTests,
    passedTests,
  };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  runGate4b1AuthFoundationIntegrationTests()
    .then((res) => {
      process.exit(res.allPassed ? 0 : 1);
    })
    .catch((err: unknown) => {
      console.error('FATAL INTEGRATION TEST ERROR:', err);
      process.exit(1);
    });
}
