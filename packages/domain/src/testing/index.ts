/**
 * SecureFlow Domain Testing Helpers Entry Point.
 *
 * Isolated testing utilities for unit and integration testing.
 *
 * SECURITY BOUNDARY:
 * - This entry point (@secureflow/domain/testing) is strictly restricted to test code.
 * - Production applications (apps/api, apps/mcp-server, apps/web) are strictly forbidden
 *   from importing this module, enforced by ESLint architectural boundary rules.
 * - Synthetic test actors must NEVER be used with untrusted transport inputs in production.
 */

import {
  ActorContext,
  createSyntheticActorContext as createSyntheticContextInternal,
  type ActorContextParams,
  type ProjectMembership,
} from '../policy/actor-context.js';

export {
  ActorContext,
  type ActorContextParams,
  type ProjectMembership,
};

/**
 * Creates a synthetic ActorContext instance for deterministic unit/integration testing.
 * Strictly forbidden from being used in production code.
 */
export function createSyntheticActorContext(params: ActorContextParams): ActorContext {
  return createSyntheticContextInternal(params);
}

/**
 * Convenience builder for synthetic Admin test actor.
 */
export function createTestAdminActor(overrides?: Partial<ActorContextParams>): ActorContext {
  return new ActorContext({
    id: '00000000-0000-0000-0000-000000000001',
    globalRole: 'ADMIN',
    isActive: true,
    memberships: [],
    ...overrides,
  });
}

/**
 * Convenience builder for synthetic Analyst test actor with project membership.
 */
export function createTestAnalystActor(
  projectId: string,
  overrides?: Partial<ActorContextParams>,
): ActorContext {
  const membership: ProjectMembership = {
    projectId,
    role: 'ANALYST',
  };

  return new ActorContext({
    id: '00000000-0000-0000-0000-000000000002',
    globalRole: 'ANALYST',
    isActive: true,
    memberships: [membership],
    ...overrides,
  });
}

/**
 * Convenience builder for synthetic Developer test actor with project membership.
 */
export function createTestDeveloperActor(
  projectId: string,
  overrides?: Partial<ActorContextParams>,
): ActorContext {
  const membership: ProjectMembership = {
    projectId,
    role: 'DEVELOPER',
  };

  return new ActorContext({
    id: '00000000-0000-0000-0000-000000000003',
    globalRole: 'DEVELOPER',
    isActive: true,
    memberships: [membership],
    ...overrides,
  });
}

// ============================================================================
// Controlled Test Dependency Injection Helpers
// ============================================================================

import { ProjectService } from '../services/project-service.js';
import { AuditService } from '../services/audit-service.js';
import { FindingService } from '../services/finding-service.js';
import { TaskService } from '../services/task-service.js';
import type { RepositoryContainer } from '../db/repositories/types.js';
import { TEST_PERSISTENCE_TOKEN } from '../services/persistence-token.js';

export type { RepositoryContainer };

/**
 * Creates a test ProjectService instance with injected mock or in-memory repositories.
 * Strictly forbidden from being used in production application code.
 */
export function createTestProjectService(repositories: RepositoryContainer): ProjectService {
  return new ProjectService({ repositories, [TEST_PERSISTENCE_TOKEN]: true } as never);
}

/**
 * Creates a test AuditService instance with injected mock or in-memory repositories.
 * Strictly forbidden from being used in production application code.
 */
export function createTestAuditService(repositories: RepositoryContainer): AuditService {
  return new AuditService({ repositories, [TEST_PERSISTENCE_TOKEN]: true } as never);
}

/**
 * Creates a test FindingService instance with injected mock or in-memory repositories.
 * Strictly forbidden from being used in production application code.
 */
export function createTestFindingService(repositories: RepositoryContainer): FindingService {
  return new FindingService({ repositories, [TEST_PERSISTENCE_TOKEN]: true } as never);
}

/**
 * Creates a test TaskService instance with injected mock or in-memory repositories.
 * Strictly forbidden from being used in production application code.
 */
export function createTestTaskService(repositories: RepositoryContainer): TaskService {
  return new TaskService({ repositories, [TEST_PERSISTENCE_TOKEN]: true } as never);
}

// ============================================================================
// Test-Scoped Database Fixture & Cleanup Helpers
// ============================================================================

import pg from 'pg';
import { SecureFlowError } from '@secureflow/shared';

/**
 * Validates integration test database connection URLs against approved safety constraints.
 * Strictly confines integration tests to host port 5433 and database 'secureflow_test'.
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

  const APPROVED_HOSTS = new Set(['127.0.0.1', 'localhost', '::1', '[::1]']);
  const normalizedHost = parsed.hostname.toLowerCase();
  if (!APPROVED_HOSTS.has(normalizedHost)) {
    throw new SecureFlowError(
      `SAFETY REFUSAL: TEST_DATABASE_URL must target an approved local loopback host (127.0.0.1, localhost, ::1), but received "${parsed.hostname}". Remote test databases are strictly prohibited.`,
      'TEST_DATABASE_HOST_REFUSED',
      500,
    );
  }

  return rawUrl;
}

export interface CleanupOptions {
  injectFailureAfterStep?: number;
}

export interface TestDatabaseClient {
  query<R extends pg.QueryResultRow = pg.QueryResultRow>(
    queryText: string,
    values?: readonly unknown[],
  ): Promise<pg.QueryResult<R>>;
  registerSyntheticProject(projectId: string): void;
  cleanupProjectHierarchy(projectId: string, options?: CleanupOptions): Promise<void>;
  close(): Promise<void>;
}

/**
 * Creates an isolated, test-owned PostgreSQL database client for integration test cleanup and assertions.
 * Validates connection URL and asserts engine identity ('secureflow_test') before enabling queries.
 * Strictly restricted to test code (@secureflow/domain/testing).
 */
export async function createTestDatabaseClient(connectionString: string): Promise<TestDatabaseClient> {
  // 1. Enforce strict URL-level safety assertions
  const validatedUrl = validateTestDatabaseUrl(connectionString);

  // 2. Establish test-owned connection
  const client = new pg.Client({
    connectionString: validatedUrl,
    connectionTimeoutMillis: 5000,
  });
  await client.connect();

  // 3. Confirm engine identity before enabling queries or destructive cleanup
  try {
    const idRes = await client.query<{ current_db: string; full_version: string }>(
      'SELECT current_database() AS current_db, version() AS full_version;',
    );
    const dbName = idRes.rows[0]?.current_db;
    if (dbName !== 'secureflow_test') {
      await client.end();
      throw new SecureFlowError(
        `SAFETY REFUSAL: Connected database identity is '${dbName}', expected 'secureflow_test'.`,
        'TEST_DATABASE_IDENTITY_MISMATCH',
        500,
      );
    }
  } catch (err: unknown) {
    await client.end();
    throw err;
  }

  const registeredSyntheticProjects = new Set<string>();

  return {
    query: <R extends pg.QueryResultRow = pg.QueryResultRow>(
      queryText: string,
      values?: readonly unknown[],
    ) => client.query<R>(queryText, values ? [...values] : undefined),
    registerSyntheticProject: (projectId: string): void => {
      if (!projectId || typeof projectId !== 'string' || projectId.trim().length === 0) {
        throw new SecureFlowError(
          'SAFETY REFUSAL: Cannot register empty or invalid synthetic project ID.',
          'TEST_SYNTHETIC_PROJECT_ID_INVALID',
          500,
        );
      }
      registeredSyntheticProjects.add(projectId.trim());
    },
    cleanupProjectHierarchy: async (
      projectId: string,
      options?: CleanupOptions,
    ): Promise<void> => {
      if (!projectId) return;

      if (!registeredSyntheticProjects.has(projectId)) {
        throw new SecureFlowError(
          `SAFETY REFUSAL: Project '${projectId}' is not registered as a synthetic test project owned by this test client. Refusing cleanup of unregistered project to prevent accidental deletion of existing fixtures.`,
          'TEST_CLEANUP_UNREGISTERED_PROJECT',
          500,
        );
      }

      // Execute all cleanup operations within an explicit transaction
      await client.query('BEGIN');
      try {
        // Clean up in reverse foreign-key dependency order with strict WHERE filters:
        // 1. Dependent remediation tasks (if any exist for findings in this project)
        await client.query(
          `DELETE FROM remediation_tasks WHERE finding_id IN (SELECT id FROM findings WHERE project_id = $1);`,
          [projectId],
        );
        if (options?.injectFailureAfterStep === 1) {
          throw new Error('INJECTED_CLEANUP_FAILURE_AFTER_STEP_1');
        }

        // 2. Dependent finding events (if any exist for findings in this project)
        await client.query(
          `DELETE FROM finding_events WHERE finding_id IN (SELECT id FROM findings WHERE project_id = $1);`,
          [projectId],
        );
        if (options?.injectFailureAfterStep === 2) {
          throw new Error('INJECTED_CLEANUP_FAILURE_AFTER_STEP_2');
        }

        // 3. Dependent findings (if any exist in this project)
        await client.query(
          `DELETE FROM findings WHERE project_id = $1;`,
          [projectId],
        );
        if (options?.injectFailureAfterStep === 3) {
          throw new Error('INJECTED_CLEANUP_FAILURE_AFTER_STEP_3');
        }

        // 4. Audit events associated with this project or its member additions/removals
        await client.query(
          `DELETE FROM audit_events WHERE resource_id = $1::uuid OR (resource_type = 'ProjectMember' AND ((before_state->>'projectId') = $1::text OR (after_state->>'projectId') = $1::text));`,
          [projectId],
        );
        if (options?.injectFailureAfterStep === 4) {
          throw new Error('INJECTED_CLEANUP_FAILURE_AFTER_STEP_4');
        }

        // 5. Project members referencing this project
        await client.query(
          `DELETE FROM project_members WHERE project_id = $1;`,
          [projectId],
        );
        if (options?.injectFailureAfterStep === 5) {
          throw new Error('INJECTED_CLEANUP_FAILURE_AFTER_STEP_5');
        }

        // 6. Project itself
        await client.query(
          `DELETE FROM projects WHERE id = $1;`,
          [projectId],
        );

        await client.query('COMMIT');
        registeredSyntheticProjects.delete(projectId);
      } catch (cleanupErr: unknown) {
        let rollbackErr: unknown = null;
        try {
          await client.query('ROLLBACK');
        } catch (rErr: unknown) {
          rollbackErr = rErr;
        }

        const cleanupMsg = cleanupErr instanceof Error ? cleanupErr.message : String(cleanupErr);
        if (rollbackErr) {
          const rollbackMsg = rollbackErr instanceof Error ? rollbackErr.message : String(rollbackErr);
          throw new Error(
            `Project cleanup transaction failed: ${cleanupMsg}. Rollback also failed: ${rollbackMsg}`,
          );
        }
        throw new Error(`Project cleanup transaction failed: ${cleanupMsg}`);
      }
    },
    close: async (): Promise<void> => {
      await client.end();
    },
  };
}
