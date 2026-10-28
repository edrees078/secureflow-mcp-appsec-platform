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
