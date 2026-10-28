/**
 * NEGATIVE TEST FIXTURE: apps/mcp-server imports domain testing helpers
 * Architectural violation: apps/mcp-server production code cannot import @secureflow/domain/testing.
 * Expected ESLint Rule: boundaries/dependencies
 */
import { createSyntheticActorContext } from '@secureflow/domain/testing';

export function invalidMcpTestingHelperUsage(): void {
  const actor = createSyntheticActorContext({
    id: '00000000-0000-0000-0000-000000000001',
    sub: 'auth0|test-admin',
    email: 'admin@demo.local',
    displayName: 'Admin User',
    globalRole: 'ADMIN',
    isActive: true,
  });
  console.log(actor);
}
