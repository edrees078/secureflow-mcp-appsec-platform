/**
 * NEGATIVE TEST FIXTURE: apps/mcp-server imports domain test persistence injection helpers
 * Architectural violation: apps/mcp-server production code cannot import createTestTaskService or RepositoryContainer.
 * Expected ESLint Rule: boundaries/dependencies
 */
import { createTestTaskService } from '@secureflow/domain/testing';

export function invalidMcpPersistenceInjectionUsage(): void {
  const service = createTestTaskService({} as never);
  console.log(service);
}
