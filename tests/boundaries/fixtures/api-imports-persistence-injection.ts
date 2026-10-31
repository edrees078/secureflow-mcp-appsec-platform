/**
 * NEGATIVE TEST FIXTURE: apps/api imports domain test persistence injection helpers
 * Architectural violation: apps/api production code cannot import createTestTaskService or RepositoryContainer.
 * Expected ESLint Rule: boundaries/dependencies
 */
import { createTestTaskService } from '@secureflow/domain/testing';

export function invalidApiPersistenceInjectionUsage(): void {
  const service = createTestTaskService({} as never);
  console.log(service);
}
