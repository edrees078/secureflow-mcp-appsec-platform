/**
 * NEGATIVE TEST FIXTURE: apps/api production code imports test helpers
 * Architectural violation: apps/api/src cannot import from apps/api/tests.
 * Expected ESLint Rule: boundaries/dependencies
 */
import { createTestApp } from '../tests/helpers/test-app.js';

export function invalidApiTestHelperUsage(): void {
  console.log(createTestApp);
}
