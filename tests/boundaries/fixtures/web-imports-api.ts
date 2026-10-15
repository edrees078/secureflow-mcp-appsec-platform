/**
 * NEGATIVE TEST FIXTURE: apps/web imports apps/api
 * Architectural violation: Cross-application imports are strictly forbidden.
 * Expected ESLint Rule: boundaries/dependencies
 */
import { ApiServer } from '../../../apps/api/src/index.js';

export function invalidCrossAppImport(): void {
  const server = new ApiServer();
  console.log(server);
}
