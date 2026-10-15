/**
 * NEGATIVE TEST FIXTURE: apps/api imports apps/web
 * Architectural violation: Cross-application imports are strictly forbidden.
 * Expected ESLint Rule: boundaries/dependencies
 */
import { renderFindingBadge } from '../../../apps/web/src/index.js';

export function invalidCrossAppImport(): void {
  console.log(renderFindingBadge);
}
