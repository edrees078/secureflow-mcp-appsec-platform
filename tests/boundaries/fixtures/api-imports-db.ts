/**
 * NEGATIVE TEST FIXTURE: apps/api imports domain internal repository
 * Architectural violation: apps/api cannot bypass service layer to touch database directly.
 * Expected ESLint Rule: boundaries/dependencies
 */
import { FindingRepository } from '../../../packages/domain/src/db/finding-repository.js';

export function invalidApiDirectDbAccess(): void {
  const repo = new FindingRepository();
  console.log(repo);
}
