/**
 * NEGATIVE TEST FIXTURE: apps/mcp-server imports domain internal repository
 * Architectural violation: apps/mcp-server cannot bypass service layer to touch database directly.
 * Expected ESLint Rule: boundaries/dependencies
 */
import { FindingRepository } from '../../../packages/domain/src/db/finding-repository.js';

export function invalidMcpDirectDbAccess(): void {
  const repo = new FindingRepository();
  console.log(repo);
}
