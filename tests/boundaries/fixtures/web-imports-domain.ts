/**
 * NEGATIVE TEST FIXTURE: apps/web imports @secureflow/domain
 * Architectural violation: Frontend apps/web cannot import server-only domain code.
 * Expected ESLint Rule: boundaries/dependencies
 */
import { FindingService } from '@secureflow/domain';

export function invalidFrontendOperation(): void {
  const service = new FindingService();
  console.log(service);
}
