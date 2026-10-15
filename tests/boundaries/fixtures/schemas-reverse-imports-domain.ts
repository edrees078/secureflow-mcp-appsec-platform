/**
 * NEGATIVE TEST FIXTURE: packages/schemas imports @secureflow/domain
 * Architectural violation: packages/schemas cannot reverse-import domain layer.
 * Expected ESLint Rule: boundaries/dependencies
 */
import { FindingService } from '@secureflow/domain';

export function invalidSchemaReverseImport(): void {
  const service = new FindingService();
  console.log(service);
}
