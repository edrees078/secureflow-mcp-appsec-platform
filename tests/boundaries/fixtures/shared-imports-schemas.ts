/**
 * NEGATIVE TEST FIXTURE: packages/shared imports @secureflow/schemas
 * Architectural violation: packages/shared is a pure leaf package and cannot import schemas.
 * Expected ESLint Rule: boundaries/dependencies
 */
import type { FindingRecord } from '@secureflow/schemas';

export function invalidSharedImport(): FindingRecord {
  return {} as FindingRecord;
}
