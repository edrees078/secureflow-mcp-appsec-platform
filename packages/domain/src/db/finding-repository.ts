import type { FindingRecord } from '@secureflow/schemas';

/**
 * @deprecated Legacy in-memory stub for FindingRepository created during Phase 2.
 * Preserved strictly for architectural boundary test fixtures (api-imports-db, mcp-imports-db)
 * and the placeholder FindingService until Gate 3D domain service migration.
 * Production repositories for Gate 3B+ are located in packages/domain/src/db/repositories/.
 * MUST NOT be imported directly by apps/api or apps/mcp-server.
 */
export class FindingRepository {
  private static readonly records: FindingRecord[] = [];

  public async findById(id: string): Promise<FindingRecord | null> {
    const found = FindingRepository.records.find((r) => r.id === id);
    return found ?? null;
  }

  public async save(finding: FindingRecord): Promise<void> {
    FindingRepository.records.push(finding);
  }
}
