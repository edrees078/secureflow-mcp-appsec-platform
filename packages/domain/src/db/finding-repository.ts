import type { FindingRecord } from '@secureflow/schemas';

/**
 * Internal Database Repository for Findings.
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
