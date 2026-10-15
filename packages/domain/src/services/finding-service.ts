import type { FindingRecord, FindingSeverity } from '@secureflow/schemas';
import { SecureFlowError, formatDateIso } from '@secureflow/shared';
import { FindingRepository } from '../db/finding-repository.js';

export interface CreateFindingDto {
  id: string;
  projectId: string;
  title: string;
  severity: FindingSeverity;
}

/**
 * Finding Domain Service.
 * Public service layer entry point mediating all access to findings data.
 */
export class FindingService {
  private readonly repo = new FindingRepository();

  public async getFindingById(id: string): Promise<FindingRecord> {
    const finding = await this.repo.findById(id);
    if (!finding) {
      throw new SecureFlowError(`Finding with ID '${id}' not found`, 'FINDING_NOT_FOUND', 404);
    }
    return finding;
  }

  public async createFinding(dto: CreateFindingDto): Promise<FindingRecord> {
    const record: FindingRecord = {
      id: dto.id,
      projectId: dto.projectId,
      title: dto.title,
      severity: dto.severity,
      status: 'OPEN',
      createdAt: formatDateIso(new Date()),
    };
    await this.repo.save(record);
    return record;
  }
}
