import { FindingService, type CreateFindingDto } from '@secureflow/domain';
import type { FindingRecord } from '@secureflow/schemas';
import { SecureFlowError } from '@secureflow/shared';

export class ApiServer {
  private readonly findingService = new FindingService();

  public async getFinding(id: string): Promise<FindingRecord> {
    try {
      return await this.findingService.getFindingById(id);
    } catch (err: unknown) {
      if (err instanceof SecureFlowError) {
        throw err;
      }
      throw new SecureFlowError('Unexpected error in API server', 'API_INTERNAL_ERROR', 500);
    }
  }

  public async createFinding(dto: CreateFindingDto): Promise<FindingRecord> {
    return this.findingService.createFinding(dto);
  }
}
