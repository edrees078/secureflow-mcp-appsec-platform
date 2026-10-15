import { FindingService } from '@secureflow/domain';
import type { FindingRecord } from '@secureflow/schemas';
import { SecureFlowError } from '@secureflow/shared';

export class McpDaemon {
  private readonly findingService = new FindingService();

  public async handleGetFinding(id: string): Promise<FindingRecord> {
    try {
      return await this.findingService.getFindingById(id);
    } catch (err: unknown) {
      if (err instanceof SecureFlowError) {
        throw err;
      }
      throw new SecureFlowError('MCP handler failure', 'MCP_HANDLER_ERROR', 500);
    }
  }
}
