import { FindingService, ActorContext, type FindingEntity } from '@secureflow/domain';
import type { FindingRecord } from '@secureflow/schemas';
import { SecureFlowError } from '@secureflow/shared';

export class McpDaemon {
  private readonly findingService = new FindingService();

  /**
   * Authorized MCP finding query handler.
   * Mandates authenticated ActorContext to enforce object-level authorization and existence hiding.
   *
   * Temporary Prototype Limitation (Sub-Gate 3D.1):
   * FindingService.getFinding currently returns a 501 NOT_IMPLEMENTED stub pending full
   * transactional implementation scheduled for Sub-Gate 3D.3. Invoking this method will reject
   * with SecureFlowError('NOT_IMPLEMENTED', 501).
   */
  public async handleGetFinding(actor: ActorContext, id: string): Promise<FindingEntity> {
    try {
      return await this.findingService.getFinding(actor, id);
    } catch (err: unknown) {
      if (err instanceof SecureFlowError) {
        throw err;
      }
      throw new SecureFlowError('MCP handler failure', 'MCP_HANDLER_ERROR', 500);
    }
  }
}

// Preserve type reference for MCP presentation layer
export type { FindingRecord };
