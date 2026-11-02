import { ActorContext } from '@secureflow/domain';
import type { GlobalRole, ProjectRole } from '@secureflow/schemas';

export function createTestActor(options?: {
  id?: string;
  globalRole?: GlobalRole;
  isActive?: boolean;
  memberships?: Array<{ projectId: string; role: ProjectRole }>;
}): ActorContext {
  return new ActorContext({
    id: options?.id ?? '00000000-0000-0000-0000-000000000001',
    globalRole: options?.globalRole ?? 'ADMIN',
    isActive: options?.isActive ?? true,
    memberships: options?.memberships ?? [],
  });
}
