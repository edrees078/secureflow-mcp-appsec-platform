import { vi } from 'vitest';
import type {
  DomainServices,
  IProjectService,
  IAuditService,
  IFindingService,
  ITaskService,
} from '@secureflow/domain';

export function createMockProjectService(): IProjectService {
  return {
    createProject: vi.fn(),
    updateProject: vi.fn(),
    archiveProject: vi.fn(),
    getProject: vi.fn(),
    listProjects: vi.fn(),
    addMember: vi.fn(),
    removeMember: vi.fn(),
    listMembers: vi.fn(),
  };
}

export function createMockDomainServices(overrides?: Partial<DomainServices>): DomainServices {
  return {
    projectService: createMockProjectService(),
    auditService: {
      logEvent: vi.fn(),
      queryEvents: vi.fn(),
    } as unknown as IAuditService,
    findingService: {} as unknown as IFindingService,
    taskService: {} as unknown as ITaskService,
    close: vi.fn().mockResolvedValue(undefined),
    ...overrides,
  };
}
