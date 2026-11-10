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

export function createMockFindingService(): IFindingService {
  return {
    createFinding: vi.fn(),
    getFinding: vi.fn(),
    listFindings: vi.fn(),
    triageFinding: vi.fn(),
    assignFinding: vi.fn(),
    submitRemediation: vi.fn(),
    verifyFinding: vi.fn(),
    confirmVerification: vi.fn(),
    rejectVerification: vi.fn(),
    closeFinding: vi.fn(),
    forceCloseFinding: vi.fn(),
    forceReopenFinding: vi.fn(),
    updateFindingMetadata: vi.fn(),
    softDeleteFinding: vi.fn(),
  };
}

export function createMockTaskService(): ITaskService {
  return {
    getTask: vi.fn(),
    getTaskByFindingId: vi.fn(),
    updateTaskNotes: vi.fn(),
  };
}

export function createMockAuditService(): IAuditService {
  return {
    queryAuditLogs: vi.fn(),
  };
}

export function createMockDomainServices(overrides?: Partial<DomainServices>): DomainServices {
  return {
    projectService: createMockProjectService(),
    auditService: createMockAuditService(),
    findingService: createMockFindingService(),
    taskService: createMockTaskService(),
    close: vi.fn().mockResolvedValue(undefined),
    ...overrides,
  };
}
