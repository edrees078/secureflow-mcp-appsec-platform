import type {
  PrismaDbClient,
  IProjectRepository,
  IFindingRepository,
  ITaskRepository,
  IAuditRepository,
  IUserRepository,
} from './types.js';
import { PrismaProjectRepository } from './project.repository.js';
import { PrismaFindingRepository } from './finding.repository.js';
import { PrismaTaskRepository } from './task.repository.js';
import { PrismaAuditRepository } from './audit.repository.js';
import { PrismaUserRepository } from './user.repository.js';

export * from './types.js';
export { PrismaProjectRepository } from './project.repository.js';
export { PrismaFindingRepository } from './finding.repository.js';
export { PrismaTaskRepository } from './task.repository.js';
export { PrismaAuditRepository } from './audit.repository.js';
export { PrismaUserRepository } from './user.repository.js';

/**
 * Container bundling all domain repositories for a given database client or transaction.
 */
export interface RepositoryContainer {
  projectRepo: IProjectRepository;
  findingRepo: IFindingRepository;
  taskRepo: ITaskRepository;
  auditRepo: IAuditRepository;
  userRepo: IUserRepository;
}

/**
 * Factory function creating all repositories bound to a specific Prisma client or transaction client.
 */
export function createRepositories(client: PrismaDbClient): RepositoryContainer {
  return {
    projectRepo: new PrismaProjectRepository(client),
    findingRepo: new PrismaFindingRepository(client),
    taskRepo: new PrismaTaskRepository(client),
    auditRepo: new PrismaAuditRepository(client),
    userRepo: new PrismaUserRepository(client),
  };
}
