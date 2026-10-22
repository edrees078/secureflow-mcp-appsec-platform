import { isNonEmptyString } from '@secureflow/shared';
import type { FindingSeverity, FindingStatus } from './enums.js';

// Canonical Enums and Schemas
export * from './enums.js';

// Common Schemas
export * from './dtos/common.js';

// Service Input DTOs
export * from './dtos/project.dto.js';
export * from './dtos/finding.dto.js';
export * from './dtos/task.dto.js';
export * from './dtos/audit.dto.js';

/**
 * Shared Finding View Record.
 * Usable by web frontend and MCP presentation layers without domain dependency.
 */
export interface FindingRecord {
  id: string;
  projectId: string;
  title: string;
  severity: FindingSeverity;
  status: FindingStatus;
  createdAt: string;
}

export function isValidFindingTitle(title: unknown): title is string {
  return isNonEmptyString(title) && title.length <= 500;
}
