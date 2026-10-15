import { isNonEmptyString } from '@secureflow/shared';

/**
 * Finding Severity Enumeration & Types
 */
export type FindingSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type FindingStatus = 'OPEN' | 'IN_TRIAGE' | 'CONFIRMED' | 'REMEDIATED' | 'ACCEPTED_RISK' | 'FALSE_POSITIVE';

export interface FindingRecord {
  id: string;
  projectId: string;
  title: string;
  severity: FindingSeverity;
  status: FindingStatus;
  createdAt: string;
}

export function isValidFindingTitle(title: unknown): title is string {
  return isNonEmptyString(title) && title.length <= 255;
}
