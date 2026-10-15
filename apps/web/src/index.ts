import type { FindingRecord } from '@secureflow/schemas';
import { formatDateIso } from '@secureflow/shared';

export function renderFindingBadge(finding: FindingRecord): string {
  return `[${finding.severity}] ${finding.title} (created: ${formatDateIso(new Date(finding.createdAt))})`;
}
