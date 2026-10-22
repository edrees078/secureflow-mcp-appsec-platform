import { z } from 'zod';
import { AuditEventCategorySchema } from '../enums.js';
import { UuidSchema } from './common.js';

/**
 * Input DTO for Querying Audit Events (Admin only).
 * Requirements: FR-020, FR-022.
 */
export const QueryAuditEventsInputSchema = z
  .object({
    eventCategory: AuditEventCategorySchema.optional(),
    eventType: z.string().trim().min(1).max(100).optional(),
    resourceId: UuidSchema.optional(),
    resourceType: z.string().trim().min(1).max(100).optional(),
    actorId: UuidSchema.optional(),
    fromTimestamp: z.string().datetime({ message: 'fromTimestamp must be an ISO 8601 datetime' }).optional(),
    toTimestamp: z.string().datetime({ message: 'toTimestamp must be an ISO 8601 datetime' }).optional(),
    page: z.number().int().min(1).default(1),
    limit: z.number().int().min(1).max(100).default(25),
  })
  .strict();
export type QueryAuditEventsInput = z.infer<typeof QueryAuditEventsInputSchema>;
