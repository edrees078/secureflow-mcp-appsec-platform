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

/**
 * Query schema for querying audit events with pagination and filters via HTTP GET.
 * Parses and validates HTTP query string parameters:
 * - String numbers for page and limit are converted to bounded positive integers (page >= 1, limit 1..100).
 * - Enforces strict property validation and ISO 8601 datetimes.
 */
export const QueryAuditEventsQuerySchema = z
  .object({
    eventCategory: AuditEventCategorySchema.optional(),
    eventType: z.string().trim().min(1, 'eventType cannot be empty').max(100, 'eventType cannot exceed 100 characters').optional(),
    resourceId: UuidSchema.optional(),
    resourceType: z.string().trim().min(1, 'resourceType cannot be empty').max(100, 'resourceType cannot exceed 100 characters').optional(),
    actorId: UuidSchema.optional(),
    fromTimestamp: z.string().datetime({ message: 'fromTimestamp must be an ISO 8601 datetime' }).optional(),
    toTimestamp: z.string().datetime({ message: 'toTimestamp must be an ISO 8601 datetime' }).optional(),
    page: z
      .preprocess((val) => (val !== undefined && val !== '' ? Number(val) : 1), z.number().int('Page must be an integer').min(1, 'Page must be at least 1'))
      .default(1),
    limit: z
      .preprocess(
        (val) => (val !== undefined && val !== '' ? Number(val) : 25),
        z.number().int('Limit must be an integer').min(1, 'Limit must be at least 1').max(100, 'Limit cannot exceed 100'),
      )
      .default(25),
  })
  .strict();
export type QueryAuditEventsQuery = z.infer<typeof QueryAuditEventsQuerySchema>;
