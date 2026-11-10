import { z } from 'zod';
import { FindingCategorySchema, FindingSeveritySchema, FindingStatusSchema } from '../enums.js';
import { ExpectedVersionSchema, UuidSchema } from './common.js';

export { ExpectedVersionSchema };

/**
 * CVSS v3.1 score validator: nullable, range [0.0, 10.0], precision (3,1) with at most 1 decimal place.
 */
export const CvssScoreSchema = z
  .number()
  .min(0.0, 'CVSS score cannot be less than 0.0')
  .max(10.0, 'CVSS score cannot exceed 10.0')
  .refine(
    (val) => Number(val.toFixed(1)) === val,
    'CVSS score must have at most 1 decimal place (precision 3,1)',
  )
  .nullable();

/**
 * Input DTO for Initial Finding Creation.
 * Requirements: FR-001, FR-002 (automatically created in OPEN status with version 1).
 */
export const CreateFindingInputSchema = z
  .object({
    projectId: UuidSchema,
    title: z.string().trim().min(1, 'Finding title is required').max(500, 'Title cannot exceed 500 characters'),
    description: z.string().trim().min(1, 'Description is required').max(10000, 'Description cannot exceed 10,000 characters'),
    severity: FindingSeveritySchema,
    category: FindingCategorySchema,
    cvssScore: CvssScoreSchema.optional(),
    dueDate: z.string().date('Due date must be in YYYY-MM-DD format').nullable().optional(),
  })
  .strict();
export type CreateFindingInput = z.infer<typeof CreateFindingInputSchema>;

/**
 * Input DTO for Finding Triage (OPEN -> TRIAGED).
 */
export const TriageFindingInputSchema = z
  .object({
    expectedVersion: ExpectedVersionSchema,
    severity: FindingSeveritySchema.optional(),
    category: FindingCategorySchema.optional(),
    cvssScore: CvssScoreSchema.optional(),
    dueDate: z.string().date('Due date must be in YYYY-MM-DD format').nullable().optional(),
  })
  .strict();
export type TriageFindingInput = z.infer<typeof TriageFindingInputSchema>;

/**
 * Input DTO for Finding Assignment & Remediation Initiation (TRIAGED/REOPENED -> IN_PROGRESS).
 */
export const AssignFindingInputSchema = z
  .object({
    expectedVersion: ExpectedVersionSchema,
    assignedToId: UuidSchema,
    taskDescription: z.string().trim().min(1, 'Task description is required').max(5000, 'Task description cannot exceed 5000 characters'),
    dueDate: z.string().date('Due date must be in YYYY-MM-DD format').nullable().optional(),
  })
  .strict();
export type AssignFindingInput = z.infer<typeof AssignFindingInputSchema>;

/**
 * Input DTO for Submitting Remediation (IN_PROGRESS -> READY_FOR_REVIEW).
 */
export const SubmitRemediationInputSchema = z
  .object({
    expectedVersion: ExpectedVersionSchema,
    notes: z.string().trim().max(5000, 'Notes cannot exceed 5000 characters').nullable().optional(),
  })
  .strict();
export type SubmitRemediationInput = z.infer<typeof SubmitRemediationInputSchema>;

/**
 * Input DTO for Verifying Remediation (READY_FOR_REVIEW -> VERIFIED or REOPENED).
 */
export const VerifyFindingInputSchema = z
  .object({
    expectedVersion: ExpectedVersionSchema,
    outcome: z.enum(['VERIFIED', 'REOPENED']),
    notes: z.string().trim().max(5000, 'Notes cannot exceed 5000 characters').nullable().optional(),
  })
  .strict();
export type VerifyFindingInput = z.infer<typeof VerifyFindingInputSchema>;

/**
 * Input DTO for Closing a Finding (VERIFIED -> CLOSED by Analyst).
 */
export const CloseFindingInputSchema = z
  .object({
    expectedVersion: ExpectedVersionSchema,
    notes: z.string().trim().max(5000, 'Notes cannot exceed 5000 characters').nullable().optional(),
  })
  .strict();
export type CloseFindingInput = z.infer<typeof CloseFindingInputSchema>;

/**
 * Input DTO for Exceptional Admin Finding Force-Close (OPEN -> CLOSED).
 * Requirements: FR-005, OLI-11 (Admin exceptional action; mandatory justification required).
 */
export const ForceCloseFindingInputSchema = z
  .object({
    expectedVersion: ExpectedVersionSchema,
    justification: z
      .string()
      .trim()
      .min(1, 'Business justification is required for exceptional force-close')
      .max(5000, 'Justification cannot exceed 5000 characters'),
  })
  .strict();
export type ForceCloseFindingInput = z.infer<typeof ForceCloseFindingInputSchema>;

/**
 * Input DTO for Reopening a Finding.
 * Preserved for Gate 3A schema compatibility; operational code uses ForceReopenFindingInputSchema or VerifyFindingInputSchema.
 */
export const ReopenFindingInputSchema = z
  .object({
    expectedVersion: ExpectedVersionSchema,
    notes: z.string().trim().max(5000, 'Notes cannot exceed 5000 characters').nullable().optional(),
  })
  .strict();
export type ReopenFindingInput = z.infer<typeof ReopenFindingInputSchema>;

/**
 * Input DTO for Exceptional Admin Finding Force-Reopen (CLOSED -> REOPENED).
 * Requirements: FR-008, OLI-11 (Admin exceptional action; mandatory justification required).
 */
export const ForceReopenFindingInputSchema = z
  .object({
    expectedVersion: ExpectedVersionSchema,
    justification: z
      .string()
      .trim()
      .min(1, 'Business justification is required for exceptional force-reopen')
      .max(5000, 'Justification cannot exceed 5000 characters'),
  })
  .strict();
export type ForceReopenFindingInput = z.infer<typeof ForceReopenFindingInputSchema>;

/**
 * Input DTO for Updating Finding Metadata (title, description, severity, category, cvss).
 */
export const UpdateFindingMetadataInputSchema = z
  .object({
    expectedVersion: ExpectedVersionSchema,
    title: z.string().trim().min(1).max(500).optional(),
    description: z.string().trim().min(1).max(10000).optional(),
    severity: FindingSeveritySchema.optional(),
    category: FindingCategorySchema.optional(),
    cvssScore: CvssScoreSchema.optional(),
    dueDate: z.string().date('Due date must be in YYYY-MM-DD format').nullable().optional(),
  })
  .strict();
export type UpdateFindingMetadataInput = z.infer<typeof UpdateFindingMetadataInputSchema>;

/**
 * Input DTO for Querying / Listing Findings.
 */
export const ListFindingsFilterInputSchema = z
  .object({
    projectId: UuidSchema.optional(),
    status: FindingStatusSchema.optional(),
    severity: FindingSeveritySchema.optional(),
    category: FindingCategorySchema.optional(),
    assignedToId: UuidSchema.optional(),
    search: z.string().trim().max(200).optional(),
    page: z.number().int().min(1).optional(),
    limit: z.number().int().min(1).max(100).optional(),
    includeDeleted: z.boolean().optional(),
  })
  .strict();
export type ListFindingsFilterInput = z.infer<typeof ListFindingsFilterInputSchema>;

/**
 * Query schema for listing findings with pagination, search, and attribute filters.
 * Parses and validates HTTP query string parameters:
 * - String numbers for page and limit are converted to positive integers.
 * - Boolean string representations are strictly parsed ('true' -> true, 'false' -> false).
 * - Enforces bounded limits (max 100) and max 200 characters for search.
 */
export const ListFindingsQuerySchema = z
  .object({
    projectId: UuidSchema.optional(),
    status: FindingStatusSchema.optional(),
    severity: FindingSeveritySchema.optional(),
    category: FindingCategorySchema.optional(),
    assignedToId: UuidSchema.optional(),
    search: z.string().trim().max(200, 'Search query cannot exceed 200 characters').optional(),
    page: z
      .preprocess((val) => (val !== undefined && val !== '' ? Number(val) : 1), z.number().int('Page must be an integer').min(1, 'Page must be at least 1'))
      .default(1),
    limit: z
      .preprocess(
        (val) => (val !== undefined && val !== '' ? Number(val) : 25),
        z.number().int('Limit must be an integer').min(1, 'Limit must be at least 1').max(100, 'Limit cannot exceed 100'),
      )
      .default(25),
    includeDeleted: z
      .preprocess((val) => {
        if (val === undefined || val === '') return undefined;
        if (val === 'true' || val === true) return true;
        if (val === 'false' || val === false) return false;
        return val;
      }, z.boolean({ message: 'includeDeleted must be a boolean (true or false)' }).optional()),
  })
  .strict();
export type ListFindingsQuery = z.infer<typeof ListFindingsQuerySchema>;

/**
 * Input DTO for Soft-Deleting a Finding.
 */
export const SoftDeleteFindingInputSchema = z
  .object({
    expectedVersion: ExpectedVersionSchema,
  })
  .strict();
export type SoftDeleteFindingInput = z.infer<typeof SoftDeleteFindingInputSchema>;
