import { z } from 'zod';
import { FindingCategorySchema, FindingSeveritySchema } from '../enums.js';
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
 * Input DTO for Closing a Finding (VERIFIED -> CLOSED, or Admin OPEN -> CLOSED).
 */
export const CloseFindingInputSchema = z
  .object({
    expectedVersion: ExpectedVersionSchema,
    notes: z.string().trim().max(5000, 'Notes cannot exceed 5000 characters').nullable().optional(),
  })
  .strict();
export type CloseFindingInput = z.infer<typeof CloseFindingInputSchema>;

/**
 * Input DTO for Reopening a Finding (CLOSED -> REOPENED).
 */
export const ReopenFindingInputSchema = z
  .object({
    expectedVersion: ExpectedVersionSchema,
    notes: z.string().trim().max(5000, 'Notes cannot exceed 5000 characters').nullable().optional(),
  })
  .strict();
export type ReopenFindingInput = z.infer<typeof ReopenFindingInputSchema>;

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
 * Input DTO for Soft-Deleting a Finding.
 */
export const SoftDeleteFindingInputSchema = z
  .object({
    expectedVersion: ExpectedVersionSchema,
  })
  .strict();
export type SoftDeleteFindingInput = z.infer<typeof SoftDeleteFindingInputSchema>;
