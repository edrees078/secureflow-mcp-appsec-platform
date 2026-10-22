import { z } from 'zod';
import { UuidSchema } from './common.js';

/**
 * Input DTO for creating a Remediation Task.
 */
export const CreateRemediationTaskInputSchema = z
  .object({
    findingId: UuidSchema,
    assignedToId: UuidSchema,
    description: z.string().trim().min(1, 'Task description is required').max(5000, 'Description cannot exceed 5000 characters'),
    dueDate: z.string().date('Due date must be in YYYY-MM-DD format').nullable().optional(),
  })
  .strict();
export type CreateRemediationTaskInput = z.infer<typeof CreateRemediationTaskInputSchema>;

/**
 * Input DTO for developer updating remediation task progress notes.
 */
export const UpdateTaskNotesInputSchema = z
  .object({
    notes: z.string().trim().max(5000, 'Notes cannot exceed 5000 characters'),
  })
  .strict();
export type UpdateTaskNotesInput = z.infer<typeof UpdateTaskNotesInputSchema>;
