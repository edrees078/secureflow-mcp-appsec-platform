import { z } from 'zod';
import { ProjectRoleSchema } from '../enums.js';
import { UuidSchema } from './common.js';

/**
 * Input DTO for Project Creation.
 * Note: Admin creator is accountability-tracked via createdById in service, NOT added to members.
 */
export const CreateProjectInputSchema = z
  .object({
    name: z.string().trim().min(1, 'Project name is required').max(255, 'Project name cannot exceed 255 characters'),
    description: z.string().trim().max(5000, 'Description cannot exceed 5000 characters').nullable().optional(),
  })
  .strict();
export type CreateProjectInput = z.infer<typeof CreateProjectInputSchema>;

/**
 * Input DTO for Project Metadata Updates.
 */
export const UpdateProjectInputSchema = z
  .object({
    name: z.string().trim().min(1).max(255).optional(),
    description: z.string().trim().max(5000).nullable().optional(),
    isActive: z.boolean().optional(),
  })
  .strict();
export type UpdateProjectInput = z.infer<typeof UpdateProjectInputSchema>;

/**
 * Input DTO for Adding a Project Member.
 * Invariant (OLI-8): Project roles are strictly ANALYST or DEVELOPER.
 */
export const AddProjectMemberInputSchema = z
  .object({
    userId: UuidSchema,
    role: ProjectRoleSchema,
  })
  .strict();
export type AddProjectMemberInput = z.infer<typeof AddProjectMemberInputSchema>;
