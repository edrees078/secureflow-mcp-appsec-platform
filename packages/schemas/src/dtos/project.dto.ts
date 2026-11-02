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

/**
 * Query schema for listing projects with pagination, search, and active status filters.
 * Parses and validates HTTP query string parameters:
 * - String numbers for page and limit are converted to positive integers.
 * - Boolean string representations are strictly parsed ('true' -> true, 'false' -> false).
 * - Enforces bounded limits (max 100) and max 200 characters for search.
 */
export const ListProjectsQuerySchema = z
  .object({
    page: z
      .preprocess((val) => (val !== undefined && val !== '' ? Number(val) : 1), z.number().int('Page must be an integer').min(1, 'Page must be at least 1'))
      .default(1),
    limit: z
      .preprocess(
        (val) => (val !== undefined && val !== '' ? Number(val) : 25),
        z.number().int('Limit must be an integer').min(1, 'Limit must be at least 1').max(100, 'Limit cannot exceed 100'),
      )
      .default(25),
    search: z.string().trim().max(200, 'Search query cannot exceed 200 characters').optional(),
    includeInactive: z
      .preprocess((val) => {
        if (val === undefined || val === '') return undefined;
        if (val === 'true' || val === true) return true;
        if (val === 'false' || val === false) return false;
        return val;
      }, z.boolean({ message: 'includeInactive must be a boolean (true or false)' }).optional()),
  })
  .strict();
export type ListProjectsQuery = z.infer<typeof ListProjectsQuerySchema>;
