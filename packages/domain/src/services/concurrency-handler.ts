import { SecureFlowError } from '@secureflow/shared';

/**
 * Generates a URL-safe, lowercase slug from a project name.
 * Constraints:
 * - Truncates to max 100 characters (per schema.prisma: projects.slug VarChar(100)).
 * - Replaces non-alphanumeric characters with hyphens.
 * - Collapses consecutive hyphens and trims leading/trailing hyphens.
 * - Defaults to 'project' if the resulting slug would be empty.
 */
export function generateProjectSlug(name: string): string {
  const sanitized = name
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
  return (sanitized || 'project').slice(0, 100);
}

/**
 * Traps raw database driver and PostgreSQL concurrency exceptions,
 * mapping them into standardized domain errors with correct HTTP status codes.
 *
 * Safe failure handling per docs/guides/gate3d-concurrency-handoff.md Section 4:
 * - 40P01: Deadlock detected -> 409 Conflict (TRANSACTION_DEADLOCK)
 * - 40001: Serialization failure -> 409 Conflict (SERIALIZATION_FAILURE)
 * - 55P03 / 57014: Lock acquisition timeout -> 504 Gateway Timeout (TRANSACTION_TIMEOUT)
 * - P2002 / 23505: Unique constraint violation -> 409 Conflict (PROJECT_SLUG_CONFLICT / MEMBER_ALREADY_EXISTS)
 */
export function handleDatabaseConcurrencyError(err: unknown): never {
  if (err instanceof SecureFlowError) {
    throw err;
  }

  const message = err instanceof Error ? err.message : String(err);
  const code = (err as { code?: string })?.code;
  const meta = (err as { meta?: { target?: string[] | string } })?.meta;

  // 1. Deadlock Detection (PostgreSQL 40P01)
  if (
    code === '40P01' ||
    message.includes('40P01') ||
    message.toLowerCase().includes('deadlock detected')
  ) {
    throw new SecureFlowError(
      'Concurrent transaction conflict (deadlock), please retry',
      'TRANSACTION_DEADLOCK',
      409,
      { originalError: message },
    );
  }

  // 2. Serialization Failure (PostgreSQL 40001)
  if (
    code === '40001' ||
    message.includes('40001') ||
    message.toLowerCase().includes('could not serialize access')
  ) {
    throw new SecureFlowError(
      'Transaction serialization conflict, please retry',
      'SERIALIZATION_FAILURE',
      409,
      { originalError: message },
    );
  }

  // 3. Lock Acquisition Timeout (PostgreSQL 55P03 / 57014)
  if (
    code === '55P03' ||
    code === '57014' ||
    message.includes('55P03') ||
    message.toLowerCase().includes('lock timeout') ||
    message.toLowerCase().includes('statement timeout') ||
    message.toLowerCase().includes('lock not available')
  ) {
    throw new SecureFlowError(
      'Lock acquisition timed out',
      'TRANSACTION_TIMEOUT',
      504,
      { originalError: message },
    );
  }

  // 4. Unique Constraint Violations (Prisma P2002 or PG 23505)
  if (
    code === 'P2002' ||
    code === '23505' ||
    message.includes('23505') ||
    message.includes('Unique constraint failed')
  ) {
    const targetStr =
      typeof meta?.target === 'string'
        ? meta.target
        : Array.isArray(meta?.target)
          ? meta.target.join(',')
          : '';

    if (
      targetStr.includes('slug') ||
      message.includes('slug') ||
      message.includes('projects_slug_key')
    ) {
      throw new SecureFlowError(
        'Project with this slug already exists',
        'PROJECT_SLUG_CONFLICT',
        409,
      );
    }

    if (
      targetStr.includes('project_id') ||
      targetStr.includes('user_id') ||
      message.includes('project_members') ||
      message.includes('project_members_project_id_user_id_key')
    ) {
      throw new SecureFlowError(
        'User is already a member of this project',
        'MEMBER_ALREADY_EXISTS',
        409,
      );
    }

    throw new SecureFlowError(
      'Database unique constraint violation',
      'UNIQUE_CONSTRAINT_VIOLATION',
      409,
      { originalError: message },
    );
  }

  // Fallback to internal error
  throw new SecureFlowError(
    err instanceof Error ? err.message : 'Database operation failed',
    'DATABASE_ERROR',
    500,
  );
}
