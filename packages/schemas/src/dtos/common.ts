import { z } from 'zod';

/**
 * Standard PostgreSQL UUID validator (36-character hyphenated hexadecimal).
 * Matches PostgreSQL's native UUID representation, accommodating both RFC 4122 v4
 * and deterministic test fixtures.
 */
export const UuidSchema = z
  .string()
  .trim()
  .regex(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i, 'Invalid UUID format');

/**
 * Optimistic Concurrency Control (OCC) version input validator.
 * Enforces positive integer version counter.
 */
export const ExpectedVersionSchema = z
  .number()
  .int('Version must be an integer')
  .min(1, 'Expected version must be at least 1');
