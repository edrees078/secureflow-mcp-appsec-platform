/**
 * SecureFlow Base Error and Common Utilities
 */

export {
  SecureFlowError,
  EntityNotFoundError,
  ForbiddenError,
  UnauthorizedError,
  DomainValidationError,
  InvalidStateTransitionError,
  ConcurrencyConflictError,
  ConflictError,
} from './errors.js';

export function formatDateIso(date: Date): string {
  return date.toISOString();
}

export function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}
