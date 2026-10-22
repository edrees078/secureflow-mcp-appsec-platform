/**
 * SecureFlow Domain & Application Error Hierarchy.
 *
 * Provides strongly typed, machine-readable error codes mapped to standard HTTP status codes.
 * Usable across all monorepo tiers (domain, api, mcp-server).
 */

export class SecureFlowError extends Error {
  public readonly code: string;
  public readonly statusCode: number;
  public readonly details: unknown | undefined;

  constructor(message: string, code = 'INTERNAL_ERROR', statusCode = 500, details?: unknown) {
    super(message);
    this.name = new.target.name;
    this.code = code;
    this.statusCode = statusCode;
    this.details = details;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Thrown when a requested resource does not exist or when an unauthorized read
 * must hide the existence of a resource for IDOR defense (HTTP 404).
 */
export class EntityNotFoundError extends SecureFlowError {
  constructor(message = 'Resource not found', details?: unknown) {
    super(message, 'ENTITY_NOT_FOUND', 404, details);
  }
}

/**
 * Thrown when an authenticated caller lacks authorization to perform an action (HTTP 403).
 */
export class ForbiddenError extends SecureFlowError {
  constructor(message = 'Access forbidden', details?: unknown) {
    super(message, 'FORBIDDEN', 403, details);
  }
}

/**
 * Thrown when authentication is missing, invalid, or the user account is deactivated (HTTP 401).
 */
export class UnauthorizedError extends SecureFlowError {
  constructor(message = 'Authentication required', details?: unknown) {
    super(message, 'UNAUTHORIZED', 401, details);
  }
}

/**
 * Thrown when request input violates schema constraints or business validation rules (HTTP 400).
 */
export class DomainValidationError extends SecureFlowError {
  constructor(message = 'Validation failed', details?: unknown) {
    super(message, 'VALIDATION_ERROR', 400, details);
  }
}

/**
 * Thrown when an entity status transition violates the state machine rules (HTTP 422).
 */
export class InvalidStateTransitionError extends SecureFlowError {
  public readonly fromStatus: string | undefined;
  public readonly toStatus: string | undefined;

  constructor(message: string, fromStatus?: string, toStatus?: string, details?: unknown) {
    super(message, 'INVALID_STATE_TRANSITION', 422, details);
    this.fromStatus = fromStatus;
    this.toStatus = toStatus;
  }
}

/**
 * Thrown when an optimistic concurrency control (OCC) version mismatch is detected (HTTP 409).
 */
export class ConcurrencyConflictError extends SecureFlowError {
  public readonly currentVersion: number | undefined;
  public readonly expectedVersion: number | undefined;

  constructor(message = 'Concurrent modification conflict', currentVersion?: number, expectedVersion?: number, details?: unknown) {
    super(message, 'CONCURRENCY_CONFLICT', 409, details);
    this.currentVersion = currentVersion;
    this.expectedVersion = expectedVersion;
  }
}
