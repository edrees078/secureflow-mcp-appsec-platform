import { Router } from 'express';
import type { Router as ExpressRouter, Request, Response, NextFunction } from 'express';
import type { DomainServices, AuditEventEntity } from '@secureflow/domain';
import {
  QueryAuditEventsQuerySchema,
  type QueryAuditEventsQuery,
} from '@secureflow/schemas';
import { UnauthorizedError } from '@secureflow/shared';
import {
  validateRequest,
  getValidatedQuery,
} from '../../middleware/validate.js';

/**
 * Explicit Audit State Disclosure Policy (Sub-Gate 3E.4):
 * Normalizes keys (lowercase alphanumeric) and redacts any credential, secret,
 * session, or connection-string fields if ever present in beforeState / afterState,
 * while preserving all legitimate forensic evidence (status, version, justification,
 * notes, role, actor/resource IDs, etc.) without mutating stored audit records.
 */
const SENSITIVE_AUDIT_STATE_KEYS: ReadonlySet<string> = new Set([
  'password',
  'passwordhash',
  'passphrase',
  'secret',
  'clientsecret',
  'sessionsecret',
  'jwtsecret',
  'token',
  'accesstoken',
  'refreshtoken',
  'idtoken',
  'apikey',
  'privatekey',
  'authorization',
  'cookie',
  'setcookie',
  'databaseurl',
  'connectionstring',
  'credentials',
]);

export const MAX_REDACTION_DEPTH = 10;

const EMBEDDED_CREDENTIAL_PATTERNS: ReadonlyArray<{
  regex: RegExp;
  replacement: string;
}> = [
  {
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----[\s\S]*?(?:-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----|$)/g,
    replacement: '[REDACTED]',
  },
  {
    regex: /\bBearer\s+[A-Za-z0-9._~+/-]+=*/gi,
    replacement: 'Bearer [REDACTED]',
  },
  {
    regex: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
    replacement: '[REDACTED]',
  },
  {
    regex: /\beyJ[A-Za-z0-9_-]{15,}\b/g,
    replacement: '[REDACTED]',
  },
  {
    regex: /postgres(?:ql)?:\/\/[^:\s'"`]+:[^@\s'"`]+@[^\s'"`]+/gi,
    replacement: 'postgresql://[REDACTED]',
  },
  {
    regex: /\b(?:(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|(?:AKIA|ASIA)[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|xox[baprs]-[0-9A-Za-z-]{10,}|sk_live_[0-9A-Za-z]{16,}|sk-(?:proj|ant)-[A-Za-z0-9_-]{16,})\b/g,
    replacement: '[REDACTED]',
  },
];

export function sanitizeStringCredentialPatterns(text: string): string {
  let result = text;
  for (const { regex, replacement } of EMBEDDED_CREDENTIAL_PATTERNS) {
    result = result.replace(regex, replacement);
  }
  return result;
}

export function sanitizeAuditStateValue(value: unknown, depth = 0): unknown {
  if (value === null || value === undefined) {
    return value;
  }
  if (value instanceof Date) {
    return value.toISOString();
  }
  if (depth >= MAX_REDACTION_DEPTH) {
    return '[MAX_DEPTH_EXCEEDED]';
  }
  if (typeof value === 'string') {
    return sanitizeStringCredentialPatterns(value);
  }
  if (typeof value !== 'object') {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item) => sanitizeAuditStateValue(item, depth + 1));
  }

  const sanitized: Record<string, unknown> = {};
  for (const [key, val] of Object.entries(value as Record<string, unknown>)) {
    const normalizedKey = key.toLowerCase().replace(/[^a-z0-9]/g, '');
    if (SENSITIVE_AUDIT_STATE_KEYS.has(normalizedKey)) {
      sanitized[key] = '[REDACTED]';
    } else {
      sanitized[key] = sanitizeAuditStateValue(val, depth + 1);
    }
  }
  return sanitized;
}

/**
 * Projects strictly the 11 approved AuditEventEntity contract fields and applies
 * non-destructive transport-layer redaction to beforeState and afterState.
 */
export function serializeAuditEvent(event: AuditEventEntity): AuditEventEntity {
  return {
    id: event.id,
    actorId: event.actorId,
    eventCategory: event.eventCategory,
    eventType: event.eventType,
    resourceId: event.resourceId,
    resourceType: event.resourceType,
    beforeState: event.beforeState
      ? (sanitizeAuditStateValue(event.beforeState) as Record<string, unknown>)
      : null,
    afterState: event.afterState
      ? (sanitizeAuditStateValue(event.afterState) as Record<string, unknown>)
      : null,
    ipAddress: event.ipAddress,
    userAgent: event.userAgent,
    createdAt: event.createdAt,
  };
}

/**
 * Creates the Express router for Audit Event REST API endpoints (/api/v1/audit-events).
 *
 * Architecture & Security Principles (Sub-Gate 3E.4):
 * 1. Thin Controller Adapter: Directly delegates to AuditService.queryAuditLogs.
 * 2. Actor Context Invariant: Every route handler passes req.actor to domain methods.
 * 3. Global Admin Enforced: Audit inspection is strictly restricted to organization-wide Admin role.
 *    Non-admin callers (Analyst, Developer) receive HTTP 403 Forbidden via domain policy.
 * 4. Read-Only Ledger: Audit inspection is strictly read-only; no modification/deletion routes exist.
 * 5. Bounded Pagination: Enforces bounded page and limit (max 100), ISO 8601 datetimes, and strict filter validation.
 * 6. Disclosure Safety: Strictly projects approved contract fields and redacts sensitive keys in state diffs.
 * 7. Canonical Status Codes:
 *    - GET /audit-events -> 200 OK with paginated audit event items
 */
export function createAuditEventsRouter(services: DomainServices): ExpressRouter {
  const router = Router();
  const { auditService } = services;

  // 1. GET /api/v1/audit-events — Query audit ledger (Global Admin only, read-only)
  router.get(
    '/',
    validateRequest({ query: QueryAuditEventsQuerySchema }),
    async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      try {
        if (!req.actor) {
          throw new UnauthorizedError('Authentication required');
        }
        const query = getValidatedQuery<QueryAuditEventsQuery>(req);
        const result = await auditService.queryAuditLogs(req.actor, query);
        res.status(200).json({
          data: result.items.map(serializeAuditEvent),
          pagination: {
            total: result.total,
            page: result.page,
            limit: result.limit,
            totalPages: result.totalPages,
          },
        });
      } catch (err) {
        next(err);
      }
    }
  );

  return router;
}
