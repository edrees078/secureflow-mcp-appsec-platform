import { describe, it, expect, beforeEach, vi } from 'vitest';
import request from 'supertest';
import { createTestApp } from '../helpers/test-app.js';
import { createMockDomainServices } from '../helpers/mock-services.js';
import { createTestActor } from '../helpers/test-actor.js';
import { createApp } from '../../src/app.js';
import type { DomainServices, AuditEventEntity } from '@secureflow/domain';
import {
  ForbiddenError,
  SecureFlowError,
} from '@secureflow/shared';

describe('Audit Event REST API Controller (/api/v1/audit-events)', () => {
  let mockServices: DomainServices;

  const adminActor = createTestActor({
    id: '00000000-0000-0000-0000-000000000001',
    globalRole: 'ADMIN',
  });

  const analystActor = createTestActor({
    id: '00000000-0000-0000-0000-000000000002',
    globalRole: 'ANALYST',
    memberships: [{ projectId: '11111111-1111-1111-1111-111111111111', role: 'ANALYST' }],
  });

  const devActor = createTestActor({
    id: '00000000-0000-0000-0000-000000000003',
    globalRole: 'DEVELOPER',
    memberships: [{ projectId: '11111111-1111-1111-1111-111111111111', role: 'DEVELOPER' }],
  });

  const sampleAuditEvent: AuditEventEntity = {
    id: '55555555-5555-5555-5555-555555555555',
    actorId: adminActor.id,
    eventCategory: 'FINDING',
    eventType: 'finding.force_closed',
    resourceId: '33333333-3333-3333-3333-333333333333',
    resourceType: 'finding',
    beforeState: { status: 'OPEN', version: 1 },
    afterState: { status: 'CLOSED', version: 2 },
    ipAddress: '127.0.0.1',
    userAgent: 'Supertest/Agent',
    createdAt: new Date('2026-03-01T12:00:00Z'),
  };

  beforeEach(() => {
    mockServices = createMockDomainServices();
  });

  // ---------------------------------------------------------------------------
  // 1. GET /api/v1/audit-events (Query Audit Ledger)
  // ---------------------------------------------------------------------------
  describe('GET /api/v1/audit-events', () => {
    it('returns paginated audit events with HTTP 200 for Global Admin', async () => {
      vi.mocked(mockServices.auditService.queryAuditLogs).mockResolvedValue({
        items: [sampleAuditEvent],
        total: 1,
        page: 1,
        limit: 25,
        totalPages: 1,
      });

      const app = createTestApp({ services: mockServices, actor: adminActor });

      const res = await request(app).get('/api/v1/audit-events');

      expect(res.status).toBe(200);
      expect(res.body).toEqual({
        data: [
          {
            ...sampleAuditEvent,
            createdAt: sampleAuditEvent.createdAt.toISOString(),
          },
        ],
        pagination: {
          total: 1,
          page: 1,
          limit: 25,
          totalPages: 1,
        },
      });
      expect(mockServices.auditService.queryAuditLogs).toHaveBeenCalledWith(
        adminActor,
        expect.objectContaining({
          page: 1,
          limit: 25,
        })
      );
    });

    it('forwards all validated query filters to auditService.queryAuditLogs', async () => {
      vi.mocked(mockServices.auditService.queryAuditLogs).mockResolvedValue({
        items: [sampleAuditEvent],
        total: 1,
        page: 2,
        limit: 10,
        totalPages: 1,
      });

      const app = createTestApp({ services: mockServices, actor: adminActor });

      const res = await request(app)
        .get('/api/v1/audit-events')
        .query({
          eventCategory: 'FINDING',
          eventType: 'finding.force_closed',
          resourceId: '33333333-3333-3333-3333-333333333333',
          resourceType: 'finding',
          actorId: adminActor.id,
          fromTimestamp: '2026-01-01T00:00:00.000Z',
          toTimestamp: '2026-12-31T23:59:59.999Z',
          page: '2',
          limit: '10',
        });

      expect(res.status).toBe(200);
      expect(mockServices.auditService.queryAuditLogs).toHaveBeenCalledWith(
        adminActor,
        {
          eventCategory: 'FINDING',
          eventType: 'finding.force_closed',
          resourceId: '33333333-3333-3333-3333-333333333333',
          resourceType: 'finding',
          actorId: adminActor.id,
          fromTimestamp: '2026-01-01T00:00:00.000Z',
          toTimestamp: '2026-12-31T23:59:59.999Z',
          page: 2,
          limit: 10,
        }
      );
    });

    it('maps domain ForbiddenError to HTTP 403 when Analyst attempts audit query', async () => {
      vi.mocked(mockServices.auditService.queryAuditLogs).mockRejectedValue(
        new ForbiddenError('Audit event inspection requires organization-wide Admin role', 'FORBIDDEN')
      );

      const app = createTestApp({ services: mockServices, actor: analystActor });

      const res = await request(app).get('/api/v1/audit-events');

      expect(res.status).toBe(403);
      expect(res.body.error.code).toBe('FORBIDDEN');
    });

    it('maps domain ForbiddenError to HTTP 403 when Developer attempts audit query', async () => {
      vi.mocked(mockServices.auditService.queryAuditLogs).mockRejectedValue(
        new ForbiddenError('Audit event inspection requires organization-wide Admin role', 'FORBIDDEN')
      );

      const app = createTestApp({ services: mockServices, actor: devActor });

      const res = await request(app).get('/api/v1/audit-events');

      expect(res.status).toBe(403);
      expect(res.body.error.code).toBe('FORBIDDEN');
    });

    it('rejects unsupported query parameters (e.g. projectId) with HTTP 400', async () => {
      const app = createTestApp({ services: mockServices, actor: adminActor });

      const res = await request(app)
        .get('/api/v1/audit-events')
        .query({ projectId: '11111111-1111-1111-1111-111111111111' });

      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
      expect(mockServices.auditService.queryAuditLogs).not.toHaveBeenCalled();
    });

    it('rejects invalid enum values for eventCategory with HTTP 400', async () => {
      const app = createTestApp({ services: mockServices, actor: adminActor });

      const res = await request(app)
        .get('/api/v1/audit-events')
        .query({ eventCategory: 'NOT_A_CATEGORY' });

      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
      expect(mockServices.auditService.queryAuditLogs).not.toHaveBeenCalled();
    });

    it('rejects non-ISO datetime for fromTimestamp with HTTP 400', async () => {
      const app = createTestApp({ services: mockServices, actor: adminActor });

      const res = await request(app)
        .get('/api/v1/audit-events')
        .query({ fromTimestamp: 'not-a-datetime' });

      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
      expect(mockServices.auditService.queryAuditLogs).not.toHaveBeenCalled();
    });

    it('rejects non-ISO datetime for toTimestamp with HTTP 400', async () => {
      const app = createTestApp({ services: mockServices, actor: adminActor });

      const res = await request(app)
        .get('/api/v1/audit-events')
        .query({ toTimestamp: '2026/01/01' });

      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
      expect(mockServices.auditService.queryAuditLogs).not.toHaveBeenCalled();
    });

    it('rejects limit exceeding 100 with HTTP 400', async () => {
      const app = createTestApp({ services: mockServices, actor: adminActor });

      const res = await request(app)
        .get('/api/v1/audit-events')
        .query({ limit: 101 });

      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
      expect(mockServices.auditService.queryAuditLogs).not.toHaveBeenCalled();
    });

    it('rejects limit less than 1 with HTTP 400', async () => {
      const app = createTestApp({ services: mockServices, actor: adminActor });

      const res = await request(app)
        .get('/api/v1/audit-events')
        .query({ limit: 0 });

      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
      expect(mockServices.auditService.queryAuditLogs).not.toHaveBeenCalled();
    });

    it('rejects page less than 1 with HTTP 400', async () => {
      const app = createTestApp({ services: mockServices, actor: adminActor });

      const res = await request(app)
        .get('/api/v1/audit-events')
        .query({ page: 0 });

      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
      expect(mockServices.auditService.queryAuditLogs).not.toHaveBeenCalled();
    });

    it('rejects non-integer page with HTTP 400', async () => {
      const app = createTestApp({ services: mockServices, actor: adminActor });

      const res = await request(app)
        .get('/api/v1/audit-events')
        .query({ page: '1.5' });

      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
      expect(mockServices.auditService.queryAuditLogs).not.toHaveBeenCalled();
    });

    it('maps domain date range inversion to HTTP 400', async () => {
      vi.mocked(mockServices.auditService.queryAuditLogs).mockRejectedValue(
        new SecureFlowError(
          'Invalid date range: fromTimestamp cannot be after toTimestamp',
          'INVALID_DATE_RANGE',
          400
        )
      );

      const app = createTestApp({ services: mockServices, actor: adminActor });

      const res = await request(app)
        .get('/api/v1/audit-events')
        .query({
          fromTimestamp: '2026-12-31T00:00:00.000Z',
          toTimestamp: '2026-01-01T00:00:00.000Z',
        });

      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('INVALID_DATE_RANGE');
    });

    it('sanitizes unexpected internal errors to HTTP 500 without leaking stack or internal details', async () => {
      vi.mocked(mockServices.auditService.queryAuditLogs).mockRejectedValue(
        new Error('Database password connection timeout at pg_connect()')
      );

      const app = createTestApp({ services: mockServices, actor: adminActor });

      const res = await request(app).get('/api/v1/audit-events');

      expect(res.status).toBe(500);
      expect(res.body.error.code).toBe('INTERNAL_ERROR');
      expect(res.body.error.message).toBe('An unexpected internal server error occurred');
      expect(res.body.error.stack).toBeUndefined();
      expect(JSON.stringify(res.body)).not.toContain('password');
    });

    it('projects strictly the 11 approved AuditEventEntity fields and strips unapproved persistence properties', async () => {
      const pollutedEvent = {
        ...sampleAuditEvent,
        _internalPrismaMeta: 'should_not_be_exposed',
        rawDatabaseRow: { secret: 'internal_db_row' },
      } as unknown as AuditEventEntity;

      vi.mocked(mockServices.auditService.queryAuditLogs).mockResolvedValue({
        items: [pollutedEvent],
        total: 1,
        page: 1,
        limit: 25,
        totalPages: 1,
      });

      const app = createTestApp({ services: mockServices, actor: adminActor });
      const res = await request(app).get('/api/v1/audit-events');

      expect(res.status).toBe(200);
      const item = res.body.data[0];
      expect(Object.keys(item).sort()).toEqual([
        'actorId',
        'afterState',
        'beforeState',
        'createdAt',
        'eventCategory',
        'eventType',
        'id',
        'ipAddress',
        'resourceId',
        'resourceType',
        'userAgent',
      ]);
      expect(item._internalPrismaMeta).toBeUndefined();
      expect(item.rawDatabaseRow).toBeUndefined();
    });

    it('redacts sensitive credential and secret keys in beforeState and afterState without mutating source objects or forensic evidence', async () => {
      const originalAfterState = {
        status: 'CLOSED',
        version: 2,
        justification: 'Emergency WAF rule applied.',
        password: 'super_secret_password',
        accessToken: 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9',
        sessionSecret: 's3ss10n_s3cr3t',
        nested: {
          clientSecret: 'kc_client_secret',
          databaseUrl: 'postgresql://user:pass@localhost:5433/db',
          notes: 'Legitimate forensic note preserved',
        },
      };

      const eventWithSensitiveState: AuditEventEntity = {
        ...sampleAuditEvent,
        beforeState: {
          status: 'OPEN',
          version: 1,
          refreshToken: 'refresh_token_value',
        },
        afterState: originalAfterState,
      };

      vi.mocked(mockServices.auditService.queryAuditLogs).mockResolvedValue({
        items: [eventWithSensitiveState],
        total: 1,
        page: 1,
        limit: 25,
        totalPages: 1,
      });

      const app = createTestApp({ services: mockServices, actor: adminActor });
      const res = await request(app).get('/api/v1/audit-events');

      expect(res.status).toBe(200);
      const item = res.body.data[0];

      // Sensitive keys redacted in HTTP response
      expect(item.beforeState.refreshToken).toBe('[REDACTED]');
      expect(item.afterState.password).toBe('[REDACTED]');
      expect(item.afterState.accessToken).toBe('[REDACTED]');
      expect(item.afterState.sessionSecret).toBe('[REDACTED]');
      expect(item.afterState.nested.clientSecret).toBe('[REDACTED]');
      expect(item.afterState.nested.databaseUrl).toBe('[REDACTED]');

      // Legitimate forensic evidence preserved
      expect(item.beforeState.status).toBe('OPEN');
      expect(item.beforeState.version).toBe(1);
      expect(item.afterState.status).toBe('CLOSED');
      expect(item.afterState.version).toBe(2);
      expect(item.afterState.justification).toBe('Emergency WAF rule applied.');
      expect(item.afterState.nested.notes).toBe('Legitimate forensic note preserved');

      // Original object in memory not mutated
      expect(originalAfterState.password).toBe('super_secret_password');
    });

    it('redacts case variations and nested arrays of sensitive fields in beforeState and afterState without mutating source objects', async () => {
      const originalBeforeState = {
        status: 'OPEN',
        PASSWORD: 'uppercase_password_value',
        Access_Token: 'snake_case_access_token_value',
        'Session-Secret': 'kebab_case_session_secret_value',
        items: [
          {
            CLIENT_SECRET: 'array_nested_client_secret',
            Database_Url: 'postgresql://user:pass@localhost:5433/db_array',
            notes: 'Preserved array forensic item',
          },
        ],
      };

      const originalAfterState = {
        status: 'CLOSED',
        snapshots: [
          {
            accessToken: 'nested_array_access_token_fixture',
            sessionSecret: 'nested_array_session_secret_fixture',
            justification: 'Verified remediation snapshot',
          },
        ],
      };

      const eventWithComplexSensitiveState: AuditEventEntity = {
        ...sampleAuditEvent,
        beforeState: originalBeforeState,
        afterState: originalAfterState,
      };

      vi.mocked(mockServices.auditService.queryAuditLogs).mockResolvedValue({
        items: [eventWithComplexSensitiveState],
        total: 1,
        page: 1,
        limit: 25,
        totalPages: 1,
      });

      const app = createTestApp({ services: mockServices, actor: adminActor });
      const res = await request(app).get('/api/v1/audit-events');

      expect(res.status).toBe(200);
      const item = res.body.data[0];

      // Case variations and nested array entries redacted
      expect(item.beforeState.PASSWORD).toBe('[REDACTED]');
      expect(item.beforeState.Access_Token).toBe('[REDACTED]');
      expect(item.beforeState['Session-Secret']).toBe('[REDACTED]');
      expect(item.beforeState.items[0].CLIENT_SECRET).toBe('[REDACTED]');
      expect(item.beforeState.items[0].Database_Url).toBe('[REDACTED]');
      expect(item.afterState.snapshots[0].accessToken).toBe('[REDACTED]');
      expect(item.afterState.snapshots[0].sessionSecret).toBe('[REDACTED]');

      // Forensic metadata inside objects and arrays preserved
      expect(item.beforeState.status).toBe('OPEN');
      expect(item.beforeState.items[0].notes).toBe('Preserved array forensic item');
      expect(item.afterState.status).toBe('CLOSED');
      expect(item.afterState.snapshots[0].justification).toBe(
        'Verified remediation snapshot',
      );

      // Original source objects and nested arrays in memory not mutated
      expect(originalBeforeState.PASSWORD).toBe('uppercase_password_value');
      expect(originalBeforeState.items[0]?.CLIENT_SECRET).toBe(
        'array_nested_client_secret',
      );
      expect(originalAfterState.snapshots[0]?.accessToken).toBe(
        'nested_array_access_token_fixture',
      );
    });

    it('replaces nested structures at MAX_REDACTION_DEPTH (10) with [MAX_DEPTH_EXCEEDED] and redacts credential-looking content inside nonsensitive field names', async () => {
      // Build an 11-level nested structure where secrets exist at depth >= 10
      let deepTree: Record<string, unknown> = {
        deepSecretField: 'unredacted_deep_value_must_never_leak',
        password: 'deep_password_must_never_leak',
      };
      for (let level = 10; level >= 1; level--) {
        deepTree = { [`level_${level}`]: deepTree };
      }

      const originalBeforeState = {
        status: 'IN_PROGRESS',
        notes:
          'Diagnostic trace connected to postgresql://user:pass@localhost:5433/db with header Bearer synthetic_bearer_credential_abc',
        deepContext: deepTree,
      };

      const originalAfterState = {
        status: 'VERIFIED',
        justification: 'Normal forensic justification text preserved intact.',
      };

      const eventWithDeepAndEmbeddedData: AuditEventEntity = {
        ...sampleAuditEvent,
        beforeState: originalBeforeState,
        afterState: originalAfterState,
      };

      vi.mocked(mockServices.auditService.queryAuditLogs).mockResolvedValue({
        items: [eventWithDeepAndEmbeddedData],
        total: 1,
        page: 1,
        limit: 25,
        totalPages: 1,
      });

      const app = createTestApp({ services: mockServices, actor: adminActor });
      const res = await request(app).get('/api/v1/audit-events');

      expect(res.status).toBe(200);
      const item = res.body.data[0];
      const serializedJson = JSON.stringify(item);

      // 1. Structures at MAX_REDACTION_DEPTH = 10 are replaced with [MAX_DEPTH_EXCEEDED]
      expect(serializedJson).toContain('[MAX_DEPTH_EXCEEDED]');
      expect(serializedJson).not.toContain('unredacted_deep_value_must_never_leak');
      expect(serializedJson).not.toContain('deep_password_must_never_leak');

      // 2. Credential-looking content inside nonsensitive 'notes' field is redacted
      expect(item.beforeState.notes).toContain('postgresql://[REDACTED]');
      expect(item.beforeState.notes).toContain('Bearer [REDACTED]');
      expect(serializedJson).not.toContain('synthetic_bearer_credential_abc');
      expect(serializedJson).not.toContain('postgresql://user:pass@localhost:5433/db');

      // 3. Legitimate forensic evidence is preserved
      expect(item.beforeState.status).toBe('IN_PROGRESS');
      expect(item.afterState.status).toBe('VERIFIED');
      expect(item.afterState.justification).toBe(
        'Normal forensic justification text preserved intact.',
      );

      // 4. Original objects in memory are not mutated
      expect(originalBeforeState.notes).toContain('synthetic_bearer_credential_abc');
    });
  });

  // ---------------------------------------------------------------------------
  // 2. Production Authentication & Boundary Enforcement
  // ---------------------------------------------------------------------------
  describe('Production Authentication & Boundary Enforcement', () => {
    it('production createApp rejects requests with HTTP 401 UNAUTHORIZED (fail-closed)', async () => {
      const prodApp = createApp(mockServices);

      const res = await request(prodApp).get('/api/v1/audit-events');

      expect(res.status).toBe(401);
      expect(res.body.error.code).toBe('UNAUTHORIZED');
      expect(mockServices.auditService.queryAuditLogs).not.toHaveBeenCalled();
    });

    it('test-only in-memory actor is isolated and not derived from HTTP headers', async () => {
      const app = createTestApp({
        services: mockServices,
        actor: undefined,
      });

      const res = await request(app)
        .get('/api/v1/audit-events')
        .set('X-User-Id', adminActor.id)
        .set('X-User-Role', 'ADMIN');

      expect(res.status).toBe(401);
      expect(res.body.error.code).toBe('UNAUTHORIZED');
      expect(mockServices.auditService.queryAuditLogs).not.toHaveBeenCalled();
    });
  });
});
