import { describe, it, expect, beforeEach, vi } from 'vitest';
import request from 'supertest';
import { createTestApp } from '../helpers/test-app.js';
import { createMockDomainServices } from '../helpers/mock-services.js';
import { createTestActor } from '../helpers/test-actor.js';
import { createApp } from '../../src/app.js';
import type { DomainServices, FindingEntity } from '@secureflow/domain';
import {
  EntityNotFoundError,
  ForbiddenError,
  ConcurrencyConflictError,
  InvalidStateTransitionError,
} from '@secureflow/shared';

describe('Finding Lifecycle REST API Controller (/api/v1/findings)', () => {
  let mockServices: DomainServices;

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

  const adminActor = createTestActor({
    id: '00000000-0000-0000-0000-000000000001',
    globalRole: 'ADMIN',
  });

  const sampleFinding: FindingEntity = {
    id: '33333333-3333-3333-3333-333333333333',
    projectId: '11111111-1111-1111-1111-111111111111',
    title: 'SQL Injection in Query Parser',
    description: 'Unsanitized input in /search endpoint permits raw query injection.',
    severity: 'HIGH',
    category: 'INJECTION',
    cvssScore: 8.5,
    status: 'OPEN',
    createdById: analystActor.id,
    assignedToId: null,
    dueDate: new Date('2026-12-31T00:00:00Z'),
    isDeleted: false,
    version: 1,
    createdAt: new Date('2026-01-01T00:00:00Z'),
    updatedAt: new Date('2026-01-01T00:00:00Z'),
  };

  beforeEach(() => {
    mockServices = createMockDomainServices();
  });

  // ---------------------------------------------------------------------------
  // 1. POST /api/v1/findings (Create Finding)
  // ---------------------------------------------------------------------------
  describe('POST /api/v1/findings', () => {
    it('creates finding and returns HTTP 201 with finding data envelope', async () => {
      vi.mocked(mockServices.findingService.createFinding).mockResolvedValue(sampleFinding);
      const app = createTestApp({ services: mockServices, actor: analystActor });

      const res = await request(app)
        .post('/api/v1/findings')
        .send({
          projectId: sampleFinding.projectId,
          title: 'SQL Injection in Query Parser',
          description: 'Unsanitized input in /search endpoint permits raw query injection.',
          severity: 'HIGH',
          category: 'INJECTION',
          cvssScore: 8.5,
          dueDate: '2026-12-31',
        });

      expect(res.status).toBe(201);
      expect(res.body).toEqual({
        data: {
          ...sampleFinding,
          cvssScore: 8.5,
          dueDate: sampleFinding.dueDate?.toISOString(),
          createdAt: sampleFinding.createdAt.toISOString(),
          updatedAt: sampleFinding.updatedAt.toISOString(),
        },
      });
      expect(mockServices.findingService.createFinding).toHaveBeenCalledWith(analystActor, {
        projectId: sampleFinding.projectId,
        title: 'SQL Injection in Query Parser',
        description: 'Unsanitized input in /search endpoint permits raw query injection.',
        severity: 'HIGH',
        category: 'INJECTION',
        cvssScore: 8.5,
        dueDate: '2026-12-31',
      });
    });

    it('rejects invalid UUID in projectId with HTTP 400 VALIDATION_ERROR', async () => {
      const app = createTestApp({ services: mockServices, actor: analystActor });

      const res = await request(app)
        .post('/api/v1/findings')
        .send({
          projectId: 'not-a-valid-uuid',
          title: 'SQL Injection',
          description: 'Valid description',
          severity: 'HIGH',
          category: 'INJECTION',
        });

      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
      expect(mockServices.findingService.createFinding).not.toHaveBeenCalled();
    });

    it('rejects missing title with HTTP 400 VALIDATION_ERROR', async () => {
      const app = createTestApp({ services: mockServices, actor: analystActor });

      const res = await request(app)
        .post('/api/v1/findings')
        .send({
          projectId: sampleFinding.projectId,
          description: 'Valid description',
          severity: 'HIGH',
          category: 'INJECTION',
        });

      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
    });

    it('rejects invalid enum values for severity with HTTP 400 VALIDATION_ERROR', async () => {
      const app = createTestApp({ services: mockServices, actor: analystActor });

      const res = await request(app)
        .post('/api/v1/findings')
        .send({
          projectId: sampleFinding.projectId,
          title: 'Title',
          description: 'Valid description',
          severity: 'CRITICAL_PLUS_EXTRA',
          category: 'INJECTION',
        });

      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
    });

    it('maps domain EntityNotFoundError to HTTP 404 (existence hiding for unauthorized project)', async () => {
      vi.mocked(mockServices.findingService.createFinding).mockRejectedValue(
        new EntityNotFoundError('Project not found or caller lacks authorized membership', 'RESOURCE_NOT_FOUND')
      );
      const app = createTestApp({ services: mockServices, actor: analystActor });

      const res = await request(app)
        .post('/api/v1/findings')
        .send({
          projectId: sampleFinding.projectId,
          title: 'Title',
          description: 'Valid description',
          severity: 'HIGH',
          category: 'INJECTION',
        });

      expect(res.status).toBe(404);
      expect(res.body.error.code).toBe('NOT_FOUND');
    });

    it('maps domain ForbiddenError to HTTP 403 (Developer or Admin creation denial)', async () => {
      vi.mocked(mockServices.findingService.createFinding).mockRejectedValue(
        new ForbiddenError('Developer role cannot create security findings', 'FORBIDDEN')
      );
      const app = createTestApp({ services: mockServices, actor: devActor });

      const res = await request(app)
        .post('/api/v1/findings')
        .send({
          projectId: sampleFinding.projectId,
          title: 'Title',
          description: 'Valid description',
          severity: 'HIGH',
          category: 'INJECTION',
        });

      expect(res.status).toBe(403);
      expect(res.body.error.code).toBe('FORBIDDEN');
    });
  });

  // ---------------------------------------------------------------------------
  // 2. GET /api/v1/findings (List / Filter Findings)
  // ---------------------------------------------------------------------------
  describe('GET /api/v1/findings', () => {
    it('retrieves paginated findings with default pagination and filter mapping', async () => {
      vi.mocked(mockServices.findingService.listFindings).mockResolvedValue({
        items: [sampleFinding],
        total: 1,
        page: 1,
        limit: 25,
        totalPages: 1,
      });
      const app = createTestApp({ services: mockServices, actor: analystActor });

      const res = await request(app)
        .get('/api/v1/findings')
        .query({
          projectId: sampleFinding.projectId,
          status: 'OPEN',
          severity: 'HIGH',
          category: 'INJECTION',
          page: '1',
          limit: '25',
        });

      expect(res.status).toBe(200);
      expect(res.body).toEqual({
        data: [
          {
            ...sampleFinding,
            dueDate: sampleFinding.dueDate?.toISOString(),
            createdAt: sampleFinding.createdAt.toISOString(),
            updatedAt: sampleFinding.updatedAt.toISOString(),
          },
        ],
        pagination: {
          total: 1,
          page: 1,
          limit: 25,
          totalPages: 1,
        },
      });
      expect(mockServices.findingService.listFindings).toHaveBeenCalledWith(analystActor, {
        projectId: sampleFinding.projectId,
        status: 'OPEN',
        severity: 'HIGH',
        category: 'INJECTION',
        page: 1,
        limit: 25,
      });
    });

    it('correctly parses includeDeleted boolean query param', async () => {
      vi.mocked(mockServices.findingService.listFindings).mockResolvedValue({
        items: [],
        total: 0,
        page: 1,
        limit: 25,
        totalPages: 0,
      });
      const app = createTestApp({ services: mockServices, actor: analystActor });

      const res = await request(app)
        .get('/api/v1/findings')
        .query({ includeDeleted: 'true' });

      expect(res.status).toBe(200);
      expect(mockServices.findingService.listFindings).toHaveBeenCalledWith(analystActor, {
        includeDeleted: true,
        page: 1,
        limit: 25,
      });
    });

    it('rejects unsupported query parameters (e.g. slaBreached) with HTTP 400', async () => {
      const app = createTestApp({ services: mockServices, actor: analystActor });

      const res = await request(app)
        .get('/api/v1/findings')
        .query({ slaBreached: 'true' });

      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
    });

    it('rejects limit exceeding 100 with HTTP 400', async () => {
      const app = createTestApp({ services: mockServices, actor: analystActor });

      const res = await request(app)
        .get('/api/v1/findings')
        .query({ limit: '101' });

      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
    });
  });

  // ---------------------------------------------------------------------------
  // 3. GET /api/v1/findings/:id (Get Finding Detail)
  // ---------------------------------------------------------------------------
  describe('GET /api/v1/findings/:id', () => {
    it('returns finding detail with HTTP 200', async () => {
      vi.mocked(mockServices.findingService.getFinding).mockResolvedValue(sampleFinding);
      const app = createTestApp({ services: mockServices, actor: analystActor });

      const res = await request(app).get(`/api/v1/findings/${sampleFinding.id}`);

      expect(res.status).toBe(200);
      expect(res.body.data.id).toBe(sampleFinding.id);
      expect(mockServices.findingService.getFinding).toHaveBeenCalledWith(analystActor, sampleFinding.id);
    });

    it('rejects malformed finding UUID with HTTP 400', async () => {
      const app = createTestApp({ services: mockServices, actor: analystActor });

      const res = await request(app).get('/api/v1/findings/invalid-uuid');

      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
    });

    it('maps EntityNotFoundError to HTTP 404 (existence hiding)', async () => {
      vi.mocked(mockServices.findingService.getFinding).mockRejectedValue(
        new EntityNotFoundError('Finding not found', 'RESOURCE_NOT_FOUND')
      );
      const app = createTestApp({ services: mockServices, actor: analystActor });

      const res = await request(app).get(`/api/v1/findings/${sampleFinding.id}`);

      expect(res.status).toBe(404);
      expect(res.body.error.code).toBe('NOT_FOUND');
    });
  });

  // ---------------------------------------------------------------------------
  // 4. PATCH /api/v1/findings/:id (Update Metadata)
  // ---------------------------------------------------------------------------
  describe('PATCH /api/v1/findings/:id', () => {
    it('updates metadata and returns HTTP 200 with incremented version', async () => {
      const updatedFinding: FindingEntity = {
        ...sampleFinding,
        title: 'Updated Title',
        version: 2,
      };
      vi.mocked(mockServices.findingService.updateFindingMetadata).mockResolvedValue(updatedFinding);
      const app = createTestApp({ services: mockServices, actor: analystActor });

      const res = await request(app)
        .patch(`/api/v1/findings/${sampleFinding.id}`)
        .send({
          expectedVersion: 1,
          title: 'Updated Title',
        });

      expect(res.status).toBe(200);
      expect(res.body.data.version).toBe(2);
      expect(mockServices.findingService.updateFindingMetadata).toHaveBeenCalledWith(
        analystActor,
        sampleFinding.id,
        {
          expectedVersion: 1,
          title: 'Updated Title',
        }
      );
    });

    it('rejects missing expectedVersion with HTTP 400', async () => {
      const app = createTestApp({ services: mockServices, actor: analystActor });

      const res = await request(app)
        .patch(`/api/v1/findings/${sampleFinding.id}`)
        .send({ title: 'Updated Title' });

      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
    });

    it('maps domain ConcurrencyConflictError to HTTP 409', async () => {
      vi.mocked(mockServices.findingService.updateFindingMetadata).mockRejectedValue(
        new ConcurrencyConflictError('Finding was modified by another transaction', 'CONCURRENCY_CONFLICT')
      );
      const app = createTestApp({ services: mockServices, actor: analystActor });

      const res = await request(app)
        .patch(`/api/v1/findings/${sampleFinding.id}`)
        .send({ expectedVersion: 1, title: 'Updated Title' });

      expect(res.status).toBe(409);
      expect(res.body.error.code).toBe('CONCURRENCY_CONFLICT');
    });
  });

  // ---------------------------------------------------------------------------
  // 5. POST /api/v1/findings/:id/triage (Triage Finding)
  // ---------------------------------------------------------------------------
  describe('POST /api/v1/findings/:id/triage', () => {
    it('triages finding to TRIAGED status with HTTP 200', async () => {
      const triagedFinding: FindingEntity = {
        ...sampleFinding,
        status: 'TRIAGED',
        version: 2,
      };
      vi.mocked(mockServices.findingService.triageFinding).mockResolvedValue(triagedFinding);
      const app = createTestApp({ services: mockServices, actor: analystActor });

      const res = await request(app)
        .post(`/api/v1/findings/${sampleFinding.id}/triage`)
        .send({
          expectedVersion: 1,
          severity: 'CRITICAL',
        });

      expect(res.status).toBe(200);
      expect(res.body.data.status).toBe('TRIAGED');
      expect(res.body.data.version).toBe(2);
    });

    it('maps domain InvalidStateTransitionError to HTTP 422', async () => {
      vi.mocked(mockServices.findingService.triageFinding).mockRejectedValue(
        new InvalidStateTransitionError('Cannot triage finding from current state', 'INVALID_STATE_TRANSITION')
      );
      const app = createTestApp({ services: mockServices, actor: analystActor });

      const res = await request(app)
        .post(`/api/v1/findings/${sampleFinding.id}/triage`)
        .send({ expectedVersion: 1 });

      expect(res.status).toBe(422);
      expect(res.body.error.code).toBe('INVALID_STATE_TRANSITION');
    });
  });

  // ---------------------------------------------------------------------------
  // 6. POST /api/v1/findings/:id/assign (Assign Finding)
  // ---------------------------------------------------------------------------
  describe('POST /api/v1/findings/:id/assign', () => {
    it('assigns finding to developer (IN_PROGRESS) with HTTP 200', async () => {
      const assignedFinding: FindingEntity = {
        ...sampleFinding,
        status: 'IN_PROGRESS',
        assignedToId: devActor.id,
        version: 3,
      };
      vi.mocked(mockServices.findingService.assignFinding).mockResolvedValue(assignedFinding);
      const app = createTestApp({ services: mockServices, actor: analystActor });

      const res = await request(app)
        .post(`/api/v1/findings/${sampleFinding.id}/assign`)
        .send({
          expectedVersion: 2,
          assignedToId: devActor.id,
          taskDescription: 'Patch SQL query to use parameterized bindings',
        });

      expect(res.status).toBe(200);
      expect(res.body.data.status).toBe('IN_PROGRESS');
      expect(res.body.data.assignedToId).toBe(devActor.id);
    });

    it('rejects missing taskDescription with HTTP 400', async () => {
      const app = createTestApp({ services: mockServices, actor: analystActor });

      const res = await request(app)
        .post(`/api/v1/findings/${sampleFinding.id}/assign`)
        .send({
          expectedVersion: 2,
          assignedToId: devActor.id,
        });

      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
    });
  });

  // ---------------------------------------------------------------------------
  // 7. POST /api/v1/findings/:id/submit-remediation (Submit Remediation)
  // ---------------------------------------------------------------------------
  describe('POST /api/v1/findings/:id/submit-remediation', () => {
    it('submits remediation by assigned developer (READY_FOR_REVIEW) with HTTP 200', async () => {
      const reviewFinding: FindingEntity = {
        ...sampleFinding,
        status: 'READY_FOR_REVIEW',
        version: 4,
      };
      vi.mocked(mockServices.findingService.submitRemediation).mockResolvedValue(reviewFinding);
      const app = createTestApp({ services: mockServices, actor: devActor });

      const res = await request(app)
        .post(`/api/v1/findings/${sampleFinding.id}/submit-remediation`)
        .send({
          expectedVersion: 3,
          notes: 'Added parameterized query and unit tests in PR #42',
        });

      expect(res.status).toBe(200);
      expect(res.body.data.status).toBe('READY_FOR_REVIEW');
    });

    it('maps domain ForbiddenError to HTTP 403 when unassigned developer attempts submission', async () => {
      vi.mocked(mockServices.findingService.submitRemediation).mockRejectedValue(
        new ForbiddenError('Only the assigned developer may submit remediation', 'FORBIDDEN')
      );
      const app = createTestApp({ services: mockServices, actor: devActor });

      const res = await request(app)
        .post(`/api/v1/findings/${sampleFinding.id}/submit-remediation`)
        .send({ expectedVersion: 3 });

      expect(res.status).toBe(403);
      expect(res.body.error.code).toBe('FORBIDDEN');
    });
  });

  // ---------------------------------------------------------------------------
  // 8. POST /api/v1/findings/:id/verify (Verify / Reject Remediation)
  // ---------------------------------------------------------------------------
  describe('POST /api/v1/findings/:id/verify', () => {
    it('verifies remediation with outcome VERIFIED with HTTP 200', async () => {
      const verifiedFinding: FindingEntity = {
        ...sampleFinding,
        status: 'VERIFIED',
        version: 5,
      };
      vi.mocked(mockServices.findingService.verifyFinding).mockResolvedValue(verifiedFinding);
      const app = createTestApp({ services: mockServices, actor: analystActor });

      const res = await request(app)
        .post(`/api/v1/findings/${sampleFinding.id}/verify`)
        .send({
          expectedVersion: 4,
          outcome: 'VERIFIED',
          notes: 'Tested payload against patched endpoint; verified no injection.',
        });

      expect(res.status).toBe(200);
      expect(res.body.data.status).toBe('VERIFIED');
      expect(mockServices.findingService.verifyFinding).toHaveBeenCalledWith(
        analystActor,
        sampleFinding.id,
        {
          expectedVersion: 4,
          outcome: 'VERIFIED',
          notes: 'Tested payload against patched endpoint; verified no injection.',
        }
      );
    });

    it('rejects remediation with outcome REOPENED with HTTP 200', async () => {
      const reopenedFinding: FindingEntity = {
        ...sampleFinding,
        status: 'REOPENED',
        version: 5,
      };
      vi.mocked(mockServices.findingService.verifyFinding).mockResolvedValue(reopenedFinding);
      const app = createTestApp({ services: mockServices, actor: analystActor });

      const res = await request(app)
        .post(`/api/v1/findings/${sampleFinding.id}/verify`)
        .send({
          expectedVersion: 4,
          outcome: 'REOPENED',
          notes: 'Second-order injection still possible via name field.',
        });

      expect(res.status).toBe(200);
      expect(res.body.data.status).toBe('REOPENED');
    });

    it('rejects invalid outcome value with HTTP 400', async () => {
      const app = createTestApp({ services: mockServices, actor: analystActor });

      const res = await request(app)
        .post(`/api/v1/findings/${sampleFinding.id}/verify`)
        .send({
          expectedVersion: 4,
          outcome: 'ACCEPTED_RISK',
        });

      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
    });

    it('maps separation of duties violation to HTTP 403', async () => {
      vi.mocked(mockServices.findingService.verifyFinding).mockRejectedValue(
        new ForbiddenError('Separation of duties violation: Developer who submitted remediation cannot verify it', 'FORBIDDEN')
      );
      const app = createTestApp({ services: mockServices, actor: analystActor });

      const res = await request(app)
        .post(`/api/v1/findings/${sampleFinding.id}/verify`)
        .send({
          expectedVersion: 4,
          outcome: 'VERIFIED',
        });

      expect(res.status).toBe(403);
      expect(res.body.error.code).toBe('FORBIDDEN');
    });
  });

  // ---------------------------------------------------------------------------
  // 9. POST /api/v1/findings/:id/close (Ordinary Finding Closure)
  // ---------------------------------------------------------------------------
  describe('POST /api/v1/findings/:id/close', () => {
    it('closes verified finding with HTTP 200', async () => {
      const closedFinding: FindingEntity = {
        ...sampleFinding,
        status: 'CLOSED',
        version: 6,
      };
      vi.mocked(mockServices.findingService.closeFinding).mockResolvedValue(closedFinding);
      const app = createTestApp({ services: mockServices, actor: analystActor });

      const res = await request(app)
        .post(`/api/v1/findings/${sampleFinding.id}/close`)
        .send({
          expectedVersion: 5,
          notes: 'Formally closed after QA and security sign-off.',
        });

      expect(res.status).toBe(200);
      expect(res.body.data.status).toBe('CLOSED');
      expect(res.body.data.version).toBe(6);
    });

    it('maps non-verified closure attempt to HTTP 422', async () => {
      vi.mocked(mockServices.findingService.closeFinding).mockRejectedValue(
        new InvalidStateTransitionError('Only VERIFIED findings can be closed through ordinary closure', 'INVALID_STATE_TRANSITION')
      );
      const app = createTestApp({ services: mockServices, actor: analystActor });

      const res = await request(app)
        .post(`/api/v1/findings/${sampleFinding.id}/close`)
        .send({ expectedVersion: 5 });

      expect(res.status).toBe(422);
      expect(res.body.error.code).toBe('INVALID_STATE_TRANSITION');
    });
  });

  // ---------------------------------------------------------------------------
  // 10. DELETE /api/v1/findings/:id (Soft Deletion with Body)
  // ---------------------------------------------------------------------------
  describe('DELETE /api/v1/findings/:id', () => {
    it('soft-deletes finding with expectedVersion in body and returns HTTP 200', async () => {
      const deletedFinding: FindingEntity = {
        ...sampleFinding,
        isDeleted: true,
        version: 2,
      };
      vi.mocked(mockServices.findingService.softDeleteFinding).mockResolvedValue(deletedFinding);
      const app = createTestApp({ services: mockServices, actor: analystActor });

      const res = await request(app)
        .delete(`/api/v1/findings/${sampleFinding.id}`)
        .send({ expectedVersion: 1 });

      expect(res.status).toBe(200);
      expect(res.body.data.isDeleted).toBe(true);
      expect(res.body.data.version).toBe(2);
      expect(mockServices.findingService.softDeleteFinding).toHaveBeenCalledWith(
        analystActor,
        sampleFinding.id,
        { expectedVersion: 1 }
      );
    });

    it('rejects soft-delete without expectedVersion in body with HTTP 400', async () => {
      const app = createTestApp({ services: mockServices, actor: analystActor });

      const res = await request(app).delete(`/api/v1/findings/${sampleFinding.id}`);

      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
    });

    it('maps soft-delete OCC conflict to HTTP 409', async () => {
      vi.mocked(mockServices.findingService.softDeleteFinding).mockRejectedValue(
        new ConcurrencyConflictError('Finding version mismatch', 'CONCURRENCY_CONFLICT')
      );
      const app = createTestApp({ services: mockServices, actor: analystActor });

      const res = await request(app)
        .delete(`/api/v1/findings/${sampleFinding.id}`)
        .send({ expectedVersion: 1 });

      expect(res.status).toBe(409);
      expect(res.body.error.code).toBe('CONCURRENCY_CONFLICT');
    });
  });

  // ---------------------------------------------------------------------------
  // 11. POST /api/v1/findings/:id/force-close
  // ---------------------------------------------------------------------------
  describe('POST /api/v1/findings/:id/force-close', () => {
    it('forces close finding and returns HTTP 200 with closed finding', async () => {
      const closedFinding: FindingEntity = {
        ...sampleFinding,
        status: 'CLOSED',
        version: 2,
      };
      vi.mocked(mockServices.findingService.forceCloseFinding).mockResolvedValue(closedFinding);
      const app = createTestApp({ services: mockServices, actor: adminActor });

      const res = await request(app)
        .post(`/api/v1/findings/${sampleFinding.id}/force-close`)
        .send({
          expectedVersion: 1,
          justification: 'Emergency mitigation applied at cloud edge WAF layer.',
        });

      expect(res.status).toBe(200);
      expect(res.body.data.id).toBe(sampleFinding.id);
      expect(res.body.data.status).toBe('CLOSED');
      expect(res.body.data.version).toBe(2);
      expect(mockServices.findingService.forceCloseFinding).toHaveBeenCalledWith(
        adminActor,
        sampleFinding.id,
        {
          expectedVersion: 1,
          justification: 'Emergency mitigation applied at cloud edge WAF layer.',
        }
      );
    });

    it('rejects force-close without justification with HTTP 400', async () => {
      const app = createTestApp({ services: mockServices, actor: adminActor });

      const res = await request(app)
        .post(`/api/v1/findings/${sampleFinding.id}/force-close`)
        .send({ expectedVersion: 1 });

      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
      expect(mockServices.findingService.forceCloseFinding).not.toHaveBeenCalled();
    });

    it('rejects force-close with empty or whitespace-only justification (spaces, tabs, newlines) with HTTP 400', async () => {
      const app = createTestApp({ services: mockServices, actor: adminActor });

      for (const invalidJustification of ['', '   ', '\t\t', '\n\r\n', ' \t \n \r ']) {
        const res = await request(app)
          .post(`/api/v1/findings/${sampleFinding.id}/force-close`)
          .send({ expectedVersion: 1, justification: invalidJustification });

        expect(res.status).toBe(400);
        expect(res.body.error.code).toBe('VALIDATION_ERROR');
      }
      expect(mockServices.findingService.forceCloseFinding).not.toHaveBeenCalled();
    });

    it('rejects force-close with justification exceeding 5000 characters with HTTP 400', async () => {
      const app = createTestApp({ services: mockServices, actor: adminActor });

      const res = await request(app)
        .post(`/api/v1/findings/${sampleFinding.id}/force-close`)
        .send({ expectedVersion: 1, justification: 'x'.repeat(5001) });

      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
      expect(mockServices.findingService.forceCloseFinding).not.toHaveBeenCalled();
    });

    it('rejects force-close with invalid expectedVersion with HTTP 400', async () => {
      const app = createTestApp({ services: mockServices, actor: adminActor });

      const res = await request(app)
        .post(`/api/v1/findings/${sampleFinding.id}/force-close`)
        .send({ expectedVersion: 0, justification: 'Emergency WAF rule applied.' });

      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
      expect(mockServices.findingService.forceCloseFinding).not.toHaveBeenCalled();
    });

    it('rejects force-close with invalid finding UUID param with HTTP 400', async () => {
      const app = createTestApp({ services: mockServices, actor: adminActor });

      const res = await request(app)
        .post('/api/v1/findings/not-a-valid-uuid/force-close')
        .send({ expectedVersion: 1, justification: 'Emergency WAF rule applied.' });

      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
      expect(mockServices.findingService.forceCloseFinding).not.toHaveBeenCalled();
    });

    it('maps force-close OCC conflict to HTTP 409', async () => {
      vi.mocked(mockServices.findingService.forceCloseFinding).mockRejectedValue(
        new ConcurrencyConflictError('Finding version mismatch', 'CONCURRENCY_CONFLICT')
      );
      const app = createTestApp({ services: mockServices, actor: adminActor });

      const res = await request(app)
        .post(`/api/v1/findings/${sampleFinding.id}/force-close`)
        .send({ expectedVersion: 1, justification: 'Emergency WAF rule applied.' });

      expect(res.status).toBe(409);
      expect(res.body.error.code).toBe('CONCURRENCY_CONFLICT');
    });

    it('maps force-close invalid state transition to HTTP 422', async () => {
      vi.mocked(mockServices.findingService.forceCloseFinding).mockRejectedValue(
        new InvalidStateTransitionError('Finding must be in OPEN state for force-close', 'INVALID_STATE_TRANSITION')
      );
      const app = createTestApp({ services: mockServices, actor: adminActor });

      const res = await request(app)
        .post(`/api/v1/findings/${sampleFinding.id}/force-close`)
        .send({ expectedVersion: 1, justification: 'Emergency WAF rule applied.' });

      expect(res.status).toBe(422);
      expect(res.body.error.code).toBe('INVALID_STATE_TRANSITION');
    });

    it('maps non-admin access denial to HTTP 403', async () => {
      vi.mocked(mockServices.findingService.forceCloseFinding).mockRejectedValue(
        new ForbiddenError('Only Global Admins may force-close findings', 'FORBIDDEN')
      );
      const app = createTestApp({ services: mockServices, actor: analystActor });

      const res = await request(app)
        .post(`/api/v1/findings/${sampleFinding.id}/force-close`)
        .send({ expectedVersion: 1, justification: 'Emergency WAF rule applied.' });

      expect(res.status).toBe(403);
      expect(res.body.error.code).toBe('FORBIDDEN');
    });
  });

  // ---------------------------------------------------------------------------
  // 12. POST /api/v1/findings/:id/force-reopen
  // ---------------------------------------------------------------------------
  describe('POST /api/v1/findings/:id/force-reopen', () => {
    it('forces reopen finding and returns HTTP 200 with reopened finding', async () => {
      const reopenedFinding: FindingEntity = {
        ...sampleFinding,
        status: 'REOPENED',
        version: 3,
      };
      vi.mocked(mockServices.findingService.forceReopenFinding).mockResolvedValue(reopenedFinding);
      const app = createTestApp({ services: mockServices, actor: adminActor });

      const res = await request(app)
        .post(`/api/v1/findings/${sampleFinding.id}/force-reopen`)
        .send({
          expectedVersion: 2,
          justification: 'WAF bypass discovered; vulnerability persists in origin service.',
        });

      expect(res.status).toBe(200);
      expect(res.body.data.id).toBe(sampleFinding.id);
      expect(res.body.data.status).toBe('REOPENED');
      expect(res.body.data.version).toBe(3);
      expect(mockServices.findingService.forceReopenFinding).toHaveBeenCalledWith(
        adminActor,
        sampleFinding.id,
        {
          expectedVersion: 2,
          justification: 'WAF bypass discovered; vulnerability persists in origin service.',
        }
      );
    });

    it('rejects force-reopen without justification with HTTP 400', async () => {
      const app = createTestApp({ services: mockServices, actor: adminActor });

      const res = await request(app)
        .post(`/api/v1/findings/${sampleFinding.id}/force-reopen`)
        .send({ expectedVersion: 2 });

      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
      expect(mockServices.findingService.forceReopenFinding).not.toHaveBeenCalled();
    });

    it('rejects force-reopen with empty or whitespace-only justification (spaces, tabs, newlines) with HTTP 400', async () => {
      const app = createTestApp({ services: mockServices, actor: adminActor });

      for (const invalidJustification of ['', '   ', '\t\t', '\n\r\n', ' \t \n \r ']) {
        const res = await request(app)
          .post(`/api/v1/findings/${sampleFinding.id}/force-reopen`)
          .send({ expectedVersion: 2, justification: invalidJustification });

        expect(res.status).toBe(400);
        expect(res.body.error.code).toBe('VALIDATION_ERROR');
      }
      expect(mockServices.findingService.forceReopenFinding).not.toHaveBeenCalled();
    });

    it('rejects force-reopen with justification exceeding 5000 characters with HTTP 400', async () => {
      const app = createTestApp({ services: mockServices, actor: adminActor });

      const res = await request(app)
        .post(`/api/v1/findings/${sampleFinding.id}/force-reopen`)
        .send({ expectedVersion: 2, justification: 'x'.repeat(5001) });

      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
      expect(mockServices.findingService.forceReopenFinding).not.toHaveBeenCalled();
    });

    it('rejects force-reopen with invalid expectedVersion with HTTP 400', async () => {
      const app = createTestApp({ services: mockServices, actor: adminActor });

      const res = await request(app)
        .post(`/api/v1/findings/${sampleFinding.id}/force-reopen`)
        .send({ expectedVersion: -1, justification: 'Vulnerability re-emerged.' });

      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
      expect(mockServices.findingService.forceReopenFinding).not.toHaveBeenCalled();
    });

    it('rejects force-reopen with invalid finding UUID param with HTTP 400', async () => {
      const app = createTestApp({ services: mockServices, actor: adminActor });

      const res = await request(app)
        .post('/api/v1/findings/invalid-uuid/force-reopen')
        .send({ expectedVersion: 2, justification: 'Vulnerability re-emerged.' });

      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
      expect(mockServices.findingService.forceReopenFinding).not.toHaveBeenCalled();
    });

    it('maps force-reopen OCC conflict to HTTP 409', async () => {
      vi.mocked(mockServices.findingService.forceReopenFinding).mockRejectedValue(
        new ConcurrencyConflictError('Finding version mismatch', 'CONCURRENCY_CONFLICT')
      );
      const app = createTestApp({ services: mockServices, actor: adminActor });

      const res = await request(app)
        .post(`/api/v1/findings/${sampleFinding.id}/force-reopen`)
        .send({ expectedVersion: 2, justification: 'Vulnerability re-emerged.' });

      expect(res.status).toBe(409);
      expect(res.body.error.code).toBe('CONCURRENCY_CONFLICT');
    });

    it('maps force-reopen invalid state transition to HTTP 422', async () => {
      vi.mocked(mockServices.findingService.forceReopenFinding).mockRejectedValue(
        new InvalidStateTransitionError('Finding must be in CLOSED state for force-reopen', 'INVALID_STATE_TRANSITION')
      );
      const app = createTestApp({ services: mockServices, actor: adminActor });

      const res = await request(app)
        .post(`/api/v1/findings/${sampleFinding.id}/force-reopen`)
        .send({ expectedVersion: 2, justification: 'Vulnerability re-emerged.' });

      expect(res.status).toBe(422);
      expect(res.body.error.code).toBe('INVALID_STATE_TRANSITION');
    });

    it('maps non-admin access denial to HTTP 403', async () => {
      vi.mocked(mockServices.findingService.forceReopenFinding).mockRejectedValue(
        new ForbiddenError('Only Global Admins may force-reopen findings', 'FORBIDDEN')
      );
      const app = createTestApp({ services: mockServices, actor: devActor });

      const res = await request(app)
        .post(`/api/v1/findings/${sampleFinding.id}/force-reopen`)
        .send({ expectedVersion: 2, justification: 'Vulnerability re-emerged.' });

      expect(res.status).toBe(403);
      expect(res.body.error.code).toBe('FORBIDDEN');
    });
  });

  // ---------------------------------------------------------------------------
  // 13. Security & Authentication Boundaries
  // ---------------------------------------------------------------------------
  describe('Production Authentication & Actor Injection', () => {
    it('production createApp rejects requests with HTTP 401 UNAUTHORIZED (fail-closed)', async () => {
      const prodApp = createApp(mockServices);

      const res = await request(prodApp)
        .get('/api/v1/findings');

      expect(res.status).toBe(401);
      expect(res.body.error.code).toBe('UNAUTHORIZED');
      expect(mockServices.findingService.listFindings).not.toHaveBeenCalled();
    });

    it('test-only in-memory actor is isolated and not derived from HTTP headers', async () => {
      const app = createTestApp({
        services: mockServices,
        actor: undefined,
      });

      const res = await request(app)
        .get('/api/v1/findings')
        .set('X-User-Id', analystActor.id)
        .set('X-User-Role', 'ADMIN');

      expect(res.status).toBe(401);
      expect(res.body.error.code).toBe('UNAUTHORIZED');
    });
  });
});
