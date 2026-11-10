import { describe, it, expect, beforeEach, vi } from 'vitest';
import request from 'supertest';
import { createTestApp } from '../helpers/test-app.js';
import { createMockDomainServices } from '../helpers/mock-services.js';
import { createTestActor } from '../helpers/test-actor.js';
import { createApp } from '../../src/app.js';
import type { DomainServices, RemediationTaskEntity } from '@secureflow/domain';
import {
  EntityNotFoundError,
  ForbiddenError,
} from '@secureflow/shared';

describe('Remediation Task REST API Controller (/api/v1/tasks)', () => {
  let mockServices: DomainServices;

  const devActor = createTestActor({
    id: '00000000-0000-0000-0000-000000000003',
    globalRole: 'DEVELOPER',
    memberships: [{ projectId: '11111111-1111-1111-1111-111111111111', role: 'DEVELOPER' }],
  });

  const sampleTask: RemediationTaskEntity = {
    id: '44444444-4444-4444-4444-444444444444',
    findingId: '33333333-3333-3333-3333-333333333333',
    assignedToId: devActor.id,
    assignedById: '00000000-0000-0000-0000-000000000002',
    description: 'Fix SQL injection vulnerability in search handler',
    notes: 'Initial developer notes',
    status: 'IN_PROGRESS',
    dueDate: new Date('2026-12-31T00:00:00Z'),
    createdAt: new Date('2026-01-01T00:00:00Z'),
    updatedAt: new Date('2026-01-01T00:00:00Z'),
  };

  beforeEach(() => {
    mockServices = createMockDomainServices();
  });

  // ---------------------------------------------------------------------------
  // 1. GET /api/v1/tasks/:id (Get Task Detail)
  // ---------------------------------------------------------------------------
  describe('GET /api/v1/tasks/:id', () => {
    it('returns task detail with HTTP 200', async () => {
      vi.mocked(mockServices.taskService.getTask).mockResolvedValue(sampleTask);
      const app = createTestApp({ services: mockServices, actor: devActor });

      const res = await request(app).get(`/api/v1/tasks/${sampleTask.id}`);

      expect(res.status).toBe(200);
      expect(res.body).toEqual({
        data: {
          ...sampleTask,
          dueDate: sampleTask.dueDate?.toISOString(),
          createdAt: sampleTask.createdAt.toISOString(),
          updatedAt: sampleTask.updatedAt.toISOString(),
        },
      });
      expect(mockServices.taskService.getTask).toHaveBeenCalledWith(devActor, sampleTask.id);
    });

    it('rejects malformed task UUID with HTTP 400 VALIDATION_ERROR', async () => {
      const app = createTestApp({ services: mockServices, actor: devActor });

      const res = await request(app).get('/api/v1/tasks/not-a-valid-uuid');

      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
      expect(mockServices.taskService.getTask).not.toHaveBeenCalled();
    });

    it('maps EntityNotFoundError to HTTP 404 (existence hiding for unauthorized access or soft-deleted parent)', async () => {
      vi.mocked(mockServices.taskService.getTask).mockRejectedValue(
        new EntityNotFoundError('Task not found', 'RESOURCE_NOT_FOUND')
      );
      const app = createTestApp({ services: mockServices, actor: devActor });

      const res = await request(app).get(`/api/v1/tasks/${sampleTask.id}`);

      expect(res.status).toBe(404);
      expect(res.body.error.code).toBe('NOT_FOUND');
    });
  });

  // ---------------------------------------------------------------------------
  // 2. PATCH /api/v1/tasks/:id/notes (Update Task Notes)
  // ---------------------------------------------------------------------------
  describe('PATCH /api/v1/tasks/:id/notes', () => {
    it('updates developer progress notes with HTTP 200', async () => {
      const updatedTask: RemediationTaskEntity = {
        ...sampleTask,
        notes: 'Updated progress notes: unit tests passing in local branch.',
        updatedAt: new Date('2026-01-02T00:00:00Z'),
      };
      vi.mocked(mockServices.taskService.updateTaskNotes).mockResolvedValue(updatedTask);
      const app = createTestApp({ services: mockServices, actor: devActor });

      const res = await request(app)
        .patch(`/api/v1/tasks/${sampleTask.id}/notes`)
        .send({
          notes: 'Updated progress notes: unit tests passing in local branch.',
        });

      expect(res.status).toBe(200);
      expect(res.body.data.notes).toBe('Updated progress notes: unit tests passing in local branch.');
      expect(mockServices.taskService.updateTaskNotes).toHaveBeenCalledWith(
        devActor,
        sampleTask.id,
        {
          notes: 'Updated progress notes: unit tests passing in local branch.',
        }
      );
    });

    it('rejects notes exceeding 5000 characters with HTTP 400 VALIDATION_ERROR', async () => {
      const app = createTestApp({ services: mockServices, actor: devActor });

      const res = await request(app)
        .patch(`/api/v1/tasks/${sampleTask.id}/notes`)
        .send({
          notes: 'a'.repeat(5001),
        });

      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
      expect(mockServices.taskService.updateTaskNotes).not.toHaveBeenCalled();
    });

    it('rejects unexpected body fields with HTTP 400 (strict validation)', async () => {
      const app = createTestApp({ services: mockServices, actor: devActor });

      const res = await request(app)
        .patch(`/api/v1/tasks/${sampleTask.id}/notes`)
        .send({
          notes: 'Valid notes',
          status: 'COMPLETED',
        });

      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
      expect(mockServices.taskService.updateTaskNotes).not.toHaveBeenCalled();
    });

    it('maps domain ForbiddenError to HTTP 403 when unassigned developer updates notes', async () => {
      vi.mocked(mockServices.taskService.updateTaskNotes).mockRejectedValue(
        new ForbiddenError('Only the assigned developer may update task progress notes', 'FORBIDDEN')
      );
      const app = createTestApp({ services: mockServices, actor: devActor });

      const res = await request(app)
        .patch(`/api/v1/tasks/${sampleTask.id}/notes`)
        .send({
          notes: 'Notes from unassigned developer',
        });

      expect(res.status).toBe(403);
      expect(res.body.error.code).toBe('FORBIDDEN');
    });

    it('maps EntityNotFoundError to HTTP 404 when parent finding is soft-deleted', async () => {
      vi.mocked(mockServices.taskService.updateTaskNotes).mockRejectedValue(
        new EntityNotFoundError('Task or parent finding not found', 'RESOURCE_NOT_FOUND')
      );
      const app = createTestApp({ services: mockServices, actor: devActor });

      const res = await request(app)
        .patch(`/api/v1/tasks/${sampleTask.id}/notes`)
        .send({
          notes: 'Notes for deleted finding task',
        });

      expect(res.status).toBe(404);
      expect(res.body.error.code).toBe('NOT_FOUND');
    });
  });

  // ---------------------------------------------------------------------------
  // 3. Security & Production Authentication
  // ---------------------------------------------------------------------------
  describe('Production Authentication & Fail-Closed Boundaries', () => {
    it('production createApp rejects requests with HTTP 401 UNAUTHORIZED', async () => {
      const prodApp = createApp(mockServices);

      const res = await request(prodApp).get(`/api/v1/tasks/${sampleTask.id}`);

      expect(res.status).toBe(401);
      expect(res.body.error.code).toBe('UNAUTHORIZED');
      expect(mockServices.taskService.getTask).not.toHaveBeenCalled();
    });

    it('rejects client-supplied identity headers without test actor injection', async () => {
      const app = createTestApp({
        services: mockServices,
        actor: undefined,
      });

      const res = await request(app)
        .get(`/api/v1/tasks/${sampleTask.id}`)
        .set('X-User-Id', devActor.id)
        .set('Authorization', 'Bearer dummy-token');

      expect(res.status).toBe(401);
      expect(res.body.error.code).toBe('UNAUTHORIZED');
    });
  });
});
