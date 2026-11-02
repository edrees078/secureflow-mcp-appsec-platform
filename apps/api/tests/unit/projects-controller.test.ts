import { describe, it, expect, beforeEach, vi } from 'vitest';
import request from 'supertest';
import { createTestApp } from '../helpers/test-app.js';
import { createMockDomainServices } from '../helpers/mock-services.js';
import { createTestActor } from '../helpers/test-actor.js';
import type { DomainServices, ProjectEntity, ProjectMemberEntity } from '@secureflow/domain';
import {
  EntityNotFoundError,
  ForbiddenError,
  ConflictError,
} from '@secureflow/shared';

describe('Project Management REST API Controller (/api/v1/projects)', () => {
  let mockServices: DomainServices;
  const adminActor = createTestActor({ globalRole: 'ADMIN' });
  const analystActor = createTestActor({
    id: '00000000-0000-0000-0000-000000000002',
    globalRole: 'ANALYST',
  });

  const sampleProject: ProjectEntity = {
    id: '11111111-1111-1111-1111-111111111111',
    name: 'Apollo Security',
    slug: 'apollo-security',
    description: 'Mission critical AppSec',
    isActive: true,
    createdById: adminActor.id,
    createdAt: new Date('2026-01-01T00:00:00Z'),
    updatedAt: new Date('2026-01-01T00:00:00Z'),
  };

  const sampleMember: ProjectMemberEntity = {
    id: '22222222-2222-2222-2222-222222222222',
    projectId: sampleProject.id,
    userId: analystActor.id,
    role: 'ANALYST',
    createdAt: new Date('2026-01-02T00:00:00Z'),
  };

  beforeEach(() => {
    mockServices = createMockDomainServices();
  });

  describe('POST /api/v1/projects (Create Project)', () => {
    it('creates project and returns HTTP 201 with project data envelope', async () => {
      vi.mocked(mockServices.projectService.createProject).mockResolvedValue(sampleProject);
      const app = createTestApp({ services: mockServices, actor: adminActor });

      const res = await request(app)
        .post('/api/v1/projects')
        .send({
          name: 'Apollo Security',
          description: 'Mission critical AppSec',
        });

      expect(res.status).toBe(201);
      expect(res.body).toEqual({
        data: {
          ...sampleProject,
          createdAt: sampleProject.createdAt.toISOString(),
          updatedAt: sampleProject.updatedAt.toISOString(),
        },
      });
      expect(mockServices.projectService.createProject).toHaveBeenCalledWith(adminActor, {
        name: 'Apollo Security',
        description: 'Mission critical AppSec',
      });
    });

    it('rejects empty name with HTTP 400 VALIDATION_ERROR', async () => {
      const app = createTestApp({ services: mockServices, actor: adminActor });

      const res = await request(app)
        .post('/api/v1/projects')
        .send({ name: '   ' });

      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
      expect(mockServices.projectService.createProject).not.toHaveBeenCalled();
    });

    it('rejects unknown fields in request body with HTTP 400 (strict validation)', async () => {
      const app = createTestApp({ services: mockServices, actor: adminActor });

      const res = await request(app)
        .post('/api/v1/projects')
        .send({ name: 'Valid Project', unexpectedField: 'malicious' });

      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
      expect(mockServices.projectService.createProject).not.toHaveBeenCalled();
    });

    it('maps domain ConflictError to HTTP 409', async () => {
      vi.mocked(mockServices.projectService.createProject).mockRejectedValue(
        new ConflictError('Project slug already exists', 'PROJECT_SLUG_CONFLICT')
      );
      const app = createTestApp({ services: mockServices, actor: adminActor });

      const res = await request(app)
        .post('/api/v1/projects')
        .send({ name: 'Duplicate Project' });

      expect(res.status).toBe(409);
      expect(res.body.error).toEqual({
        code: 'PROJECT_SLUG_CONFLICT',
        message: 'Project slug already exists',
      });
    });
  });

  describe('GET /api/v1/projects (List Projects)', () => {
    it('returns HTTP 200 with data array and pagination metadata', async () => {
      vi.mocked(mockServices.projectService.listProjects).mockResolvedValue({
        items: [sampleProject],
        total: 1,
        page: 1,
        limit: 25,
        totalPages: 1,
      });
      const app = createTestApp({ services: mockServices, actor: adminActor });

      const res = await request(app).get('/api/v1/projects');

      expect(res.status).toBe(200);
      expect(res.body.data).toHaveLength(1);
      expect(res.body.pagination).toEqual({
        total: 1,
        page: 1,
        limit: 25,
        totalPages: 1,
      });
      expect(mockServices.projectService.listProjects).toHaveBeenCalledWith(adminActor, {
        page: 1,
        limit: 25,
      });
    });

    it('parses valid query parameters including boolean strings correctly', async () => {
      vi.mocked(mockServices.projectService.listProjects).mockResolvedValue({
        items: [],
        total: 0,
        page: 2,
        limit: 10,
        totalPages: 0,
      });
      const app = createTestApp({ services: mockServices, actor: adminActor });

      const res = await request(app).get(
        '/api/v1/projects?page=2&limit=10&search=security&includeInactive=true'
      );

      expect(res.status).toBe(200);
      expect(mockServices.projectService.listProjects).toHaveBeenCalledWith(adminActor, {
        page: 2,
        limit: 10,
        search: 'security',
        includeInactive: true,
      });
    });

    it('parses includeInactive=false strictly as boolean false', async () => {
      vi.mocked(mockServices.projectService.listProjects).mockResolvedValue({
        items: [],
        total: 0,
        page: 1,
        limit: 25,
        totalPages: 0,
      });
      const app = createTestApp({ services: mockServices, actor: adminActor });

      const res = await request(app).get('/api/v1/projects?includeInactive=false');

      expect(res.status).toBe(200);
      expect(mockServices.projectService.listProjects).toHaveBeenCalledWith(adminActor, {
        page: 1,
        limit: 25,
        includeInactive: false,
      });
      const calledFilter = vi.mocked(mockServices.projectService.listProjects).mock.calls[0]?.[1];
      expect(calledFilter?.includeInactive).toBe(false);
      expect(typeof calledFilter?.includeInactive).toBe('boolean');
    });

    it('rejects invalid pagination parameters with HTTP 400', async () => {
      const app = createTestApp({ services: mockServices, actor: adminActor });

      const resZeroPage = await request(app).get('/api/v1/projects?page=0');
      expect(resZeroPage.status).toBe(400);

      const resExceedLimit = await request(app).get('/api/v1/projects?limit=101');
      expect(resExceedLimit.status).toBe(400);

      const resBadBool = await request(app).get('/api/v1/projects?includeInactive=not-a-bool');
      expect(resBadBool.status).toBe(400);

      const resUnknownParam = await request(app).get('/api/v1/projects?extra=unexpected');
      expect(resUnknownParam.status).toBe(400);

      expect(mockServices.projectService.listProjects).not.toHaveBeenCalled();
    });
  });

  describe('GET /api/v1/projects/:id (Get Project)', () => {
    it('returns HTTP 200 with project data when found', async () => {
      vi.mocked(mockServices.projectService.getProject).mockResolvedValue(sampleProject);
      const app = createTestApp({ services: mockServices, actor: adminActor });

      const res = await request(app).get(`/api/v1/projects/${sampleProject.id}`);

      expect(res.status).toBe(200);
      expect(res.body.data.id).toBe(sampleProject.id);
      expect(mockServices.projectService.getProject).toHaveBeenCalledWith(
        adminActor,
        sampleProject.id
      );
    });

    it('rejects non-UUID identifier with HTTP 400', async () => {
      const app = createTestApp({ services: mockServices, actor: adminActor });

      const res = await request(app).get('/api/v1/projects/not-a-uuid');

      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
      expect(mockServices.projectService.getProject).not.toHaveBeenCalled();
    });

    it('maps EntityNotFoundError to HTTP 404 for existence hiding', async () => {
      vi.mocked(mockServices.projectService.getProject).mockRejectedValue(
        new EntityNotFoundError('Project not found')
      );
      const app = createTestApp({ services: mockServices, actor: analystActor });

      const res = await request(app).get(`/api/v1/projects/${sampleProject.id}`);

      expect(res.status).toBe(404);
      expect(res.body.error).toEqual({
        code: 'NOT_FOUND',
        message: 'Project not found',
      });
    });
  });

  describe('PATCH /api/v1/projects/:id (Update Project)', () => {
    it('updates project metadata and returns HTTP 200', async () => {
      const updatedProject = { ...sampleProject, name: 'Renamed Project' };
      vi.mocked(mockServices.projectService.updateProject).mockResolvedValue(updatedProject);
      const app = createTestApp({ services: mockServices, actor: adminActor });

      const res = await request(app)
        .patch(`/api/v1/projects/${sampleProject.id}`)
        .send({ name: 'Renamed Project' });

      expect(res.status).toBe(200);
      expect(res.body.data.name).toBe('Renamed Project');
      expect(mockServices.projectService.updateProject).toHaveBeenCalledWith(
        adminActor,
        sampleProject.id,
        { name: 'Renamed Project' }
      );
    });

    it('rejects invalid updates with HTTP 400', async () => {
      const app = createTestApp({ services: mockServices, actor: adminActor });

      const res = await request(app)
        .patch(`/api/v1/projects/${sampleProject.id}`)
        .send({ name: '' });

      expect(res.status).toBe(400);
      expect(mockServices.projectService.updateProject).not.toHaveBeenCalled();
    });

    it('maps domain ForbiddenError to HTTP 403', async () => {
      vi.mocked(mockServices.projectService.updateProject).mockRejectedValue(
        new ForbiddenError('Only administrators can modify project settings')
      );
      const app = createTestApp({ services: mockServices, actor: analystActor });

      const res = await request(app)
        .patch(`/api/v1/projects/${sampleProject.id}`)
        .send({ name: 'Unauthorized Change' });

      expect(res.status).toBe(403);
      expect(res.body.error.code).toBe('FORBIDDEN');
    });
  });

  describe('DELETE /api/v1/projects/:id (Archive Project)', () => {
    it('archives project and returns HTTP 200 with archived entity', async () => {
      const archivedProject = { ...sampleProject, isActive: false };
      vi.mocked(mockServices.projectService.archiveProject).mockResolvedValue(archivedProject);
      const app = createTestApp({ services: mockServices, actor: adminActor });

      const res = await request(app).delete(`/api/v1/projects/${sampleProject.id}`);

      expect(res.status).toBe(200);
      expect(res.body.data.isActive).toBe(false);
      expect(mockServices.projectService.archiveProject).toHaveBeenCalledWith(
        adminActor,
        sampleProject.id
      );
    });
  });

  describe('GET /api/v1/projects/:id/members (List Members)', () => {
    it('returns HTTP 200 with list of project members', async () => {
      vi.mocked(mockServices.projectService.listMembers).mockResolvedValue([sampleMember]);
      const app = createTestApp({ services: mockServices, actor: adminActor });

      const res = await request(app).get(`/api/v1/projects/${sampleProject.id}/members`);

      expect(res.status).toBe(200);
      expect(res.body.data).toHaveLength(1);
      expect(res.body.data[0].id).toBe(sampleMember.id);
      expect(mockServices.projectService.listMembers).toHaveBeenCalledWith(
        adminActor,
        sampleProject.id
      );
    });
  });

  describe('POST /api/v1/projects/:id/members (Add Member)', () => {
    it('adds member and returns HTTP 201 with created member data', async () => {
      vi.mocked(mockServices.projectService.addMember).mockResolvedValue(sampleMember);
      const app = createTestApp({ services: mockServices, actor: adminActor });

      const res = await request(app)
        .post(`/api/v1/projects/${sampleProject.id}/members`)
        .send({
          userId: analystActor.id,
          role: 'ANALYST',
        });

      expect(res.status).toBe(201);
      expect(res.body.data.id).toBe(sampleMember.id);
      expect(mockServices.projectService.addMember).toHaveBeenCalledWith(
        adminActor,
        sampleProject.id,
        {
          userId: analystActor.id,
          role: 'ANALYST',
        }
      );
    });

    it('rejects invalid project role (ADMIN) with HTTP 400 (OLI-8 invariant)', async () => {
      const app = createTestApp({ services: mockServices, actor: adminActor });

      const res = await request(app)
        .post(`/api/v1/projects/${sampleProject.id}/members`)
        .send({
          userId: analystActor.id,
          role: 'ADMIN',
        });

      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
      expect(mockServices.projectService.addMember).not.toHaveBeenCalled();
    });
  });

  describe('DELETE /api/v1/projects/:id/members/:userId (Remove Member)', () => {
    it('removes member and returns HTTP 204 with empty response body', async () => {
      vi.mocked(mockServices.projectService.removeMember).mockResolvedValue(true);
      const app = createTestApp({ services: mockServices, actor: adminActor });

      const res = await request(app).delete(
        `/api/v1/projects/${sampleProject.id}/members/${analystActor.id}`
      );

      expect(res.status).toBe(204);
      expect(res.body).toEqual({});
      expect(res.text).toBe('');
      expect(mockServices.projectService.removeMember).toHaveBeenCalledWith(
        adminActor,
        sampleProject.id,
        analystActor.id
      );
    });

    it('rejects invalid userId format with HTTP 400', async () => {
      const app = createTestApp({ services: mockServices, actor: adminActor });

      const res = await request(app).delete(
        `/api/v1/projects/${sampleProject.id}/members/not-a-valid-user-uuid`
      );

      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
      expect(mockServices.projectService.removeMember).not.toHaveBeenCalled();
    });
  });

  describe('Actor Context Guard & Error Sanitization', () => {
    it('returns HTTP 401 when test app is invoked without actor context', async () => {
      const app = createTestApp({ services: mockServices }); // No actor injected

      const res = await request(app).get(`/api/v1/projects/${sampleProject.id}`);

      expect(res.status).toBe(401);
      expect(res.body.error.code).toBe('UNAUTHORIZED');
      expect(mockServices.projectService.getProject).not.toHaveBeenCalled();
    });

    it('returns HTTP 500 without leaking stack traces or internal messages when service throws unexpected error', async () => {
      vi.mocked(mockServices.projectService.getProject).mockRejectedValue(
        new Error('SELECT * FROM secret_table FAILED with DB_PASSWORD')
      );
      const app = createTestApp({ services: mockServices, actor: adminActor });

      const res = await request(app).get(`/api/v1/projects/${sampleProject.id}`);

      expect(res.status).toBe(500);
      expect(res.body).toEqual({
        error: {
          code: 'INTERNAL_ERROR',
          message: 'An unexpected internal server error occurred',
        },
      });
      expect(JSON.stringify(res.body)).not.toContain('secret_table');
      expect(JSON.stringify(res.body)).not.toContain('DB_PASSWORD');
    });
  });
});
