import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import { createApp } from '../../src/app.js';
import { createMockDomainServices } from '../helpers/mock-services.js';
import type { DomainServices } from '@secureflow/domain';

describe('Production Fail-Closed Authentication Boundary (/api/v1)', () => {
  let mockServices: DomainServices;
  let app: ReturnType<typeof createApp>;

  beforeEach(() => {
    mockServices = createMockDomainServices();
    app = createApp(mockServices);
  });

  it('rejects unauthenticated GET /api/v1/projects with HTTP 401', async () => {
    const res = await request(app).get('/api/v1/projects');

    expect(res.status).toBe(401);
    expect(res.body).toEqual({
      error: {
        code: 'UNAUTHORIZED',
        message: 'Authentication required to access this resource',
      },
    });
    expect(mockServices.projectService.listProjects).not.toHaveBeenCalled();
  });

  it('rejects unauthenticated POST /api/v1/projects with HTTP 401', async () => {
    const res = await request(app)
      .post('/api/v1/projects')
      .send({ name: 'Secret Project' });

    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('UNAUTHORIZED');
    expect(mockServices.projectService.createProject).not.toHaveBeenCalled();
  });

  it('rejects unauthenticated GET /api/v1/projects/:id with HTTP 401', async () => {
    const res = await request(app).get('/api/v1/projects/00000000-0000-0000-0000-000000000001');

    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('UNAUTHORIZED');
    expect(mockServices.projectService.getProject).not.toHaveBeenCalled();
  });

  it('rejects unauthenticated PATCH /api/v1/projects/:id with HTTP 401', async () => {
    const res = await request(app)
      .patch('/api/v1/projects/00000000-0000-0000-0000-000000000001')
      .send({ name: 'Updated Name' });

    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('UNAUTHORIZED');
    expect(mockServices.projectService.updateProject).not.toHaveBeenCalled();
  });

  it('rejects unauthenticated DELETE /api/v1/projects/:id with HTTP 401', async () => {
    const res = await request(app).delete('/api/v1/projects/00000000-0000-0000-0000-000000000001');

    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('UNAUTHORIZED');
    expect(mockServices.projectService.archiveProject).not.toHaveBeenCalled();
  });

  it('rejects unauthenticated member management endpoints with HTTP 401', async () => {
    const listMembersRes = await request(app).get(
      '/api/v1/projects/00000000-0000-0000-0000-000000000001/members'
    );
    expect(listMembersRes.status).toBe(401);
    expect(mockServices.projectService.listMembers).not.toHaveBeenCalled();

    const addMemberRes = await request(app)
      .post('/api/v1/projects/00000000-0000-0000-0000-000000000001/members')
      .send({ userId: '00000000-0000-0000-0000-000000000002', role: 'DEVELOPER' });
    expect(addMemberRes.status).toBe(401);
    expect(mockServices.projectService.addMember).not.toHaveBeenCalled();

    const removeMemberRes = await request(app).delete(
      '/api/v1/projects/00000000-0000-0000-0000-000000000001/members/00000000-0000-0000-0000-000000000002'
    );
    expect(removeMemberRes.status).toBe(401);
    expect(mockServices.projectService.removeMember).not.toHaveBeenCalled();
  });

  it('prohibits authentication bypass via client-supplied spoofing headers', async () => {
    const spoofHeaders = [
      { 'x-user-id': '00000000-0000-0000-0000-000000000001' },
      { 'x-actor-role': 'ADMIN' },
      { 'x-actor-id': '00000000-0000-0000-0000-000000000001' },
      { 'x-remote-user': 'admin@demo.local' },
      { Authorization: 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.fake' },
      { Cookie: 'sf_session=fake-session-token' },
      {
        'x-user-id': '00000000-0000-0000-0000-000000000001',
        'x-actor-role': 'ADMIN',
        Authorization: 'Bearer fake',
      },
    ];

    for (const headers of spoofHeaders) {
      let reqBuilder = request(app).get('/api/v1/projects');
      for (const [key, val] of Object.entries(headers)) {
        reqBuilder = reqBuilder.set(key, val);
      }
      const res = await reqBuilder;
      expect(res.status).toBe(401);
      expect(res.body.error.code).toBe('UNAUTHORIZED');
    }

    expect(mockServices.projectService.listProjects).not.toHaveBeenCalled();
  });

  it('keeps public GET /health/ready accessible without authentication or domain calls', async () => {
    const res = await request(app).get('/health/ready');

    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ready');
    expect(mockServices.projectService.listProjects).not.toHaveBeenCalled();
  });

  it('rejects unauthenticated malformed JSON request with HTTP 401 (fails closed before body parsing)', async () => {
    const res = await request(app)
      .post('/api/v1/projects')
      .set('Content-Type', 'application/json')
      .send('{ invalid json: "broken",');

    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('UNAUTHORIZED');
    expect(mockServices.projectService.createProject).not.toHaveBeenCalled();
  });

  it('rejects unauthenticated oversized payload with HTTP 401 (fails closed before body parsing)', async () => {
    const oversizedBody = 'x'.repeat(2 * 1024 * 1024); // 2MB payload (> 1MB limit)
    const res = await request(app)
      .post('/api/v1/projects')
      .set('Content-Type', 'application/json')
      .send(JSON.stringify({ name: oversizedBody }));

    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('UNAUTHORIZED');
    expect(mockServices.projectService.createProject).not.toHaveBeenCalled();
  });

  it('prohibits authentication bypass even if req.actor is pre-attached before requireAuth in production', async () => {
    // Inject an upstream middleware directly into the production app to simulate forged req.actor
    app.use('/api/v1', (req, _res, next) => {
      // @ts-expect-error simulating pre-attached actor
      req.actor = { id: 'forged-actor-id', globalRole: 'ADMIN', isActive: true };
      next();
    });

    const res = await request(app).get('/api/v1/projects');

    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('UNAUTHORIZED');
    expect(mockServices.projectService.listProjects).not.toHaveBeenCalled();
  });

  it('unconditionally rejects unauthenticated requests across all 23 protected operational endpoints', async () => {
    const endpoints: ReadonlyArray<{ readonly method: 'get' | 'post' | 'patch' | 'delete'; readonly path: string }> = [
      { method: 'get', path: '/api/v1/projects' },
      { method: 'post', path: '/api/v1/projects' },
      { method: 'get', path: '/api/v1/projects/00000000-0000-0000-0000-000000000001' },
      { method: 'patch', path: '/api/v1/projects/00000000-0000-0000-0000-000000000001' },
      { method: 'delete', path: '/api/v1/projects/00000000-0000-0000-0000-000000000001' },
      { method: 'get', path: '/api/v1/projects/00000000-0000-0000-0000-000000000001/members' },
      { method: 'post', path: '/api/v1/projects/00000000-0000-0000-0000-000000000001/members' },
      { method: 'delete', path: '/api/v1/projects/00000000-0000-0000-0000-000000000001/members/00000000-0000-0000-0000-000000000002' },
      { method: 'get', path: '/api/v1/findings' },
      { method: 'post', path: '/api/v1/findings' },
      { method: 'get', path: '/api/v1/findings/00000000-0000-0000-0000-000000000001' },
      { method: 'patch', path: '/api/v1/findings/00000000-0000-0000-0000-000000000001' },
      { method: 'delete', path: '/api/v1/findings/00000000-0000-0000-0000-000000000001' },
      { method: 'post', path: '/api/v1/findings/00000000-0000-0000-0000-000000000001/triage' },
      { method: 'post', path: '/api/v1/findings/00000000-0000-0000-0000-000000000001/assign' },
      { method: 'post', path: '/api/v1/findings/00000000-0000-0000-0000-000000000001/submit' },
      { method: 'post', path: '/api/v1/findings/00000000-0000-0000-0000-000000000001/verify' },
      { method: 'post', path: '/api/v1/findings/00000000-0000-0000-0000-000000000001/close' },
      { method: 'post', path: '/api/v1/findings/00000000-0000-0000-0000-000000000001/force-close' },
      { method: 'post', path: '/api/v1/findings/00000000-0000-0000-0000-000000000001/force-reopen' },
      { method: 'get', path: '/api/v1/tasks/00000000-0000-0000-0000-000000000001' },
      { method: 'patch', path: '/api/v1/tasks/00000000-0000-0000-0000-000000000001/notes' },
      { method: 'get', path: '/api/v1/audit-events' },
    ];

    expect(endpoints).toHaveLength(23);

    for (const ep of endpoints) {
      const res = await request(app)[ep.method](ep.path);
      expect(res.status).toBe(401);
      expect(res.body).toEqual({
        error: {
          code: 'UNAUTHORIZED',
          message: 'Authentication required to access this resource',
        },
      });
    }

    expect(mockServices.projectService.listProjects).not.toHaveBeenCalled();
    expect(mockServices.projectService.createProject).not.toHaveBeenCalled();
    expect(mockServices.findingService.listFindings).not.toHaveBeenCalled();
    expect(mockServices.taskService.getTask).not.toHaveBeenCalled();
    expect(mockServices.auditService.queryAuditLogs).not.toHaveBeenCalled();
  });
});
