import { describe, it, expect, beforeEach, vi } from 'vitest';
import request from 'supertest';
import { createApp } from '../../src/app.js';
import type { AuthRuntimeConfig } from '../../src/config/auth.js';
import type { IOidcClient } from '../../src/auth/oidc-client.js';
import { createMockDomainServices } from '../helpers/mock-services.js';
import { createTestActor } from '../helpers/test-actor.js';
import type {
  AuditEventEntity,
  DomainServices,
  FindingEntity,
  IAuthService,
  ProjectEntity,
  ProjectMemberEntity,
  RemediationTaskEntity,
} from '@secureflow/domain';

describe('Phase 3 Operational REST Route Inventory (Exact 23 Routes + BFF Integration)', () => {
  const PROJECT_ID = '11111111-1111-1111-1111-111111111111';
  const MEMBER_ID = '22222222-2222-2222-2222-222222222222';
  const USER_ID = '00000000-0000-0000-0000-000000000002';
  const FINDING_ID = '33333333-3333-3333-3333-333333333333';
  const TASK_ID = '44444444-4444-4444-4444-444444444444';
  const SESSION_TOKEN = 'route_inventory_session_token_fixture_123456';
  const CSRF_TOKEN = 'route_inventory_csrf_token_fixture_123456';
  const ALLOWED_ORIGIN = 'http://localhost:5173';

  const authConfig: AuthRuntimeConfig = {
    mode: 'development',
    authEnabled: true,
    oidc: {
      issuerUrl: 'http://127.0.0.1:8080/realms/secureflow',
      clientId: 'secureflow-bff',
      clientSecret: 'test_client_secret_value_for_route_inventory',
      clientAuthMethod: 'client_secret_basic',
      redirectUri: 'http://127.0.0.1:3000/api/v1/auth/callback',
      allowedRedirectUris: ['http://127.0.0.1:3000/api/v1/auth/callback'],
      postLogoutRedirectUri: `${ALLOWED_ORIGIN}/login`,
      allowedPostLogoutRedirectUris: [`${ALLOWED_ORIGIN}/login`],
      scopes: 'openid profile email',
      clockToleranceSeconds: 30,
      allowInsecureHttp: true,
      requestTimeoutSeconds: 5,
    },
    session: {
      idleTimeoutSeconds: 1800,
      absoluteTimeoutSeconds: 28800,
      oidcTxnTtlSeconds: 300,
    },
    cookies: {
      mode: 'development',
      sessionCookieName: 'sf_session',
      oidcTxnCookieName: 'sf_oidc_txn',
      secure: false,
      httpOnly: true,
      sameSite: 'lax',
      sessionPath: '/',
      oidcTxnPath: '/api/v1/auth',
      maxAgeSeconds: 28800,
      oidcTxnMaxAgeSeconds: 300,
    },
    allowedOrigins: [ALLOWED_ORIGIN],
  };

  const sampleProject: ProjectEntity = {
    id: PROJECT_ID,
    name: 'Route Inventory Project',
    slug: 'route-inventory-project',
    description: 'Verification project',
    isActive: true,
    createdById: USER_ID,
    createdAt: new Date('2026-01-01T00:00:00Z'),
    updatedAt: new Date('2026-01-01T00:00:00Z'),
  };

  const sampleMember: ProjectMemberEntity = {
    id: MEMBER_ID,
    projectId: PROJECT_ID,
    userId: USER_ID,
    role: 'ANALYST',
    createdAt: new Date('2026-01-01T00:00:00Z'),
  };

  const sampleFinding: FindingEntity = {
    id: FINDING_ID,
    projectId: PROJECT_ID,
    title: 'Sample Finding',
    description: 'Detailed finding description for route inventory',
    severity: 'HIGH',
    category: 'INJECTION',
    cvssScore: 7.5,
    status: 'OPEN',
    createdById: USER_ID,
    assignedToId: null,
    dueDate: new Date('2026-12-31T00:00:00Z'),
    isDeleted: false,
    version: 1,
    createdAt: new Date('2026-01-01T00:00:00Z'),
    updatedAt: new Date('2026-01-01T00:00:00Z'),
  };

  const sampleTask: RemediationTaskEntity = {
    id: TASK_ID,
    findingId: FINDING_ID,
    assignedToId: USER_ID,
    assignedById: USER_ID,
    description: 'Fix route validation issue',
    notes: 'Updated notes',
    status: 'IN_PROGRESS',
    dueDate: new Date('2026-12-31T00:00:00Z'),
    createdAt: new Date('2026-01-01T00:00:00Z'),
    updatedAt: new Date('2026-01-01T00:00:00Z'),
  };

  const sampleAudit: AuditEventEntity = {
    id: '55555555-5555-5555-5555-555555555555',
    actorId: USER_ID,
    eventCategory: 'FINDING',
    eventType: 'finding.created',
    resourceId: FINDING_ID,
    resourceType: 'finding',
    beforeState: null,
    afterState: { status: 'OPEN' },
    ipAddress: '127.0.0.1',
    userAgent: 'Vitest',
    createdAt: new Date('2026-01-01T00:00:00Z'),
  };

  let mockServices: DomainServices;
  let mockOidcClient: IOidcClient;

  beforeEach(() => {
    const fixedNow = new Date('2026-05-01T00:00:00Z');
    const actor = createTestActor({ id: USER_ID, globalRole: 'ADMIN' });

    const mockAuthService: IAuthService = {
      createOidcTransaction: vi.fn(),
      consumeOidcTransaction: vi.fn(),
      establishAuthenticatedSession: vi.fn(),
      resolveSessionActor: vi.fn().mockResolvedValue({
        actor,
        session: {
          id: '66666666-6666-6666-6666-666666666666',
          userId: USER_ID,
          sessionTokenHash: 'a'.repeat(64),
          csrfToken: CSRF_TOKEN,
          oidcSid: 'sid-1',
          ipAddress: '127.0.0.1',
          userAgent: 'Vitest',
          createdAt: fixedNow,
          lastActiveAt: fixedNow,
          idleExpiresAt: new Date(fixedNow.getTime() + 1_800_000),
          expiresAt: new Date(fixedNow.getTime() + 28_800_000),
          revokedAt: null,
          revocationReason: null,
        },
      }),
      revokeSession: vi.fn().mockResolvedValue(true),
      revokeAllUserSessions: vi.fn().mockResolvedValue(1),
      revokeSessionsByOidcSid: vi.fn().mockResolvedValue(1),
      bootstrapInitialAdmin: vi.fn(),
      updateUserGlobalRole: vi.fn(),
      deactivateUser: vi.fn(),
      recordAuthenticationFailure: vi.fn(),
    };

    const paginated = <T,>(items: T[]) => ({
      items,
      total: items.length,
      page: 1,
      limit: 25,
      totalPages: 1,
    });

    mockServices = createMockDomainServices({ authService: mockAuthService });
    vi.mocked(mockServices.projectService.createProject).mockResolvedValue(sampleProject);
    vi.mocked(mockServices.projectService.listProjects).mockResolvedValue(paginated([sampleProject]));
    vi.mocked(mockServices.projectService.getProject).mockResolvedValue(sampleProject);
    vi.mocked(mockServices.projectService.updateProject).mockResolvedValue(sampleProject);
    vi.mocked(mockServices.projectService.archiveProject).mockResolvedValue(sampleProject);
    vi.mocked(mockServices.projectService.listMembers).mockResolvedValue([sampleMember]);
    vi.mocked(mockServices.projectService.addMember).mockResolvedValue(sampleMember);
    vi.mocked(mockServices.projectService.removeMember).mockResolvedValue(undefined);

    vi.mocked(mockServices.findingService.createFinding).mockResolvedValue(sampleFinding);
    vi.mocked(mockServices.findingService.listFindings).mockResolvedValue(paginated([sampleFinding]));
    vi.mocked(mockServices.findingService.getFinding).mockResolvedValue(sampleFinding);
    vi.mocked(mockServices.findingService.updateFindingMetadata).mockResolvedValue(sampleFinding);
    vi.mocked(mockServices.findingService.triageFinding).mockResolvedValue(sampleFinding);
    vi.mocked(mockServices.findingService.assignFinding).mockResolvedValue(sampleFinding);
    vi.mocked(mockServices.findingService.submitRemediation).mockResolvedValue(sampleFinding);
    vi.mocked(mockServices.findingService.verifyFinding).mockResolvedValue(sampleFinding);
    vi.mocked(mockServices.findingService.closeFinding).mockResolvedValue(sampleFinding);
    vi.mocked(mockServices.findingService.softDeleteFinding).mockResolvedValue(sampleFinding);
    vi.mocked(mockServices.findingService.forceCloseFinding).mockResolvedValue(sampleFinding);
    vi.mocked(mockServices.findingService.forceReopenFinding).mockResolvedValue(sampleFinding);

    vi.mocked(mockServices.taskService.getTask).mockResolvedValue(sampleTask);
    vi.mocked(mockServices.taskService.updateTaskNotes).mockResolvedValue(sampleTask);

    vi.mocked(mockServices.auditService.queryAuditLogs).mockResolvedValue(paginated([sampleAudit]));

    mockOidcClient = {
      discover: vi.fn(),
      buildAuthorizationUrl: vi.fn(),
      buildEndSessionUrl: vi.fn().mockResolvedValue(null),
      exchangeAuthorizationCode: vi.fn(),
      clearCache: vi.fn(),
    };
  });

  it('dispatches every one of the 23 operational REST routes into its controller and domain service under authenticated BFF session', async () => {
    const app = createApp(mockServices, { authConfig, oidcClient: mockOidcClient });

    const routeSpecs: Array<{
      method: 'get' | 'post' | 'patch' | 'delete';
      path: string;
      body?: Record<string, unknown>;
      expectedStatus: number;
      assertCalled: () => void;
    }> = [
      // Projects (8 routes)
      {
        method: 'post',
        path: '/api/v1/projects',
        body: { name: 'New Project', description: 'Created via route inventory' },
        expectedStatus: 201,
        assertCalled: () => expect(mockServices.projectService.createProject).toHaveBeenCalledTimes(1),
      },
      {
        method: 'get',
        path: '/api/v1/projects',
        expectedStatus: 200,
        assertCalled: () => expect(mockServices.projectService.listProjects).toHaveBeenCalledTimes(1),
      },
      {
        method: 'get',
        path: `/api/v1/projects/${PROJECT_ID}`,
        expectedStatus: 200,
        assertCalled: () => expect(mockServices.projectService.getProject).toHaveBeenCalledTimes(1),
      },
      {
        method: 'patch',
        path: `/api/v1/projects/${PROJECT_ID}`,
        body: { name: 'Updated Project Name' },
        expectedStatus: 200,
        assertCalled: () => expect(mockServices.projectService.updateProject).toHaveBeenCalledTimes(1),
      },
      {
        method: 'delete',
        path: `/api/v1/projects/${PROJECT_ID}`,
        expectedStatus: 200,
        assertCalled: () => expect(mockServices.projectService.archiveProject).toHaveBeenCalledTimes(1),
      },
      {
        method: 'get',
        path: `/api/v1/projects/${PROJECT_ID}/members`,
        expectedStatus: 200,
        assertCalled: () => expect(mockServices.projectService.listMembers).toHaveBeenCalledTimes(1),
      },
      {
        method: 'post',
        path: `/api/v1/projects/${PROJECT_ID}/members`,
        body: { userId: USER_ID, role: 'ANALYST' },
        expectedStatus: 201,
        assertCalled: () => expect(mockServices.projectService.addMember).toHaveBeenCalledTimes(1),
      },
      {
        method: 'delete',
        path: `/api/v1/projects/${PROJECT_ID}/members/${USER_ID}`,
        expectedStatus: 204,
        assertCalled: () => expect(mockServices.projectService.removeMember).toHaveBeenCalledTimes(1),
      },

      // Findings (12 routes)
      {
        method: 'post',
        path: '/api/v1/findings',
        body: {
          projectId: PROJECT_ID,
          title: 'XSS Vulnerability',
          description: 'Reflected XSS in query parameter',
          severity: 'HIGH',
          category: 'XSS',
        },
        expectedStatus: 201,
        assertCalled: () => expect(mockServices.findingService.createFinding).toHaveBeenCalledTimes(1),
      },
      {
        method: 'get',
        path: '/api/v1/findings',
        expectedStatus: 200,
        assertCalled: () => expect(mockServices.findingService.listFindings).toHaveBeenCalledTimes(1),
      },
      {
        method: 'get',
        path: `/api/v1/findings/${FINDING_ID}`,
        expectedStatus: 200,
        assertCalled: () => expect(mockServices.findingService.getFinding).toHaveBeenCalledTimes(1),
      },
      {
        method: 'patch',
        path: `/api/v1/findings/${FINDING_ID}`,
        body: { expectedVersion: 1, title: 'Updated Finding Title' },
        expectedStatus: 200,
        assertCalled: () =>
          expect(mockServices.findingService.updateFindingMetadata).toHaveBeenCalledTimes(1),
      },
      {
        method: 'post',
        path: `/api/v1/findings/${FINDING_ID}/triage`,
        body: { expectedVersion: 1, severity: 'CRITICAL' },
        expectedStatus: 200,
        assertCalled: () => expect(mockServices.findingService.triageFinding).toHaveBeenCalledTimes(1),
      },
      {
        method: 'post',
        path: `/api/v1/findings/${FINDING_ID}/assign`,
        body: {
          expectedVersion: 1,
          assignedToId: USER_ID,
          taskDescription: 'Sanitize HTML output cleanly',
        },
        expectedStatus: 200,
        assertCalled: () => expect(mockServices.findingService.assignFinding).toHaveBeenCalledTimes(1),
      },
      {
        method: 'post',
        path: `/api/v1/findings/${FINDING_ID}/submit-remediation`,
        body: { expectedVersion: 1, notes: 'Fixed with output encoding' },
        expectedStatus: 200,
        assertCalled: () => expect(mockServices.findingService.submitRemediation).toHaveBeenCalledTimes(1),
      },
      {
        method: 'post',
        path: `/api/v1/findings/${FINDING_ID}/verify`,
        body: { expectedVersion: 1, outcome: 'VERIFIED', notes: 'Confirmed fixed' },
        expectedStatus: 200,
        assertCalled: () => expect(mockServices.findingService.verifyFinding).toHaveBeenCalledTimes(1),
      },
      {
        method: 'post',
        path: `/api/v1/findings/${FINDING_ID}/close`,
        body: { expectedVersion: 1, notes: 'Verified and closed' },
        expectedStatus: 200,
        assertCalled: () => expect(mockServices.findingService.closeFinding).toHaveBeenCalledTimes(1),
      },
      {
        method: 'delete',
        path: `/api/v1/findings/${FINDING_ID}`,
        body: { expectedVersion: 1 },
        expectedStatus: 200,
        assertCalled: () => expect(mockServices.findingService.softDeleteFinding).toHaveBeenCalledTimes(1),
      },
      {
        method: 'post',
        path: `/api/v1/findings/${FINDING_ID}/force-close`,
        body: { expectedVersion: 1, justification: 'Compensating WAF control accepted' },
        expectedStatus: 200,
        assertCalled: () => expect(mockServices.findingService.forceCloseFinding).toHaveBeenCalledTimes(1),
      },
      {
        method: 'post',
        path: `/api/v1/findings/${FINDING_ID}/force-reopen`,
        body: { expectedVersion: 1, justification: 'Regression detected during audit' },
        expectedStatus: 200,
        assertCalled: () => expect(mockServices.findingService.forceReopenFinding).toHaveBeenCalledTimes(1),
      },

      // Tasks (2 routes)
      {
        method: 'get',
        path: `/api/v1/tasks/${TASK_ID}`,
        expectedStatus: 200,
        assertCalled: () => expect(mockServices.taskService.getTask).toHaveBeenCalledTimes(1),
      },
      {
        method: 'patch',
        path: `/api/v1/tasks/${TASK_ID}/notes`,
        body: { notes: 'Developer remediation notes' },
        expectedStatus: 200,
        assertCalled: () => expect(mockServices.taskService.updateTaskNotes).toHaveBeenCalledTimes(1),
      },

      // Audit Events (1 route)
      {
        method: 'get',
        path: '/api/v1/audit-events',
        expectedStatus: 200,
        assertCalled: () => expect(mockServices.auditService.queryAuditLogs).toHaveBeenCalledTimes(1),
      },
    ];

    expect(routeSpecs).toHaveLength(23);

    for (const spec of routeSpecs) {
      let req = request(app)[spec.method](spec.path).set(
        'Cookie',
        `${authConfig.cookies.sessionCookieName}=${SESSION_TOKEN}`,
      );

      if (spec.method !== 'get') {
        req = req.set('Origin', ALLOWED_ORIGIN).set('X-CSRF-Token', CSRF_TOKEN);
      }
      if (spec.body !== undefined) {
        req = req.send(spec.body);
      }

      const res = await req;
      expect(res.status, `Expected ${spec.method.toUpperCase()} ${spec.path} to return ${spec.expectedStatus}`).toBe(
        spec.expectedStatus,
      );
      spec.assertCalled();
    }
  });

  it('returns 404 NOT_FOUND for deprecated/non-existent route aliases even when authenticated', async () => {
    const app = createApp(mockServices, { authConfig, oidcClient: mockOidcClient });

    const nonExistentRoutes = [
      { method: 'post' as const, path: `/api/v1/projects/${PROJECT_ID}/archive`, body: {} },
      { method: 'post' as const, path: `/api/v1/findings/${FINDING_ID}/confirm`, body: { expectedVersion: 1 } },
      { method: 'post' as const, path: `/api/v1/findings/${FINDING_ID}/reject`, body: { expectedVersion: 1 } },
    ];

    for (const badRoute of nonExistentRoutes) {
      const res = await request(app)
        [badRoute.method](badRoute.path)
        .set('Cookie', `${authConfig.cookies.sessionCookieName}=${SESSION_TOKEN}`)
        .set('Origin', ALLOWED_ORIGIN)
        .set('X-CSRF-Token', CSRF_TOKEN)
        .send(badRoute.body);

      expect(res.status).toBe(404);
      expect(res.body.error.code).toBe('NOT_FOUND');
    }
  });
});
