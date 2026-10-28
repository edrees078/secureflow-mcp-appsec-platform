import { describe, it, expect } from 'vitest';
import {
  ActorContext,
  ProjectPolicy,
  FindingPolicy,
  TaskPolicy,
  AuditPolicy,
  deriveProjectQueryScope,
  deriveFindingQueryScope,
} from '../../src/policy/index.js';
import { createSyntheticActorContext } from '../../src/testing/index.js';
import {
  EntityNotFoundError,
  ForbiddenError,
  UnauthorizedError,
} from '@secureflow/shared';

describe('Gate 3C — Object-Level Authorization Policies & Negative Tests (Offline Unit Tests)', () => {
  // ---------------------------------------------------------------------------
  // Deterministic Synthetic Personas
  // ---------------------------------------------------------------------------
  const projectA = '11111111-1111-1111-1111-111111111111';
  const projectB = '22222222-2222-2222-2222-222222222222';
  const projectC = '33333333-3333-3333-3333-333333333333';

  // Alex — Global Admin
  const adminActor = new ActorContext({
    id: 'admin-alex-uuid',
    globalRole: 'ADMIN',
    isActive: true,
  });

  // Sam — Security Analyst (Member of ProjectA and ProjectB)
  const analystActor = new ActorContext({
    id: 'analyst-sam-uuid',
    globalRole: 'ANALYST',
    isActive: true,
    memberships: [
      { projectId: projectA, role: 'ANALYST' },
      { projectId: projectB, role: 'ANALYST' },
    ],
  });

  // Dev1 — Developer (Member of ProjectA)
  const dev1Actor = new ActorContext({
    id: 'dev1-uuid',
    globalRole: 'DEVELOPER',
    isActive: true,
    memberships: [{ projectId: projectA, role: 'DEVELOPER' }],
  });

  // DevOtherInProjA — Developer (Member of ProjectA, not assigned to Dev1 tasks)
  const devOtherInProjA = new ActorContext({
    id: 'dev-other-projA-uuid',
    globalRole: 'DEVELOPER',
    isActive: true,
    memberships: [{ projectId: projectA, role: 'DEVELOPER' }],
  });

  // Dev2 — Developer (Member of ProjectB)
  const dev2Actor = new ActorContext({
    id: 'dev2-uuid',
    globalRole: 'DEVELOPER',
    isActive: true,
    memberships: [{ projectId: projectB, role: 'DEVELOPER' }],
  });

  // Inactive Actors
  const inactiveAdmin = new ActorContext({
    id: 'inactive-admin-uuid',
    globalRole: 'ADMIN',
    isActive: false,
  });

  const inactiveAnalyst = new ActorContext({
    id: 'inactive-analyst-uuid',
    globalRole: 'ANALYST',
    isActive: false,
    memberships: [{ projectId: projectA, role: 'ANALYST' }],
  });

  const inactiveDev = new ActorContext({
    id: 'inactive-dev-uuid',
    globalRole: 'DEVELOPER',
    isActive: false,
    memberships: [{ projectId: projectA, role: 'DEVELOPER' }],
  });

  // ---------------------------------------------------------------------------
  // 1. Inactive Account Denial (Fail-closed for all inactive accounts)
  // ---------------------------------------------------------------------------
  describe('Inactive Account Denial (NEG-05 / Account Inactive)', () => {
    it('denies inactive Admin across project, finding, and audit policies', () => {
      expect(ProjectPolicy.can(inactiveAdmin, 'create').allowed).toBe(false);
      expect(ProjectPolicy.can(inactiveAdmin, 'create').errorCode).toBe('ACCOUNT_INACTIVE');

      expect(AuditPolicy.can(inactiveAdmin, 'view_org').allowed).toBe(false);
      expect(AuditPolicy.can(inactiveAdmin, 'view_org').errorCode).toBe('ACCOUNT_INACTIVE');

      expect(
        FindingPolicy.can(inactiveAdmin, 'view', {
          finding: { id: 'f-1', projectId: projectA, isDeleted: false },
        }).allowed,
      ).toBe(false);
    });

    it('denies inactive Analyst across finding and task policies', () => {
      expect(FindingPolicy.can(inactiveAnalyst, 'create', { projectId: projectA }).allowed).toBe(false);
      expect(
        FindingPolicy.can(inactiveAnalyst, 'triage', {
          finding: { id: 'f-1', projectId: projectA },
        }).allowed,
      ).toBe(false);

      expect(TaskPolicy.can(inactiveAnalyst, 'create', { projectId: projectA }).allowed).toBe(false);
    });

    it('denies inactive Developer across task and finding policies', () => {
      expect(
        FindingPolicy.can(inactiveDev, 'submit_remediation', {
          finding: { id: 'f-1', projectId: projectA, assignedToId: inactiveDev.id },
        }).allowed,
      ).toBe(false);

      expect(
        TaskPolicy.can(inactiveDev, 'update_notes', {
          projectId: projectA,
          task: { id: 't-1', findingId: 'f-1', assignedToId: inactiveDev.id },
        }).allowed,
      ).toBe(false);
    });
  });

  // ---------------------------------------------------------------------------
  // 1B. Unauthenticated Request Denial (NEG-05 / 401 Unauthorized)
  // ---------------------------------------------------------------------------
  describe('Unauthenticated Request Denial (NEG-05 / 401 Unauthorized)', () => {
    it('denies null actor across project policy with 401 Unauthorized and throws UnauthorizedError', () => {
      const decision = ProjectPolicy.can(null, 'view', { id: projectA });
      expect(decision.allowed).toBe(false);
      expect(decision.httpStatus).toBe(401);
      expect(decision.errorCode).toBe('UNAUTHORIZED');
      expect(() => ProjectPolicy.authorize(null, 'view', { id: projectA })).toThrow(UnauthorizedError);
    });

    it('denies undefined actor across finding policy with 401 Unauthorized and throws UnauthorizedError', () => {
      const decision = FindingPolicy.can(undefined, 'view', {
        finding: { id: 'f-1', projectId: projectA },
      });
      expect(decision.allowed).toBe(false);
      expect(decision.httpStatus).toBe(401);
      expect(decision.errorCode).toBe('UNAUTHORIZED');
      expect(() =>
        FindingPolicy.authorize(undefined, 'view', {
          finding: { id: 'f-1', projectId: projectA },
        }),
      ).toThrow(UnauthorizedError);
    });

    it('denies null actor across task policy with 401 Unauthorized and throws UnauthorizedError', () => {
      const decision = TaskPolicy.can(null, 'create', { projectId: projectA });
      expect(decision.allowed).toBe(false);
      expect(decision.httpStatus).toBe(401);
      expect(decision.errorCode).toBe('UNAUTHORIZED');
      expect(() => TaskPolicy.authorize(null, 'create', { projectId: projectA })).toThrow(
        UnauthorizedError,
      );
    });

    it('denies null actor across audit policy with 401 Unauthorized and throws UnauthorizedError', () => {
      const decision = AuditPolicy.can(null, 'view_org');
      expect(decision.allowed).toBe(false);
      expect(decision.httpStatus).toBe(401);
      expect(decision.errorCode).toBe('UNAUTHORIZED');
      expect(() => AuditPolicy.authorize(null, 'view_org')).toThrow(UnauthorizedError);
    });
  });

  // ---------------------------------------------------------------------------
  // 2. ProjectPolicy Tests
  // ---------------------------------------------------------------------------
  describe('ProjectPolicy (docs/04-authorization-matrix.md §2.1)', () => {
    it('Admin can create, list_all, update, archive, and manage members', () => {
      expect(ProjectPolicy.can(adminActor, 'create').allowed).toBe(true);
      expect(ProjectPolicy.can(adminActor, 'list_all').allowed).toBe(true);
      expect(ProjectPolicy.can(adminActor, 'update', { id: projectA }).allowed).toBe(true);
      expect(ProjectPolicy.can(adminActor, 'archive', { id: projectA }).allowed).toBe(true);
      expect(ProjectPolicy.can(adminActor, 'add_member', { id: projectA }).allowed).toBe(true);
      expect(ProjectPolicy.can(adminActor, 'remove_member', { id: projectA }).allowed).toBe(true);
      expect(ProjectPolicy.can(adminActor, 'view', { id: projectA }).allowed).toBe(true);
      expect(ProjectPolicy.can(adminActor, 'view_members', { id: projectA }).allowed).toBe(true);
    });

    it('NEG-06: Developer cannot add project members (403 Forbidden)', () => {
      const decision = ProjectPolicy.can(dev1Actor, 'add_member', { id: projectA });
      expect(decision.allowed).toBe(false);
      expect(decision.httpStatus).toBe(403);
      expect(() => ProjectPolicy.authorize(dev1Actor, 'add_member', { id: projectA })).toThrow(
        ForbiddenError,
      );
    });

    it('NEG-07: Analyst cannot add project members (403 Forbidden)', () => {
      const decision = ProjectPolicy.can(analystActor, 'add_member', { id: projectA });
      expect(decision.allowed).toBe(false);
      expect(decision.httpStatus).toBe(403);
      expect(() => ProjectPolicy.authorize(analystActor, 'add_member', { id: projectA })).toThrow(
        ForbiddenError,
      );
    });

    it('Analyst and Developer can view projects they are members of', () => {
      expect(ProjectPolicy.can(analystActor, 'view', { id: projectA }).allowed).toBe(true);
      expect(ProjectPolicy.can(dev1Actor, 'view', { id: projectA }).allowed).toBe(true);
      expect(ProjectPolicy.can(analystActor, 'view_members', { id: projectA }).allowed).toBe(true);
      expect(ProjectPolicy.can(dev1Actor, 'view_members', { id: projectA }).allowed).toBe(true);
    });

    it('Existence Hiding: non-members receive 404 Not Found on view, not 403', () => {
      // Dev1 is NOT member of projectB
      const decision = ProjectPolicy.can(dev1Actor, 'view', { id: projectB });
      expect(decision.allowed).toBe(false);
      expect(decision.httpStatus).toBe(404);
      expect(decision.errorCode).toBe('RESOURCE_NOT_FOUND');
      expect(() => ProjectPolicy.authorize(dev1Actor, 'view', { id: projectB })).toThrow(
        EntityNotFoundError,
      );
    });
  });

  // ---------------------------------------------------------------------------
  // 3. FindingPolicy Tests
  // ---------------------------------------------------------------------------
  describe('FindingPolicy (docs/04-authorization-matrix.md §2.2 & Invariants)', () => {
    describe('Finding Creation (F-13, NEG-04, NEG-13)', () => {
      it('Analyst can create finding in project where they are member', () => {
        expect(FindingPolicy.can(analystActor, 'create', { projectId: projectA }).allowed).toBe(true);
      });

      it('NEG-13: Admin cannot create operational findings (403 Forbidden)', () => {
        const decision = FindingPolicy.can(adminActor, 'create', { projectId: projectA });
        expect(decision.allowed).toBe(false);
        expect(decision.httpStatus).toBe(403);
        expect(() => FindingPolicy.authorize(adminActor, 'create', { projectId: projectA })).toThrow(
          ForbiddenError,
        );
      });

      it('NEG-04: Developer cannot create findings (403 Forbidden)', () => {
        const decision = FindingPolicy.can(dev1Actor, 'create', { projectId: projectA });
        expect(decision.allowed).toBe(false);
        expect(decision.httpStatus).toBe(403);
        expect(() => FindingPolicy.authorize(dev1Actor, 'create', { projectId: projectA })).toThrow(
          ForbiddenError,
        );
      });

      it('Analyst cannot create finding in non-member project (404 Not Found)', () => {
        // Sam is NOT in ProjectC
        const decision = FindingPolicy.can(analystActor, 'create', { projectId: projectC });
        expect(decision.allowed).toBe(false);
        expect(decision.httpStatus).toBe(404);
      });
    });

    describe('Finding Viewing & Existence Hiding (OLI-1, OLI-2, OLI-12, NEG-01, NEG-03)', () => {
      const findingProjAAssignedDev1 = {
        id: 'f-projA-dev1',
        projectId: projectA,
        assignedToId: dev1Actor.id,
        isDeleted: false,
      };

      const findingProjAUnassigned = {
        id: 'f-projA-unassigned',
        projectId: projectA,
        assignedToId: null,
        isDeleted: false,
      };

      const findingProjBAssignedDev2 = {
        id: 'f-projB-dev2',
        projectId: projectB,
        assignedToId: dev2Actor.id,
        isDeleted: false,
      };

      const softDeletedFindingProjA = {
        id: 'f-projA-deleted',
        projectId: projectA,
        assignedToId: dev1Actor.id,
        isDeleted: true,
      };

      it('Admin can view any active finding across any project', () => {
        expect(FindingPolicy.can(adminActor, 'view', { finding: findingProjAAssignedDev1 }).allowed).toBe(
          true,
        );
        expect(FindingPolicy.can(adminActor, 'view', { finding: findingProjBAssignedDev2 }).allowed).toBe(
          true,
        );
      });

      it('Analyst can view findings in authorized projects', () => {
        expect(FindingPolicy.can(analystActor, 'view', { finding: findingProjAAssignedDev1 }).allowed).toBe(
          true,
        );
        expect(FindingPolicy.can(analystActor, 'view', { finding: findingProjBAssignedDev2 }).allowed).toBe(
          true,
        );
      });

      it('NEG-03: Analyst in ProjectA attempting to access finding in ProjectC receives 404 (existence hiding)', () => {
        const findingProjC = { id: 'f-projC-1', projectId: projectC, isDeleted: false };
        const decision = FindingPolicy.can(analystActor, 'view', { finding: findingProjC });
        expect(decision.allowed).toBe(false);
        expect(decision.httpStatus).toBe(404);
        expect(decision.errorCode).toBe('RESOURCE_NOT_FOUND');
        expect(() => FindingPolicy.authorize(analystActor, 'view', { finding: findingProjC })).toThrow(
          EntityNotFoundError,
        );
      });

      it('Developer can view finding assigned to them in their authorized project (OLI-2)', () => {
        expect(FindingPolicy.can(dev1Actor, 'view', { finding: findingProjAAssignedDev1 }).allowed).toBe(
          true,
        );
      });

      it('NEG-01: Developer accessing unassigned finding in own project receives 404 (existence hiding)', () => {
        const decision = FindingPolicy.can(dev1Actor, 'view', { finding: findingProjAUnassigned });
        expect(decision.allowed).toBe(false);
        expect(decision.httpStatus).toBe(404);
        expect(decision.errorCode).toBe('RESOURCE_NOT_FOUND');
        expect(() =>
          FindingPolicy.authorize(dev1Actor, 'view', { finding: findingProjAUnassigned }),
        ).toThrow(EntityNotFoundError);
      });

      it('NEG-01: Developer accessing another project finding by guessing UUID receives 404 (existence hiding)', () => {
        const decision = FindingPolicy.can(dev1Actor, 'view', { finding: findingProjBAssignedDev2 });
        expect(decision.allowed).toBe(false);
        expect(decision.httpStatus).toBe(404);
        expect(decision.errorCode).toBe('RESOURCE_NOT_FOUND');
        expect(() =>
          FindingPolicy.authorize(dev1Actor, 'view', { finding: findingProjBAssignedDev2 }),
        ).toThrow(EntityNotFoundError);
      });

      it('Invariant OLI-12: Soft-deleted finding is hidden from Analyst and Developer (returns 404)', () => {
        const decisionAnalyst = FindingPolicy.can(analystActor, 'view', {
          finding: softDeletedFindingProjA,
        });
        expect(decisionAnalyst.allowed).toBe(false);
        expect(decisionAnalyst.httpStatus).toBe(404);

        const decisionDev = FindingPolicy.can(dev1Actor, 'view', { finding: softDeletedFindingProjA });
        expect(decisionDev.allowed).toBe(false);
        expect(decisionDev.httpStatus).toBe(404);

        // Admin can view soft-deleted finding
        expect(FindingPolicy.can(adminActor, 'view', { finding: softDeletedFindingProjA }).allowed).toBe(
          true,
        );
      });
    });

    describe('Analyst Operations (Triage, Metadata, Assign, Close, Reopen, Soft-Delete)', () => {
      const finding = { id: 'f-1', projectId: projectA, isDeleted: false };

      it('Analyst in project can triage, update metadata, assign, close, reopen, and soft-delete', () => {
        expect(FindingPolicy.can(analystActor, 'triage', { finding }).allowed).toBe(true);
        expect(FindingPolicy.can(analystActor, 'update_metadata', { finding }).allowed).toBe(true);
        expect(FindingPolicy.can(analystActor, 'assign', { finding }).allowed).toBe(true);
        expect(FindingPolicy.can(analystActor, 'close', { finding }).allowed).toBe(true);
        expect(FindingPolicy.can(analystActor, 'reopen', { finding }).allowed).toBe(true);
        expect(FindingPolicy.can(analystActor, 'soft_delete', { finding }).allowed).toBe(true);
      });

      it('Developer cannot triage, update metadata, assign, close, or soft-delete (403 Forbidden)', () => {
        expect(FindingPolicy.can(dev1Actor, 'triage', { finding }).httpStatus).toBe(403);
        expect(FindingPolicy.can(dev1Actor, 'update_metadata', { finding }).httpStatus).toBe(403);
        expect(FindingPolicy.can(dev1Actor, 'assign', { finding }).httpStatus).toBe(403);
        expect(FindingPolicy.can(dev1Actor, 'close', { finding }).httpStatus).toBe(403);
        expect(FindingPolicy.can(dev1Actor, 'soft_delete', { finding }).httpStatus).toBe(403);
      });

      it('Admin cannot triage, update metadata, assign, close, or soft-delete (403 Forbidden)', () => {
        expect(FindingPolicy.can(adminActor, 'triage', { finding }).httpStatus).toBe(403);
        expect(FindingPolicy.can(adminActor, 'update_metadata', { finding }).httpStatus).toBe(403);
        expect(FindingPolicy.can(adminActor, 'assign', { finding }).httpStatus).toBe(403);
        expect(FindingPolicy.can(adminActor, 'close', { finding }).httpStatus).toBe(403);
        expect(FindingPolicy.can(adminActor, 'soft_delete', { finding }).httpStatus).toBe(403);
      });

      it('Admin can execute exceptional force_close and force_reopen', () => {
        expect(FindingPolicy.can(adminActor, 'force_close', { finding }).allowed).toBe(true);
        expect(FindingPolicy.can(adminActor, 'force_reopen', { finding }).allowed).toBe(true);

        expect(FindingPolicy.can(analystActor, 'force_close', { finding }).httpStatus).toBe(403);
        expect(FindingPolicy.can(dev1Actor, 'force_close', { finding }).httpStatus).toBe(403);
      });
    });

    describe('Remediation Submission (OLI-6, NEG-08)', () => {
      const findingAssignedDev1 = {
        id: 'f-1',
        projectId: projectA,
        assignedToId: dev1Actor.id,
      };

      it('Assigned Developer can submit remediation', () => {
        expect(
          FindingPolicy.can(dev1Actor, 'submit_remediation', { finding: findingAssignedDev1 }).allowed,
        ).toBe(true);
      });

      it('NEG-08: Non-assignee Developer in same project cannot submit remediation (403 Forbidden)', () => {
        const decision = FindingPolicy.can(devOtherInProjA, 'submit_remediation', {
          finding: findingAssignedDev1,
        });
        expect(decision.allowed).toBe(false);
        expect(decision.httpStatus).toBe(403);
        expect(decision.errorCode).toBe('FORBIDDEN');
      });

      it('NEG-08: Developer in different project attempting to submit remediation receives 404 (existence hiding)', () => {
        const decision = FindingPolicy.can(dev2Actor, 'submit_remediation', {
          finding: findingAssignedDev1,
        });
        expect(decision.allowed).toBe(false);
        expect(decision.httpStatus).toBe(404);
        expect(decision.errorCode).toBe('RESOURCE_NOT_FOUND');
      });

      it('Analyst or Admin cannot submit remediation (403 Forbidden)', () => {
        expect(
          FindingPolicy.can(analystActor, 'submit_remediation', { finding: findingAssignedDev1 })
            .httpStatus,
        ).toBe(403);
        expect(
          FindingPolicy.can(adminActor, 'submit_remediation', { finding: findingAssignedDev1 })
            .httpStatus,
        ).toBe(403);
      });
    });

    describe('Finding Verification & Separation of Duties (docs/04-authorization-matrix.md §3 OLI-7, NEG-02, NEG-11)', () => {
      const finding = { id: 'f-1', projectId: projectA };

      it('Case 1: Analyst can verify finding when different authorized actor submitted remediation', () => {
        const decision = FindingPolicy.can(analystActor, 'verify', {
          finding,
          remediationSubmitterId: 'different-developer-uuid',
        });
        expect(decision.allowed).toBe(true);
      });

      it('Case 2: OLI-7: Analyst who submitted remediation cannot self-verify finding (403 SEPARATION_OF_DUTIES_VIOLATION)', () => {
        const decision = FindingPolicy.can(analystActor, 'verify', {
          finding,
          remediationSubmitterId: analystActor.id, // Self-verification attempt
        });
        expect(decision.allowed).toBe(false);
        expect(decision.httpStatus).toBe(403);
        expect(decision.errorCode).toBe('SEPARATION_OF_DUTIES_VIOLATION');
        expect(() =>
          FindingPolicy.authorize(analystActor, 'verify', {
            finding,
            remediationSubmitterId: analystActor.id,
          }),
        ).toThrow(ForbiddenError);
      });

      it('Case 3: Fail-closed: Verification rejected when remediation-submitter evidence is undefined', () => {
        const decision = FindingPolicy.can(analystActor, 'verify', {
          finding,
          remediationSubmitterId: undefined, // Missing evidence
        });
        expect(decision.allowed).toBe(false);
        expect(decision.httpStatus).toBe(403);
        expect(decision.errorCode).toBe('SEPARATION_OF_DUTIES_VIOLATION');
        expect(decision.reason).toContain('fail-closed SoD enforcement');
        expect(() =>
          FindingPolicy.authorize(analystActor, 'verify', {
            finding,
            remediationSubmitterId: undefined,
          }),
        ).toThrow(ForbiddenError);
      });

      it('Case 4: Fail-closed: Verification rejected when remediation-submitter evidence is null', () => {
        const decision = FindingPolicy.can(analystActor, 'verify', {
          finding,
          remediationSubmitterId: null, // Null evidence
        });
        expect(decision.allowed).toBe(false);
        expect(decision.httpStatus).toBe(403);
        expect(decision.errorCode).toBe('SEPARATION_OF_DUTIES_VIOLATION');
        expect(() =>
          FindingPolicy.authorize(analystActor, 'verify', {
            finding,
            remediationSubmitterId: null,
          }),
        ).toThrow(ForbiddenError);
      });

      it('Case 5: NEG-02 & NEG-11: Developer cannot verify finding (403 Forbidden)', () => {
        const decision = FindingPolicy.can(dev1Actor, 'verify', {
          finding,
          remediationSubmitterId: 'different-developer-uuid',
        });
        expect(decision.allowed).toBe(false);
        expect(decision.httpStatus).toBe(403);
        expect(decision.errorCode).toBe('FORBIDDEN');
        expect(() =>
          FindingPolicy.authorize(dev1Actor, 'verify', {
            finding,
            remediationSubmitterId: 'different-developer-uuid',
          }),
        ).toThrow(ForbiddenError);
      });

      it('Case 6: Admin cannot verify finding (403 Forbidden)', () => {
        const decision = FindingPolicy.can(adminActor, 'verify', {
          finding,
          remediationSubmitterId: 'different-developer-uuid',
        });
        expect(decision.allowed).toBe(false);
        expect(decision.httpStatus).toBe(403);
        expect(decision.errorCode).toBe('FORBIDDEN');
        expect(() =>
          FindingPolicy.authorize(adminActor, 'verify', {
            finding,
            remediationSubmitterId: 'different-developer-uuid',
          }),
        ).toThrow(ForbiddenError);
      });
    });

    describe('Dynamic Membership Revocation (OLI-10, NEG-14)', () => {
      it('NEG-14: Removing project membership immediately causes subsequent view to return 404', () => {
        const finding = { id: 'f-projA-1', projectId: projectA, isDeleted: false };

        // Before removal: member Dev1 can view assigned finding
        const findingAssignedDev1 = { ...finding, assignedToId: dev1Actor.id };
        expect(FindingPolicy.can(dev1Actor, 'view', { finding: findingAssignedDev1 }).allowed).toBe(true);

        // After removal: Dev1 removed from projectA (no memberships)
        const formerDev1 = new ActorContext({
          id: dev1Actor.id,
          globalRole: 'DEVELOPER',
          isActive: true,
          memberships: [],
        });

        const decision = FindingPolicy.can(formerDev1, 'view', { finding: findingAssignedDev1 });
        expect(decision.allowed).toBe(false);
        expect(decision.httpStatus).toBe(404);
        expect(decision.errorCode).toBe('RESOURCE_NOT_FOUND');
        expect(() => FindingPolicy.authorize(formerDev1, 'view', { finding: findingAssignedDev1 })).toThrow(
          EntityNotFoundError,
        );
      });
    });
  });

  // ---------------------------------------------------------------------------
  // 4. TaskPolicy Tests
  // ---------------------------------------------------------------------------
  describe('TaskPolicy (docs/04-authorization-matrix.md §2.3)', () => {
    const taskAssignedDev1 = {
      id: 't-1',
      findingId: 'f-1',
      assignedToId: dev1Actor.id,
    };

    it('Analyst in project can create, view, verify, and reject remediation tasks', () => {
      expect(TaskPolicy.can(analystActor, 'create', { projectId: projectA }).allowed).toBe(true);
      expect(
        TaskPolicy.can(analystActor, 'view', { projectId: projectA, task: taskAssignedDev1 }).allowed,
      ).toBe(true);
      expect(
        TaskPolicy.can(analystActor, 'verify', { projectId: projectA, task: taskAssignedDev1 }).allowed,
      ).toBe(true);
      expect(
        TaskPolicy.can(analystActor, 'reject', { projectId: projectA, task: taskAssignedDev1 }).allowed,
      ).toBe(true);
    });

    it('Assigned Developer can view, update notes, and submit task (OLI-3)', () => {
      expect(
        TaskPolicy.can(dev1Actor, 'view', { projectId: projectA, task: taskAssignedDev1 }).allowed,
      ).toBe(true);
      expect(
        TaskPolicy.can(dev1Actor, 'update_notes', { projectId: projectA, task: taskAssignedDev1 }).allowed,
      ).toBe(true);
      expect(
        TaskPolicy.can(dev1Actor, 'submit', { projectId: projectA, task: taskAssignedDev1 }).allowed,
      ).toBe(true);
    });

    it('Non-assignee Developer in same project cannot view (404), update notes (403), or submit task (403)', () => {
      // devOtherInProjA is a member of ProjectA, but not assigned to taskAssignedDev1
      expect(
        TaskPolicy.can(devOtherInProjA, 'view', { projectId: projectA, task: taskAssignedDev1 }).httpStatus,
      ).toBe(404);
      expect(
        TaskPolicy.can(devOtherInProjA, 'update_notes', { projectId: projectA, task: taskAssignedDev1 })
          .httpStatus,
      ).toBe(403);
      expect(
        TaskPolicy.can(devOtherInProjA, 'submit', { projectId: projectA, task: taskAssignedDev1 }).httpStatus,
      ).toBe(403);
    });

    it('Developer in different project receives 404 Not Found on all task operations (existence hiding)', () => {
      // dev2Actor is only in ProjectB
      expect(
        TaskPolicy.can(dev2Actor, 'view', { projectId: projectA, task: taskAssignedDev1 }).httpStatus,
      ).toBe(404);
      expect(
        TaskPolicy.can(dev2Actor, 'update_notes', { projectId: projectA, task: taskAssignedDev1 })
          .httpStatus,
      ).toBe(404);
      expect(
        TaskPolicy.can(dev2Actor, 'submit', { projectId: projectA, task: taskAssignedDev1 }).httpStatus,
      ).toBe(404);
    });

    it('Developer cannot verify or reject task (403 Forbidden)', () => {
      expect(
        TaskPolicy.can(dev1Actor, 'verify', { projectId: projectA, task: taskAssignedDev1 }).httpStatus,
      ).toBe(403);
      expect(
        TaskPolicy.can(dev1Actor, 'reject', { projectId: projectA, task: taskAssignedDev1 }).httpStatus,
      ).toBe(403);
    });
  });

  // ---------------------------------------------------------------------------
  // 5. AuditPolicy Tests
  // ---------------------------------------------------------------------------
  describe('AuditPolicy (docs/04-authorization-matrix.md §2.4 & NEG-12)', () => {
    it('Admin can view project and org-wide audit events', () => {
      expect(AuditPolicy.can(adminActor, 'view_project').allowed).toBe(true);
      expect(AuditPolicy.can(adminActor, 'view_org').allowed).toBe(true);
    });

    it('NEG-12: Analyst cannot view audit events (403 Forbidden)', () => {
      const decision = AuditPolicy.can(analystActor, 'view_project');
      expect(decision.allowed).toBe(false);
      expect(decision.httpStatus).toBe(403);
      expect(decision.errorCode).toBe('FORBIDDEN');
      expect(() => AuditPolicy.authorize(analystActor, 'view_project')).toThrow(ForbiddenError);
    });

    it('Developer cannot view audit events (403 Forbidden)', () => {
      const decision = AuditPolicy.can(dev1Actor, 'view_org');
      expect(decision.allowed).toBe(false);
      expect(decision.httpStatus).toBe(403);
      expect(decision.errorCode).toBe('FORBIDDEN');
      expect(() => AuditPolicy.authorize(dev1Actor, 'view_org')).toThrow(ForbiddenError);
    });
  });

  // ---------------------------------------------------------------------------
  // 6. Query-Scope Derivation Tests
  // ---------------------------------------------------------------------------
  describe('Query Scope Derivation (Controlled Internal Construction)', () => {
    describe('ProjectQueryScope Derivation', () => {
      it('Admin derives unrestricted project scope', () => {
        const scope = deriveProjectQueryScope(adminActor, { includeInactiveProjects: true });
        expect(scope.unrestricted).toBe(true);
        expect(scope.includeInactive).toBe(true);
        expect(scope.accessibleProjectIds).toBeUndefined();
      });

      it('Analyst derives scope constrained to active project memberships', () => {
        const scope = deriveProjectQueryScope(analystActor);
        expect(scope.unrestricted).toBe(false);
        expect(scope.includeInactive).toBe(false);
        expect(scope.accessibleProjectIds).toEqual([projectA, projectB]);
      });

      it('Developer derives scope constrained to active project memberships', () => {
        const scope = deriveProjectQueryScope(dev1Actor);
        expect(scope.unrestricted).toBe(false);
        expect(scope.includeInactive).toBe(false);
        expect(scope.accessibleProjectIds).toEqual([projectA]);
      });

      it('Inactive user derives fail-closed empty accessibleProjectIds: []', () => {
        const scope = deriveProjectQueryScope(inactiveAdmin);
        expect(scope.accessibleProjectIds).toEqual([]);
        expect(scope.unrestricted).toBeUndefined();
      });
    });

    describe('FindingQueryScope Derivation', () => {
      it('Admin derives unrestricted finding scope and can explicitly request soft-deleted records', () => {
        const scope = deriveFindingQueryScope(adminActor, { includeDeletedFindings: true });
        expect(scope.unrestricted).toBe(true);
        expect(scope.includeDeleted).toBe(true);
        expect(scope.assignedToUserId).toBeUndefined();
      });

      it('Analyst derives project-scoped finding scope and cannot see soft-deleted records', () => {
        // Even if includeDeletedFindings: true is passed, it is strictly ignored for Analyst
        const scope = deriveFindingQueryScope(analystActor, { includeDeletedFindings: true });
        expect(scope.unrestricted).toBe(false);
        expect(scope.includeDeleted).toBe(false);
        expect(scope.accessibleProjectIds).toEqual([projectA, projectB]);
        expect(scope.assignedToUserId).toBeUndefined();
      });

      it('Developer derives project-scoped finding scope strictly constrained to assigned findings', () => {
        // Developer must have assignedToUserId: actor.id and cannot see deleted records
        const scope = deriveFindingQueryScope(dev1Actor, { includeDeletedFindings: true });
        expect(scope.unrestricted).toBe(false);
        expect(scope.includeDeleted).toBe(false);
        expect(scope.accessibleProjectIds).toEqual([projectA]);
        expect(scope.assignedToUserId).toBe(dev1Actor.id);
      });

      it('Actor with zero memberships derives fail-closed empty accessibleProjectIds: []', () => {
        const userNoProjects = new ActorContext({
          id: 'user-no-proj',
          globalRole: 'ANALYST',
          isActive: true,
          memberships: [],
        });
        const scope = deriveFindingQueryScope(userNoProjects);
        expect(scope.accessibleProjectIds).toEqual([]);
        expect(scope.unrestricted).toBe(false);
      });

      it('Null or undefined actor derives fail-closed empty accessibleProjectIds: []', () => {
        expect(deriveProjectQueryScope(null).accessibleProjectIds).toEqual([]);
        expect(deriveProjectQueryScope(undefined).accessibleProjectIds).toEqual([]);
        expect(deriveFindingQueryScope(null).accessibleProjectIds).toEqual([]);
        expect(deriveFindingQueryScope(undefined).accessibleProjectIds).toEqual([]);
      });
    });
  });

  // ---------------------------------------------------------------------------
  // 7. Authorization Matrix Reconciled Scenarios (NEG-01 to NEG-15 & OLI-1 to OLI-12)
  // ---------------------------------------------------------------------------
  describe('Authorization Matrix Reconciled Scenarios (docs/04-authorization-matrix.md)', () => {
    it('NEG-09: MCP cross-project resource access is rejected with 404 existence hiding by FindingPolicy', () => {
      // In docs/04-authorization-matrix.md Table 4, NEG-09 is defined as MCP client calling get_finding_details
      // with another project's UUID. Per REST/MCP Parity (§1 Principle 6), MCP tools invoke the same domain policy.
      const mcpActorProjectA = createSyntheticActorContext({
        id: 'mcp-analyst-uuid',
        globalRole: 'ANALYST',
        isActive: true,
        memberships: [{ projectId: projectA, role: 'ANALYST' }],
      });
      const findingInProjectB = { id: 'f-projB-cross', projectId: projectB, isDeleted: false };
      const decision = FindingPolicy.can(mcpActorProjectA, 'view', { finding: findingInProjectB });
      expect(decision.allowed).toBe(false);
      expect(decision.httpStatus).toBe(404);
      expect(decision.errorCode).toBe('RESOURCE_NOT_FOUND');
    });

    it('NEG-10 (Policy Contract): Unauthenticated actor rejected with 401 Unauthorized (JWT expiration enforcement deferred to Phase 4/6)', () => {
      // In docs/04-authorization-matrix.md Table 4, NEG-10 defines an MCP client calling a tool with an expired Bearer token.
      // Actual cryptographic Bearer-token expiry and signature verification belongs to future authentication/MCP integration.
      // At the domain policy layer (Gate 3C), an unauthenticated principal (null/undefined ActorContext) fails closed with 401.
      const decision = FindingPolicy.can(null, 'view', {
        finding: { id: 'f-1', projectId: projectA },
      });
      expect(decision.allowed).toBe(false);
      expect(decision.httpStatus).toBe(401);
      expect(decision.errorCode).toBe('UNAUTHORIZED');
    });

    it('NEG-15 (Policy Contract): Action policy enforces caller role boundaries (end-to-end MCP execution re-authorization deferred to Phase 6)', () => {
      // In docs/04-authorization-matrix.md Table 4, NEG-15 specifies that proposed actions must re-authorize
      // the requesting principal immediately before execution.
      // End-to-end MCP proposed-action execution security is an MCP runtime requirement in Phase 6.
      // At the domain policy layer (Gate 3C), this test proves that the underlying action policy enforces role boundaries
      // (e.g. Developer cannot execute an Analyst operational action like triage).
      const decision = FindingPolicy.can(dev1Actor, 'triage', {
        finding: { id: 'f-1', projectId: projectA },
      });
      expect(decision.allowed).toBe(false);
      expect(decision.httpStatus).toBe(403);
      expect(decision.errorCode).toBe('FORBIDDEN');
    });

    it('Synthetic Actor Factory: createSyntheticActorContext constructs deterministic test context', () => {
      const syntheticActor = createSyntheticActorContext({
        id: 'synthetic-id',
        globalRole: 'DEVELOPER',
        isActive: true,
        memberships: [{ projectId: projectA, role: 'DEVELOPER' }],
      });
      expect(syntheticActor.id).toBe('synthetic-id');
      expect(syntheticActor.isDeveloper()).toBe(true);
      expect(syntheticActor.isMemberOf(projectA)).toBe(true);
      expect(syntheticActor.isMemberOf(projectB)).toBe(false);
    });
  });
});
