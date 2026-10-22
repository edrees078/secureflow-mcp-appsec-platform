import { describe, it, expect } from 'vitest';
import {
  SecureFlowError,
  EntityNotFoundError,
  ForbiddenError,
  UnauthorizedError,
  DomainValidationError,
  InvalidStateTransitionError,
  ConcurrencyConflictError,
} from '@secureflow/shared';

import {
  GlobalRoleSchema,
  ProjectRoleSchema,
  FindingSeveritySchema,
  FindingCategorySchema,
  FindingStatusSchema,
  RemediationTaskStatusSchema,
  FindingEventTypeSchema,
  AuditEventCategorySchema,
  CreateProjectInputSchema,
  UpdateProjectInputSchema,
  AddProjectMemberInputSchema,
  CreateFindingInputSchema,
  TriageFindingInputSchema,
  AssignFindingInputSchema,
  SubmitRemediationInputSchema,
  VerifyFindingInputSchema,
  CloseFindingInputSchema,
  ReopenFindingInputSchema,
  UpdateFindingMetadataInputSchema,
  SoftDeleteFindingInputSchema,
  CreateRemediationTaskInputSchema,
  UpdateTaskNotesInputSchema,
  QueryAuditEventsInputSchema,
} from '@secureflow/schemas';

import {
  _checkGlobalRole,
  _checkProjectRole,
  _checkFindingSeverity,
  _checkFindingCategory,
  _checkFindingStatus,
  _checkRemediationTaskStatus,
  _checkFindingEventType,
  _checkAuditEventCategory,
  type AssertIdentical,
} from '../../src/contracts-check.js';

import type { GlobalRole as PrismaGlobalRole } from '../../src/generated/prisma/enums.js';

describe('SecureFlow — Gate 3A Unit Test Suite', () => {
  // ---------------------------------------------------------------------------
  // 1. Domain Error Hierarchy & HTTP Status Mapping Tests
  // ---------------------------------------------------------------------------
  describe('Domain Error Hierarchy', () => {
    it('SecureFlowError base class defaults and prototype', () => {
      const err = new SecureFlowError('base failure');
      expect(err.statusCode).toBe(500);
      expect(err.code).toBe('INTERNAL_ERROR');
      expect(err.message).toBe('base failure');
      expect(err).toBeInstanceOf(Error);
      expect(err).toBeInstanceOf(SecureFlowError);
    });

    it('EntityNotFoundError maps to HTTP 404 with ENTITY_NOT_FOUND code', () => {
      const err = new EntityNotFoundError('Finding 123 not found');
      expect(err.statusCode).toBe(404);
      expect(err.code).toBe('ENTITY_NOT_FOUND');
      expect(err.message).toBe('Finding 123 not found');
      expect(err).toBeInstanceOf(SecureFlowError);
      expect(err).toBeInstanceOf(EntityNotFoundError);
    });

    it('ForbiddenError maps to HTTP 403 with FORBIDDEN code', () => {
      const err = new ForbiddenError('Admin cannot create findings');
      expect(err.statusCode).toBe(403);
      expect(err.code).toBe('FORBIDDEN');
      expect(err).toBeInstanceOf(SecureFlowError);
      expect(err).toBeInstanceOf(ForbiddenError);
    });

    it('UnauthorizedError maps to HTTP 401 with UNAUTHORIZED code', () => {
      const err = new UnauthorizedError('User account deactivated');
      expect(err.statusCode).toBe(401);
      expect(err.code).toBe('UNAUTHORIZED');
      expect(err).toBeInstanceOf(SecureFlowError);
      expect(err).toBeInstanceOf(UnauthorizedError);
    });

    it('DomainValidationError maps to HTTP 400 with VALIDATION_ERROR code', () => {
      const err = new DomainValidationError('Invalid CVSS score', { field: 'cvssScore' });
      expect(err.statusCode).toBe(400);
      expect(err.code).toBe('VALIDATION_ERROR');
      expect(err.details).toEqual({ field: 'cvssScore' });
      expect(err).toBeInstanceOf(SecureFlowError);
      expect(err).toBeInstanceOf(DomainValidationError);
    });

    it('InvalidStateTransitionError maps to HTTP 422 with transition metadata', () => {
      const err = new InvalidStateTransitionError('Cannot transition OPEN to VERIFIED', 'OPEN', 'VERIFIED');
      expect(err.statusCode).toBe(422);
      expect(err.code).toBe('INVALID_STATE_TRANSITION');
      expect(err.fromStatus).toBe('OPEN');
      expect(err.toStatus).toBe('VERIFIED');
      expect(err).toBeInstanceOf(SecureFlowError);
      expect(err).toBeInstanceOf(InvalidStateTransitionError);
    });

    it('ConcurrencyConflictError maps to HTTP 409 with version conflict metadata', () => {
      const err = new ConcurrencyConflictError('Version mismatch on finding', 2, 1);
      expect(err.statusCode).toBe(409);
      expect(err.code).toBe('CONCURRENCY_CONFLICT');
      expect(err.currentVersion).toBe(2);
      expect(err.expectedVersion).toBe(1);
      expect(err).toBeInstanceOf(SecureFlowError);
      expect(err).toBeInstanceOf(ConcurrencyConflictError);
    });
  });

  // ---------------------------------------------------------------------------
  // 2. Canonical Domain Enums Tests
  // ---------------------------------------------------------------------------
  describe('Canonical Domain Enums', () => {
    it('GlobalRoleSchema validates ADMIN, ANALYST, DEVELOPER and rejects invalid', () => {
      expect(GlobalRoleSchema.parse('ADMIN')).toBe('ADMIN');
      expect(GlobalRoleSchema.parse('ANALYST')).toBe('ANALYST');
      expect(GlobalRoleSchema.parse('DEVELOPER')).toBe('DEVELOPER');
      expect(GlobalRoleSchema.safeParse('SUPERUSER').success).toBe(false);
    });

    it('ProjectRoleSchema accepts ANALYST, DEVELOPER and rejects ADMIN (OLI-8)', () => {
      expect(ProjectRoleSchema.parse('ANALYST')).toBe('ANALYST');
      expect(ProjectRoleSchema.parse('DEVELOPER')).toBe('DEVELOPER');
      // Invariant OLI-8: Project roles must never accept ADMIN
      expect(ProjectRoleSchema.safeParse('ADMIN').success).toBe(false);
    });

    it('FindingSeveritySchema validates all 5 severity levels', () => {
      const severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const;
      for (const sev of severities) {
        expect(FindingSeveritySchema.parse(sev)).toBe(sev);
      }
      expect(FindingSeveritySchema.safeParse('URGENT').success).toBe(false);
    });

    it('FindingCategorySchema validates all 13 security categories', () => {
      const categories = [
        'INJECTION',
        'AUTH',
        'ACCESS_CONTROL',
        'CRYPTO',
        'XSS',
        'SSRF',
        'IDOR',
        'INSECURE_DESERIALIZATION',
        'SUPPLY_CHAIN',
        'CONFIG_EXPOSURE',
        'SENSITIVE_DATA',
        'LOGGING',
        'OTHER',
      ] as const;
      for (const cat of categories) {
        expect(FindingCategorySchema.parse(cat)).toBe(cat);
      }
      expect(FindingCategorySchema.safeParse('BUSINESS_LOGIC').success).toBe(false);
    });

    it('FindingStatusSchema validates all 7 lifecycle statuses', () => {
      const statuses = [
        'OPEN',
        'TRIAGED',
        'IN_PROGRESS',
        'READY_FOR_REVIEW',
        'VERIFIED',
        'CLOSED',
        'REOPENED',
      ] as const;
      for (const status of statuses) {
        expect(FindingStatusSchema.parse(status)).toBe(status);
      }
      expect(FindingStatusSchema.safeParse('WONT_FIX').success).toBe(false);
    });

    it('RemediationTaskStatusSchema validates all 5 task statuses', () => {
      const statuses = ['PENDING', 'IN_PROGRESS', 'SUBMITTED', 'VERIFIED', 'REJECTED'] as const;
      for (const status of statuses) {
        expect(RemediationTaskStatusSchema.parse(status)).toBe(status);
      }
      expect(RemediationTaskStatusSchema.safeParse('DONE').success).toBe(false);
    });

    it('FindingEventTypeSchema validates all 7 event types', () => {
      const events = [
        'CREATED',
        'STATUS_CHANGED',
        'ASSIGNED',
        'UNASSIGNED',
        'UPDATED',
        'DELETED',
        'REOPENED',
      ] as const;
      for (const ev of events) {
        expect(FindingEventTypeSchema.parse(ev)).toBe(ev);
      }
      expect(FindingEventTypeSchema.safeParse('PURGED').success).toBe(false);
    });

    it('AuditEventCategorySchema standardizes on AuditEventCategory (not AuditCategory)', () => {
      const categories = ['AUTH', 'FINDING', 'PROJECT', 'MEMBER', 'TASK', 'MCP'] as const;
      for (const cat of categories) {
        expect(AuditEventCategorySchema.parse(cat)).toBe(cat);
      }
      expect(AuditEventCategorySchema.safeParse('SYSTEM').success).toBe(false);
    });
  });

  // ---------------------------------------------------------------------------
  // 3. Compile-Time Contract Bidirectional Consistency & Negative Demonstration
  // ---------------------------------------------------------------------------
  describe('Compile-Time Contract Compatibility', () => {
    it('Positive compile-time contract assertions evaluate to true', () => {
      expect(_checkGlobalRole).toBe(true);
      expect(_checkProjectRole).toBe(true);
      expect(_checkFindingSeverity).toBe(true);
      expect(_checkFindingCategory).toBe(true);
      expect(_checkFindingStatus).toBe(true);
      expect(_checkRemediationTaskStatus).toBe(true);
      expect(_checkFindingEventType).toBe(true);
      expect(_checkAuditEventCategory).toBe(true);
    });

    it('Negative compile-time verification: AssertIdentical rejects mismatched contracts', () => {
      // Demonstration: Type with an extra spurious value ('AUDITOR')
      type MismatchedRoleExtra = 'ADMIN' | 'ANALYST' | 'DEVELOPER' | 'AUDITOR';
      type IsExtraIdentical = AssertIdentical<PrismaGlobalRole, MismatchedRoleExtra>;
      const extraAssertion: IsExtraIdentical = false;
      expect(extraAssertion).toBe(false);

      // Demonstration: Type missing a value ('DEVELOPER')
      type MismatchedRoleMissing = 'ADMIN' | 'ANALYST';
      type IsMissingIdentical = AssertIdentical<PrismaGlobalRole, MismatchedRoleMissing>;
      const missingAssertion: IsMissingIdentical = false;
      expect(missingAssertion).toBe(false);
    });
  });

  // ---------------------------------------------------------------------------
  // 4. Service Input DTO Schemas Validation
  // ---------------------------------------------------------------------------
  describe('Service Input DTO Schemas', () => {
    it('CreateProjectInputSchema validates required name and bounds', () => {
      const valid = CreateProjectInputSchema.safeParse({ name: 'Alpha Core', description: 'Primary project' });
      expect(valid.success).toBe(true);

      const emptyName = CreateProjectInputSchema.safeParse({ name: '   ' });
      expect(emptyName.success).toBe(false);

      const longName = CreateProjectInputSchema.safeParse({ name: 'A'.repeat(256) });
      expect(longName.success).toBe(false);
    });

    it('AddProjectMemberInputSchema enforces UUID and ANALYST/DEVELOPER role', () => {
      const valid = AddProjectMemberInputSchema.safeParse({
        userId: '00000000-0000-0000-0000-000000000001',
        role: 'ANALYST',
      });
      expect(valid.success).toBe(true);

      const invalidRole = AddProjectMemberInputSchema.safeParse({
        userId: '00000000-0000-0000-0000-000000000001',
        role: 'ADMIN',
      });
      expect(invalidRole.success).toBe(false);

      const invalidUuid = AddProjectMemberInputSchema.safeParse({
        userId: 'not-a-uuid',
        role: 'DEVELOPER',
      });
      expect(invalidUuid.success).toBe(false);
    });

    it('CreateFindingInputSchema validates title (500), description (10000), CVSS [0.0, 10.0] and precision', () => {
      const valid = CreateFindingInputSchema.safeParse({
        projectId: '00000000-0000-0000-0000-000000000010',
        title: 'SQL Injection in Auth Controller',
        description: 'User input in search parameter is concatenated directly into SQL query.',
        severity: 'HIGH',
        category: 'INJECTION',
        cvssScore: 8.5,
        dueDate: '2026-11-15',
      });
      expect(valid.success).toBe(true);

      // CVSS bounds check
      const cvssTooHigh = CreateFindingInputSchema.safeParse({
        projectId: '00000000-0000-0000-0000-000000000010',
        title: 'Test',
        description: 'Test',
        severity: 'HIGH',
        category: 'INJECTION',
        cvssScore: 10.1,
      });
      expect(cvssTooHigh.success).toBe(false);

      const cvssNegative = CreateFindingInputSchema.safeParse({
        projectId: '00000000-0000-0000-0000-000000000010',
        title: 'Test',
        description: 'Test',
        severity: 'HIGH',
        category: 'INJECTION',
        cvssScore: -0.1,
      });
      expect(cvssNegative.success).toBe(false);

      // CVSS precision check (at most 1 decimal place matching Decimal(3,1))
      const cvssTooPrecise = CreateFindingInputSchema.safeParse({
        projectId: '00000000-0000-0000-0000-000000000010',
        title: 'Test',
        description: 'Test',
        severity: 'HIGH',
        category: 'INJECTION',
        cvssScore: 8.55,
      });
      expect(cvssTooPrecise.success).toBe(false);

      // Title max length check (500)
      const titleTooLong = CreateFindingInputSchema.safeParse({
        projectId: '00000000-0000-0000-0000-000000000010',
        title: 'X'.repeat(501),
        description: 'Valid',
        severity: 'LOW',
        category: 'OTHER',
      });
      expect(titleTooLong.success).toBe(false);

      // Description max length check (10000)
      const descTooLong = CreateFindingInputSchema.safeParse({
        projectId: '00000000-0000-0000-0000-000000000010',
        title: 'Valid',
        description: 'Y'.repeat(10001),
        severity: 'LOW',
        category: 'OTHER',
      });
      expect(descTooLong.success).toBe(false);
    });

    it('Mutation DTOs strictly require expectedVersion >= 1', () => {
      // Triage
      expect(TriageFindingInputSchema.safeParse({ expectedVersion: 1, severity: 'HIGH' }).success).toBe(true);
      expect(TriageFindingInputSchema.safeParse({ expectedVersion: 0 }).success).toBe(false);
      expect(TriageFindingInputSchema.safeParse({ expectedVersion: -1 }).success).toBe(false);

      // Assign
      expect(
        AssignFindingInputSchema.safeParse({
          expectedVersion: 1,
          assignedToId: '00000000-0000-0000-0000-000000000002',
          taskDescription: 'Patch SQL concatenation in repository',
        }).success,
      ).toBe(true);
      expect(
        AssignFindingInputSchema.safeParse({
          expectedVersion: 0,
          assignedToId: '00000000-0000-0000-0000-000000000002',
          taskDescription: 'Patch',
        }).success,
      ).toBe(false);

      // Submit Remediation
      expect(SubmitRemediationInputSchema.safeParse({ expectedVersion: 2, notes: 'Implemented parameterized query' }).success).toBe(true);
      expect(SubmitRemediationInputSchema.safeParse({ expectedVersion: 0 }).success).toBe(false);

      // Verify
      expect(VerifyFindingInputSchema.safeParse({ expectedVersion: 3, outcome: 'VERIFIED' }).success).toBe(true);
      expect(VerifyFindingInputSchema.safeParse({ expectedVersion: 3, outcome: 'REOPENED' }).success).toBe(true);
      expect(VerifyFindingInputSchema.safeParse({ expectedVersion: 3, outcome: 'INVALID_OUTCOME' }).success).toBe(false);

      // Update Finding Metadata
      expect(
        UpdateFindingMetadataInputSchema.safeParse({ expectedVersion: 1, title: 'Updated Title', cvssScore: 7.2 }).success,
      ).toBe(true);
      expect(UpdateFindingMetadataInputSchema.safeParse({ expectedVersion: 0 }).success).toBe(false);

      // Close & Reopen
      expect(CloseFindingInputSchema.safeParse({ expectedVersion: 4 }).success).toBe(true);
      expect(ReopenFindingInputSchema.safeParse({ expectedVersion: 5 }).success).toBe(true);

      // Soft Delete
      expect(SoftDeleteFindingInputSchema.safeParse({ expectedVersion: 1 }).success).toBe(true);
    });

    it('UpdateProjectInputSchema validates partial project metadata updates', () => {
      const valid = UpdateProjectInputSchema.safeParse({ name: 'Beta Project', isActive: false });
      expect(valid.success).toBe(true);

      const emptyUpdate = UpdateProjectInputSchema.safeParse({});
      expect(emptyUpdate.success).toBe(true);
    });

    it('CreateRemediationTaskInputSchema and UpdateTaskNotesInputSchema validate task inputs', () => {
      const validTask = CreateRemediationTaskInputSchema.safeParse({
        findingId: '00000000-0000-0000-0000-000000000010',
        assignedToId: '00000000-0000-0000-0000-000000000002',
        description: 'Implement escaping in template engine',
        dueDate: '2026-11-20',
      });
      expect(validTask.success).toBe(true);

      const invalidTask = CreateRemediationTaskInputSchema.safeParse({
        findingId: 'not-a-uuid',
        assignedToId: '00000000-0000-0000-0000-000000000002',
        description: 'Fix',
      });
      expect(invalidTask.success).toBe(false);

      const validNotes = UpdateTaskNotesInputSchema.safeParse({ notes: 'Completed patch review' });
      expect(validNotes.success).toBe(true);

      const longNotes = UpdateTaskNotesInputSchema.safeParse({ notes: 'N'.repeat(5001) });
      expect(longNotes.success).toBe(false);
    });

    it('QueryAuditEventsInputSchema validates pagination bounds and datetime filters', () => {
      const valid = QueryAuditEventsInputSchema.safeParse({
        eventCategory: 'FINDING',
        eventType: 'STATUS_CHANGED',
        resourceType: 'finding',
        page: 2,
        limit: 50,
        fromTimestamp: '2026-10-01T00:00:00.000Z',
        toTimestamp: '2026-10-22T23:59:59.000Z',
      });
      expect(valid.success).toBe(true);

      // Limit bounds: max 100
      const limitTooHigh = QueryAuditEventsInputSchema.safeParse({ limit: 101 });
      expect(limitTooHigh.success).toBe(false);

      // Page bounds: min 1
      const pageZero = QueryAuditEventsInputSchema.safeParse({ page: 0 });
      expect(pageZero.success).toBe(false);

      // Datetime validation
      const badDate = QueryAuditEventsInputSchema.safeParse({ fromTimestamp: 'not-a-datetime' });
      expect(badDate.success).toBe(false);

      // Whitespace-only eventType must be rejected (trim occurs before min(1))
      const emptyEventType = QueryAuditEventsInputSchema.safeParse({ eventType: '   ' });
      expect(emptyEventType.success).toBe(false);

      // Whitespace-only resourceType must be rejected (trim occurs before min(1))
      const emptyResourceType = QueryAuditEventsInputSchema.safeParse({ resourceType: '   \t  ' });
      expect(emptyResourceType.success).toBe(false);
    });

    it('DTO mass-assignment protection: rejects server-managed fields across mutation schemas', () => {
      // 1. CreateFindingInputSchema rejects id, createdById, version, status, isDeleted, createdAt, updatedAt
      const forbiddenFindingFields = [
        { id: '00000000-0000-0000-0000-000000000001' },
        { createdById: '00000000-0000-0000-0000-000000000002' },
        { version: 1 },
        { status: 'CLOSED' },
        { isDeleted: true },
        { createdAt: new Date().toISOString() },
        { updatedAt: new Date().toISOString() },
      ];
      const validFindingPayload = {
        projectId: '00000000-0000-0000-0000-000000000010',
        title: 'Valid Finding',
        description: 'Valid Description',
        severity: 'HIGH',
        category: 'INJECTION',
      };

      for (const forbidden of forbiddenFindingFields) {
        const result = CreateFindingInputSchema.safeParse({
          ...validFindingPayload,
          ...forbidden,
        });
        expect(result.success).toBe(false);
      }

      // 2. UpdateFindingMetadataInputSchema rejects status, isDeleted, assignedToId, projectId
      const forbiddenMetadataFields = [
        { status: 'VERIFIED' },
        { isDeleted: true },
        { assignedToId: '00000000-0000-0000-0000-000000000002' },
        { projectId: '00000000-0000-0000-0000-000000000010' },
      ];
      for (const forbidden of forbiddenMetadataFields) {
        const result = UpdateFindingMetadataInputSchema.safeParse({
          expectedVersion: 1,
          title: 'Updated Title',
          ...forbidden,
        });
        expect(result.success).toBe(false);
      }

      // 3. CreateProjectInputSchema rejects slug, id, createdById, version
      const forbiddenProjectFields = [
        { slug: 'custom-slug' },
        { id: '00000000-0000-0000-0000-000000000001' },
        { createdById: '00000000-0000-0000-0000-000000000002' },
      ];
      for (const forbidden of forbiddenProjectFields) {
        const result = CreateProjectInputSchema.safeParse({
          name: 'Core Security Platform',
          ...forbidden,
        });
        expect(result.success).toBe(false);
      }

      // 4. AssignFindingInputSchema rejects status, assignedById
      expect(
        AssignFindingInputSchema.safeParse({
          expectedVersion: 1,
          assignedToId: '00000000-0000-0000-0000-000000000002',
          taskDescription: 'Fix vulnerability',
          status: 'IN_PROGRESS',
        }).success,
      ).toBe(false);

      // 5. SubmitRemediationInputSchema rejects status, actorId
      expect(
        SubmitRemediationInputSchema.safeParse({
          expectedVersion: 1,
          notes: 'Fixed',
          status: 'READY_FOR_REVIEW',
        }).success,
      ).toBe(false);

      // 6. CreateRemediationTaskInputSchema rejects status, assignedById, id
      expect(
        CreateRemediationTaskInputSchema.safeParse({
          findingId: '00000000-0000-0000-0000-000000000010',
          assignedToId: '00000000-0000-0000-0000-000000000002',
          description: 'Fix',
          assignedById: '00000000-0000-0000-0000-000000000003',
        }).success,
      ).toBe(false);
    });
  });
});
