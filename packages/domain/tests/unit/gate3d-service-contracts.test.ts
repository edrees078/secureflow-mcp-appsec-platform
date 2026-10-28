import { describe, it, expect } from 'vitest';
import {
  FindingService,
  ActorContext,
} from '../../src/index.js';
import * as DomainRoot from '../../src/index.js';
import * as DomainTesting from '../../src/testing/index.js';
import {
  createSyntheticActorContext,
  createTestAdminActor,
  createTestAnalystActor,
  createTestDeveloperActor,
} from '../../src/testing/index.js';
import {
  VerifyFindingInputSchema,
  UpdateTaskNotesInputSchema,
  QueryAuditEventsInputSchema,
  FindingEventTypeSchema,
  AuditEventCategorySchema,
  ForceCloseFindingInputSchema,
  ForceReopenFindingInputSchema,
} from '@secureflow/schemas';

describe('Gate 3D.1 — Service Contracts & Trust Boundaries (Unit Tests)', () => {
  describe('1. Trust Boundary Isolation & Testing Subpath', () => {
    it('Root @secureflow/domain export MUST NOT include createSyntheticActorContext', () => {
      // Cast to Record<string, unknown> to verify absence of synthetic testing helper
      const rootExports = DomainRoot as unknown as Record<string, unknown>;
      expect(rootExports['createSyntheticActorContext']).toBeUndefined();
      expect('createSyntheticActorContext' in DomainRoot).toBe(false);
    });

    it('@secureflow/domain/testing MUST export createSyntheticActorContext and test persona factories', () => {
      expect(typeof DomainTesting.createSyntheticActorContext).toBe('function');
      expect(typeof DomainTesting.createTestAdminActor).toBe('function');
      expect(typeof DomainTesting.createTestAnalystActor).toBe('function');
      expect(typeof DomainTesting.createTestDeveloperActor).toBe('function');
    });

    it('Synthetic test actor factories construct valid, deterministic ActorContext instances', () => {
      const admin = createTestAdminActor();
      expect(admin).toBeInstanceOf(ActorContext);
      expect(admin.isAdmin()).toBe(true);
      expect(admin.globalRole).toBe('ADMIN');
      expect(admin.isActive).toBe(true);

      const projectId = '00000000-0000-0000-0000-000000000099';
      const analyst = createTestAnalystActor(projectId);
      expect(analyst.isAnalyst()).toBe(true);
      expect(analyst.hasProjectRole(projectId, 'ANALYST')).toBe(true);
      expect(analyst.isMemberOf(projectId)).toBe(true);

      const dev = createTestDeveloperActor(projectId);
      expect(dev.isDeveloper()).toBe(true);
      expect(dev.hasProjectRole(projectId, 'DEVELOPER')).toBe(true);
      expect(dev.isMemberOf(projectId)).toBe(true);
    });

    it('createSyntheticActorContext instantiates deterministic context with provided params', () => {
      const synthetic = createSyntheticActorContext({
        id: '12345678-1234-1234-1234-123456789012',
        globalRole: 'ANALYST',
        isActive: true,
        memberships: [
          {
            projectId: '11111111-2222-3333-4444-555555555555',
            role: 'ANALYST',
          },
        ],
      });
      expect(synthetic.id).toBe('12345678-1234-1234-1234-123456789012');
      expect(synthetic.hasProjectRole('11111111-2222-3333-4444-555555555555', 'ANALYST')).toBe(true);
    });
  });

  describe('2. Service Interface & FindingService Reconciled Stubs (100% Authorized)', () => {
    it('FindingService has NO actorless methods; all operations require ActorContext', () => {
      const service = new FindingService();
      const servicePrototype = Object.getPrototypeOf(service);

      // Verify absence of legacy unauthenticated / actorless methods
      expect('getFindingById' in servicePrototype).toBe(false);
      expect('reopenFinding' in servicePrototype).toBe(false);

      // Verify presence of authorized IFindingService methods
      expect(typeof service.createFinding).toBe('function');
      expect(typeof service.getFinding).toBe('function');
      expect(typeof service.listFindings).toBe('function');
      expect(typeof service.triageFinding).toBe('function');
      expect(typeof service.assignFinding).toBe('function');
      expect(typeof service.submitRemediation).toBe('function');
      expect(typeof service.verifyFinding).toBe('function');
      expect(typeof service.confirmVerification).toBe('function');
      expect(typeof service.rejectVerification).toBe('function');
      expect(typeof service.closeFinding).toBe('function');
      expect(typeof service.forceCloseFinding).toBe('function');
      expect(typeof service.forceReopenFinding).toBe('function');
      expect(typeof service.updateFindingMetadata).toBe('function');
      expect(typeof service.softDeleteFinding).toBe('function');
    });

    it('Transactional IFindingService methods throw NOT_IMPLEMENTED (501) stubs during Sub-Gate 3D.1', async () => {
      const service = new FindingService();
      const actor = createTestAdminActor();
      const findingId = '11111111-1111-1111-1111-111111111111';

      await expect(service.createFinding(actor, {
        projectId: '22222222-2222-2222-2222-222222222222',
        title: 'SQL Injection in Login',
        description: 'Vulnerable query parameter',
        severity: 'CRITICAL',
        category: 'INJECTION',
      })).rejects.toThrowError(/NOT_IMPLEMENTED/);

      await expect(service.getFinding(actor, findingId))
        .rejects.toThrowError(/NOT_IMPLEMENTED/);

      await expect(service.listFindings(actor))
        .rejects.toThrowError(/NOT_IMPLEMENTED/);

      await expect(service.triageFinding(actor, findingId, { expectedVersion: 1 }))
        .rejects.toThrowError(/NOT_IMPLEMENTED/);

      await expect(service.assignFinding(actor, findingId, {
        expectedVersion: 1,
        assignedToId: '00000000-0000-0000-0000-000000000003',
        taskDescription: 'Fix SQL injection parameterization',
      })).rejects.toThrowError(/NOT_IMPLEMENTED/);

      await expect(service.submitRemediation(actor, findingId, { expectedVersion: 1 }))
        .rejects.toThrowError(/NOT_IMPLEMENTED/);

      await expect(service.verifyFinding(actor, findingId, { expectedVersion: 1, outcome: 'VERIFIED' }))
        .rejects.toThrowError(/NOT_IMPLEMENTED/);

      await expect(service.closeFinding(actor, findingId, { expectedVersion: 1 }))
        .rejects.toThrowError(/NOT_IMPLEMENTED/);

      await expect(service.forceCloseFinding(actor, findingId, { expectedVersion: 1, justification: 'Unactionable false positive' }))
        .rejects.toThrowError(/NOT_IMPLEMENTED/);

      await expect(service.forceReopenFinding(actor, findingId, { expectedVersion: 1, justification: 'Regressed in production' }))
        .rejects.toThrowError(/NOT_IMPLEMENTED/);

      await expect(service.updateFindingMetadata(actor, findingId, { expectedVersion: 1, title: 'Updated title' }))
        .rejects.toThrowError(/NOT_IMPLEMENTED/);

      await expect(service.softDeleteFinding(actor, findingId, { expectedVersion: 1 }))
        .rejects.toThrowError(/NOT_IMPLEMENTED/);
    });

    it('confirmVerification and rejectVerification delegate to verifyFinding with corresponding outcomes', async () => {
      const service = new FindingService();
      const actor = createTestAnalystActor('22222222-2222-2222-2222-222222222222');
      const findingId = '11111111-1111-1111-1111-111111111111';

      await expect(service.confirmVerification(actor, findingId, { expectedVersion: 1 }))
        .rejects.toThrowError(/NOT_IMPLEMENTED/);

      await expect(service.rejectVerification(actor, findingId, { expectedVersion: 1 }))
        .rejects.toThrowError(/NOT_IMPLEMENTED/);
    });
  });

  describe('3. Database Enum Reconciliation (No Invented Members)', () => {
    it('FindingEventType strictly conforms to the 7 approved enum members in schema.prisma', () => {
      const approvedValues = [
        'CREATED',
        'STATUS_CHANGED',
        'ASSIGNED',
        'UNASSIGNED',
        'UPDATED',
        'DELETED',
        'REOPENED',
      ];
      expect(FindingEventTypeSchema.options).toEqual(approvedValues);

      // Verify that previously proposed invented enum members are NOT accepted
      const inventedValues = [
        'METADATA_UPDATED',
        'REMEDIATION_SUBMITTED',
        'VERIFIED',
        'REMEDIATION_REJECTED',
        'CLOSED',
        'FORCE_CLOSED',
        'FORCE_REOPENED',
        'SOFT_DELETED',
      ];
      for (const val of inventedValues) {
        expect(FindingEventTypeSchema.safeParse(val).success).toBe(false);
      }
    });

    it('AuditEventCategory strictly conforms to the 6 approved enum members in schema.prisma', () => {
      const approvedValues = [
        'AUTH',
        'FINDING',
        'PROJECT',
        'MEMBER',
        'TASK',
        'MCP',
      ];
      expect(AuditEventCategorySchema.options).toEqual(approvedValues);

      // Verify that previously proposed invented categories are NOT accepted
      const inventedCategories = ['DATA_MUTATION', 'STATUS_CHANGE', 'DATA_ACCESS', 'SYSTEM'];
      for (const cat of inventedCategories) {
        expect(AuditEventCategorySchema.safeParse(cat).success).toBe(false);
      }
    });
  });

  describe('4. DTO Validation Reconciliation', () => {
    it('VerifyFindingInputSchema enforces expectedVersion, outcome (VERIFIED | REOPENED), and strict fields', () => {
      const validVerified = VerifyFindingInputSchema.safeParse({
        expectedVersion: 1,
        outcome: 'VERIFIED',
        notes: 'Patch successfully verified in staging',
      });
      expect(validVerified.success).toBe(true);

      const validReopened = VerifyFindingInputSchema.safeParse({
        expectedVersion: 2,
        outcome: 'REOPENED',
        notes: 'Vulnerability still reproducible with payload X',
      });
      expect(validReopened.success).toBe(true);

      // Invalid outcome
      const invalidOutcome = VerifyFindingInputSchema.safeParse({
        expectedVersion: 1,
        outcome: 'CLOSED',
      });
      expect(invalidOutcome.success).toBe(false);

      // Missing expectedVersion
      const missingVersion = VerifyFindingInputSchema.safeParse({
        outcome: 'VERIFIED',
      });
      expect(missingVersion.success).toBe(false);

      // Extra unapproved fields rejected under .strict()
      const extraField = VerifyFindingInputSchema.safeParse({
        expectedVersion: 1,
        outcome: 'VERIFIED',
        unapprovedField: 'not allowed',
      });
      expect(extraField.success).toBe(false);
    });

    it('ForceCloseFindingInputSchema enforces expectedVersion, nonempty justification, and strict properties', () => {
      const valid = ForceCloseFindingInputSchema.safeParse({
        expectedVersion: 1,
        justification: 'Third-party dependency false positive confirmed by vendor errata',
      });
      expect(valid.success).toBe(true);

      // Empty justification
      expect(ForceCloseFindingInputSchema.safeParse({
        expectedVersion: 1,
        justification: '',
      }).success).toBe(false);

      // Whitespace-only justification
      expect(ForceCloseFindingInputSchema.safeParse({
        expectedVersion: 1,
        justification: '   ',
      }).success).toBe(false);

      // Overlength justification
      expect(ForceCloseFindingInputSchema.safeParse({
        expectedVersion: 1,
        justification: 'x'.repeat(5001),
      }).success).toBe(false);

      // Missing expectedVersion
      expect(ForceCloseFindingInputSchema.safeParse({
        justification: 'Valid reason',
      }).success).toBe(false);

      // Unexpected property
      expect(ForceCloseFindingInputSchema.safeParse({
        expectedVersion: 1,
        justification: 'Valid reason',
        extraProperty: true,
      }).success).toBe(false);
    });

    it('ForceReopenFindingInputSchema enforces expectedVersion, nonempty justification, and strict properties', () => {
      const valid = ForceReopenFindingInputSchema.safeParse({
        expectedVersion: 2,
        justification: 'Security regression observed following canary release',
      });
      expect(valid.success).toBe(true);

      // Empty justification
      expect(ForceReopenFindingInputSchema.safeParse({
        expectedVersion: 2,
        justification: '',
      }).success).toBe(false);

      // Whitespace-only justification
      expect(ForceReopenFindingInputSchema.safeParse({
        expectedVersion: 2,
        justification: '  \t\n  ',
      }).success).toBe(false);

      // Overlength justification
      expect(ForceReopenFindingInputSchema.safeParse({
        expectedVersion: 2,
        justification: 'y'.repeat(5001),
      }).success).toBe(false);

      // Unexpected property
      expect(ForceReopenFindingInputSchema.safeParse({
        expectedVersion: 2,
        justification: 'Valid reason',
        notes: 'legacy notes field not allowed',
      }).success).toBe(false);
    });

    it('UpdateTaskNotesInputSchema enforces notes length constraint', () => {
      const valid = UpdateTaskNotesInputSchema.safeParse({
        notes: 'Investigating database query plan and indexing options',
      });
      expect(valid.success).toBe(true);

      const overLimit = UpdateTaskNotesInputSchema.safeParse({
        notes: 'a'.repeat(5001),
      });
      expect(overLimit.success).toBe(false);
    });

    it('QueryAuditEventsInputSchema enforces approved query filters and rejects unauthorized fields like projectId', () => {
      const valid = QueryAuditEventsInputSchema.safeParse({
        eventCategory: 'FINDING',
        eventType: 'finding.status_changed',
        page: 1,
        limit: 50,
      });
      expect(valid.success).toBe(true);

      // Rejects unapproved fields (e.g. projectId) under .strict()
      const invalid = QueryAuditEventsInputSchema.safeParse({
        eventCategory: 'FINDING',
        projectId: '00000000-0000-0000-0000-000000000001',
      });
      expect(invalid.success).toBe(false);
    });
  });
});
