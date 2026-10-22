/**
 * Compile-Time Bidirectional Enum Consistency Verification.
 *
 * This file verifies that the canonical Zod enums defined in `@secureflow/schemas`
 * and the Prisma ORM 7 generated enums in `packages/domain/src/generated/prisma/enums.js`
 * remain 100% identical in their accepted string literal sets.
 *
 * If either side adds, removes, or misspells an enum member, this file causes an immediate
 * TypeScript compilation failure (Type 'false' is not assignable to type 'true').
 *
 * This guarantees contract consistency across tiers without creating a forbidden runtime
 * reverse dependency from `@secureflow/schemas` to `@secureflow/domain`.
 */

import type {
  GlobalRole as PrismaGlobalRole,
  ProjectRole as PrismaProjectRole,
  FindingSeverity as PrismaFindingSeverity,
  FindingCategory as PrismaFindingCategory,
  FindingStatus as PrismaFindingStatus,
  RemediationTaskStatus as PrismaRemediationTaskStatus,
  FindingEventType as PrismaFindingEventType,
  AuditEventCategory as PrismaAuditEventCategory,
} from './generated/prisma/enums.js';

import type {
  GlobalRole as SchemasGlobalRole,
  ProjectRole as SchemasProjectRole,
  FindingSeverity as SchemasFindingSeverity,
  FindingCategory as SchemasFindingCategory,
  FindingStatus as SchemasFindingStatus,
  RemediationTaskStatus as SchemasRemediationTaskStatus,
  FindingEventType as SchemasFindingEventType,
  AuditEventCategory as SchemasAuditEventCategory,
} from '@secureflow/schemas';

/**
 * Type-level equality assertion.
 * Evaluates to `true` if and only if types A and B are mutually assignable.
 */
export type AssertIdentical<A, B> = [A] extends [B] ? ([B] extends [A] ? true : false) : false;

// 1. GlobalRole assertion
export const _checkGlobalRole: AssertIdentical<PrismaGlobalRole, SchemasGlobalRole> = true;

// 2. ProjectRole assertion
export const _checkProjectRole: AssertIdentical<PrismaProjectRole, SchemasProjectRole> = true;

// 3. FindingSeverity assertion
export const _checkFindingSeverity: AssertIdentical<PrismaFindingSeverity, SchemasFindingSeverity> = true;

// 4. FindingCategory assertion
export const _checkFindingCategory: AssertIdentical<PrismaFindingCategory, SchemasFindingCategory> = true;

// 5. FindingStatus assertion
export const _checkFindingStatus: AssertIdentical<PrismaFindingStatus, SchemasFindingStatus> = true;

// 6. RemediationTaskStatus assertion
export const _checkRemediationTaskStatus: AssertIdentical<PrismaRemediationTaskStatus, SchemasRemediationTaskStatus> = true;

// 7. FindingEventType assertion
export const _checkFindingEventType: AssertIdentical<PrismaFindingEventType, SchemasFindingEventType> = true;

// 8. AuditEventCategory assertion (verifies AuditEventCategory vs AuditCategory consistency)
export const _checkAuditEventCategory: AssertIdentical<PrismaAuditEventCategory, SchemasAuditEventCategory> = true;
