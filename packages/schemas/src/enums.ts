import { z } from 'zod';

/**
 * Global User Role Enumeration.
 * Coarse-grained platform access governance.
 */
export const GlobalRoleSchema = z.enum(['ADMIN', 'ANALYST', 'DEVELOPER']);
export type GlobalRole = z.infer<typeof GlobalRoleSchema>;

/**
 * Project-Scoped Membership Role Enumeration.
 * Fine-grained per-project authorization.
 * Note: Admin does not participate in project_members.
 */
export const ProjectRoleSchema = z.enum(['ANALYST', 'DEVELOPER']);
export type ProjectRole = z.infer<typeof ProjectRoleSchema>;

/**
 * Finding Severity Enumeration.
 */
export const FindingSeveritySchema = z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']);
export type FindingSeverity = z.infer<typeof FindingSeveritySchema>;

/**
 * Finding Security Category Enumeration.
 */
export const FindingCategorySchema = z.enum([
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
]);
export type FindingCategory = z.infer<typeof FindingCategorySchema>;

/**
 * Finding Status Lifecycle State Machine Enumeration.
 */
export const FindingStatusSchema = z.enum([
  'OPEN',
  'TRIAGED',
  'IN_PROGRESS',
  'READY_FOR_REVIEW',
  'VERIFIED',
  'CLOSED',
  'REOPENED',
]);
export type FindingStatus = z.infer<typeof FindingStatusSchema>;

/**
 * Remediation Task Lifecycle Status Enumeration.
 */
export const RemediationTaskStatusSchema = z.enum([
  'PENDING',
  'IN_PROGRESS',
  'SUBMITTED',
  'VERIFIED',
  'REJECTED',
]);
export type RemediationTaskStatus = z.infer<typeof RemediationTaskStatusSchema>;

/**
 * Finding Event Type Enumeration.
 * Immutable audit trail for finding lifecycle state transitions.
 */
export const FindingEventTypeSchema = z.enum([
  'CREATED',
  'STATUS_CHANGED',
  'ASSIGNED',
  'UNASSIGNED',
  'UPDATED',
  'DELETED',
  'REOPENED',
]);
export type FindingEventType = z.infer<typeof FindingEventTypeSchema>;

/**
 * Audit Event Category Enumeration.
 * Standardized across data model and application layers.
 */
export const AuditEventCategorySchema = z.enum([
  'AUTH',
  'FINDING',
  'PROJECT',
  'MEMBER',
  'TASK',
  'MCP',
]);
export type AuditEventCategory = z.infer<typeof AuditEventCategorySchema>;
