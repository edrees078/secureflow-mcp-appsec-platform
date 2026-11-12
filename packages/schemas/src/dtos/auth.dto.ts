import { z } from 'zod';
import { GlobalRoleSchema } from '../enums.js';
import { UuidSchema } from './common.js';

/**
 * Validates that a post-login returnTo destination is strictly a safe,
 * internal relative path starting with a single `/` and not `//` or containing
 * backslashes or control characters (preventing open redirects).
 */
export const RelativeReturnToPathSchema = z
  .string()
  .trim()
  .min(1, 'Return path cannot be empty')
  .max(500, 'Return path cannot exceed 500 characters')
  .refine(
    (val) =>
      val.startsWith('/') &&
      !val.startsWith('//') &&
      !val.includes('\\') &&
      !/[\x00-\x1f\x7f]/.test(val),
    'Return path must be a safe internal relative path starting with a single "/"'
  );

/**
 * Input DTO for creating an OIDC authorization transaction.
 */
export const CreateOidcTransactionInputSchema = z
  .object({
    returnTo: RelativeReturnToPathSchema.optional().default('/'),
    ttlSeconds: z.number().int().min(30).max(900).optional().default(300),
  })
  .strict();
export type CreateOidcTransactionInput = z.infer<typeof CreateOidcTransactionInputSchema>;

/**
 * Input DTO for atomically consuming a single-use OIDC transaction during callback.
 */
export const ConsumeOidcTransactionInputSchema = z
  .object({
    rawTxnToken: z.string().trim().min(16, 'Transaction token is required').max(512),
    state: z.string().trim().min(16, 'OIDC state parameter is required').max(512),
    ipAddress: z.string().trim().max(45).nullable().optional(),
    userAgent: z.string().trim().max(500).nullable().optional(),
  })
  .strict();
export type ConsumeOidcTransactionInput = z.infer<typeof ConsumeOidcTransactionInputSchema>;

/**
 * Input DTO representing a verified OIDC identity returned by the IdP token/ID-token exchange.
 * Any `realmRoles` or external group claims included in the payload are ignored for authorization
 * by SecureFlow's strict least-privilege JIT provisioning model.
 */
export const VerifiedOidcIdentityInputSchema = z
  .object({
    sub: z.string().trim().min(1, 'OIDC sub claim is required').max(255),
    email: z.string().trim().email('Valid email claim is required').max(255),
    emailVerified: z.boolean(),
    displayName: z.string().trim().min(1).max(255).optional(),
    oidcSid: z.string().trim().min(1).max(255).nullable().optional(),
    realmRoles: z.array(z.string()).optional(),
    ipAddress: z.string().trim().max(45).nullable().optional(),
    userAgent: z.string().trim().max(500).nullable().optional(),
    idleTimeoutSeconds: z.number().int().min(60).max(86400).optional().default(1800),
    absoluteTimeoutSeconds: z.number().int().min(300).max(604800).optional().default(28800),
  })
  .strict();
export type VerifiedOidcIdentityInput = z.infer<typeof VerifiedOidcIdentityInputSchema>;

/**
 * Input DTO for resolving an opaque session token into an authoritative ActorContext.
 */
export const ResolveSessionInputSchema = z
  .object({
    rawSessionToken: z.string().trim().min(16, 'Session token is required').max(512),
  })
  .strict();
export type ResolveSessionInput = z.infer<typeof ResolveSessionInputSchema>;

/**
 * Input DTO for revoking a single opaque session token (e.g. during logout).
 */
export const RevokeSessionInputSchema = z
  .object({
    rawSessionToken: z.string().trim().min(16, 'Session token is required').max(512),
    reason: z.string().trim().min(1).max(100).optional().default('USER_LOGOUT'),
    ipAddress: z.string().trim().max(45).nullable().optional(),
    userAgent: z.string().trim().max(500).nullable().optional(),
  })
  .strict();
export type RevokeSessionInput = z.infer<typeof RevokeSessionInputSchema>;

/**
 * Input DTO for deterministic, concurrent-safe initial Admin bootstrap.
 */
export const BootstrapInitialAdminInputSchema = z
  .object({
    issuer: z.string().trim().url('Valid OIDC issuer URL is required').max(500),
    expectedIssuer: z.string().trim().url('Valid expected OIDC issuer URL is required').max(500),
    sub: z.string().trim().min(1, 'OIDC sub is required').max(255),
    expectedSub: z.string().trim().min(1, 'Expected bootstrap OIDC sub is required').max(255),
    email: z.string().trim().email('Valid email is required').max(255),
    displayName: z.string().trim().min(1).max(255).optional(),
    justification: z
      .string()
      .trim()
      .min(5, 'Bootstrap justification must be at least 5 characters')
      .max(1000)
      .optional()
      .default('Initial Global Admin bootstrap via verified OIDC subject'),
    ipAddress: z.string().trim().max(45).nullable().optional(),
    userAgent: z.string().trim().max(500).nullable().optional(),
  })
  .strict();
export type BootstrapInitialAdminInput = z.infer<typeof BootstrapInitialAdminInputSchema>;

/**
 * Input DTO for Global Admin updates to a user's global role.
 */
export const UpdateUserGlobalRoleInputSchema = z
  .object({
    globalRole: GlobalRoleSchema,
    justification: z
      .string()
      .trim()
      .min(5, 'Role update justification must be at least 5 characters')
      .max(1000),
    ipAddress: z.string().trim().max(45).nullable().optional(),
    userAgent: z.string().trim().max(500).nullable().optional(),
  })
  .strict();
export type UpdateUserGlobalRoleInput = z.infer<typeof UpdateUserGlobalRoleInputSchema>;

/**
 * Input DTO for Global Admin deactivation of a user account.
 */
export const DeactivateUserInputSchema = z
  .object({
    justification: z
      .string()
      .trim()
      .min(5, 'Deactivation justification must be at least 5 characters')
      .max(1000),
    ipAddress: z.string().trim().max(45).nullable().optional(),
    userAgent: z.string().trim().max(500).nullable().optional(),
  })
  .strict();
export type DeactivateUserInput = z.infer<typeof DeactivateUserInputSchema>;

/**
 * Sanctioned failure reasons for `auth.login_failed` security audit telemetry.
 */
export const AuthFailureReasonSchema = z.enum([
  'MISSING_OR_EXPIRED_OIDC_TRANSACTION',
  'OIDC_STATE_MISMATCH',
  'OIDC_NONCE_MISMATCH',
  'OIDC_TOKEN_EXCHANGE_FAILED',
  'EMAIL_NOT_VERIFIED',
  'EMAIL_SUB_CONFLICT',
  'USER_DEACTIVATED',
  'INVALID_BOOTSTRAP_CREDENTIALS',
  'INITIAL_ADMIN_ALREADY_EXISTS',
]);
export type AuthFailureReason = z.infer<typeof AuthFailureReasonSchema>;

/**
 * Input DTO for separate, rollback-safe failed authentication audit recording.
 */
export const RecordAuthFailureInputSchema = z
  .object({
    reason: AuthFailureReasonSchema,
    actorId: UuidSchema.nullable().optional().default(null),
    resourceUserId: UuidSchema.nullable().optional().default(null),
    ipAddress: z.string().trim().max(45).nullable().optional().default(null),
    userAgent: z.string().trim().max(500).nullable().optional().default(null),
    metadata: z.record(z.string(), z.unknown()).optional().default({}),
  })
  .strict();
export type RecordAuthFailureInput = z.infer<typeof RecordAuthFailureInputSchema>;
