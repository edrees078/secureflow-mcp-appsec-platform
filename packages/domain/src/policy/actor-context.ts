import type { GlobalRole, ProjectRole } from '@secureflow/schemas';

/**
 * Membership record associating an actor with a specific project and project-level role.
 * Invariant OLI-8: Project-level role must be ANALYST or DEVELOPER; no project-level ADMIN exists.
 */
export interface ProjectMembership {
  readonly projectId: string;
  readonly role: ProjectRole;
}

export interface ActorContextParams {
  readonly id: string;
  readonly globalRole: GlobalRole;
  readonly isActive: boolean;
  readonly memberships?: readonly ProjectMembership[] | ReadonlyMap<string, ProjectRole>;
}

/**
 * Internal Domain Authorization Actor Context.
 *
 * Security Boundary & Trust Model:
 * 1. NOT AUTHENTICATION PROOF:
 *    Possession of an ActorContext instance is an internal authorization context, NOT authentication proof.
 *    It must never be constructed directly from untrusted client transport input (HTTP request bodies,
 *    query parameters, or client-controlled headers like x-user-id or x-role).
 *
 * 2. PRODUCTION CONSTRUCTION STRATEGY (Phase 4):
 *    In production runtime, ActorContext must ONLY be constructed by authenticated server-side middleware:
 *    - Step A: Verify OIDC / Keycloak Bearer JWT (RS256 signature, expiry, audience, issuer).
 *    - Step B: Authoritative Database User Check: Look up user in PostgreSQL `users` table via `sub` to
 *      retrieve authoritative `globalRole` and `isActive` status. Never trust client-asserted roles.
 *    - Step C: Authoritative Database Membership Check: Query PostgreSQL `project_members` table to
 *      derive current active memberships. Client-supplied project IDs must NEVER grant membership.
 *
 * 3. AUTHORIZATION FRESHNESS CONTRACT & GATE 3D CONCURRENT-REVOCATION REQUIREMENTS:
 *    - ActorContext is an immutable point-in-time value snapshot.
 *    - Rebuilding ActorContext at a request boundary prevents cross-request reuse of stale membership data.
 *    - An ActorContext instance does not automatically invalidate if a database membership is revoked
 *      after instantiation. Therefore, caching or reusing ActorContext instances across requests
 *      without database re-validation is strictly prohibited.
 *    - Rechecking membership inside a transaction is necessary.
 *    - A simple membership SELECT under default READ COMMITTED does not automatically prevent membership
 *      revocation from racing with a subsequent mutation (e.g. member removed in concurrent transaction T2
 *      right after SELECT in T1).
 *    - Gate 3D Implementation Requirement: The domain service layer must define the intended authorization
 *      linearization point and transaction isolation/locking strategy (e.g. SELECT FOR SHARE/UPDATE or
 *      OCC / serializable validation on project membership records).
 *    - Gate 3D Test Requirement: Concurrency tests must distinguish between:
 *      (a) Revocation committed prior to authorization evaluation, and
 *      (b) Revocation racing concurrently with an in-flight mutation transaction.
 *    - Deadlock or serialization failures must be handled safely without bypassing authorization or
 *      allowing stale writes.
 *
 * 4. SYNTHETIC ACTOR CONSTRUCTION:
 *    The ActorContext constructor and createSyntheticActorContext are provided for deterministic
 *    unit and integration testing with synthetic personas.
 */
export class ActorContext {
  public readonly id: string;
  public readonly globalRole: GlobalRole;
  public readonly isActive: boolean;
  private readonly memberships: Map<string, ProjectRole>;

  constructor(params: ActorContextParams) {
    this.id = params.id;
    this.globalRole = params.globalRole;
    this.isActive = params.isActive;
    this.memberships = new Map();

    if (params.memberships) {
      if (Array.isArray(params.memberships)) {
        for (const m of params.memberships as readonly ProjectMembership[]) {
          this.memberships.set(m.projectId, m.role);
        }
      } else {
        (params.memberships as ReadonlyMap<string, ProjectRole>).forEach((role, projectId) => {
          this.memberships.set(projectId, role);
        });
      }
    }
  }

  /**
   * Returns true if the actor has an active membership record in the specified project.
   */
  public isMemberOf(projectId: string): boolean {
    return this.memberships.has(projectId);
  }

  /**
   * Returns the actor's role in the specified project, or null if not a member.
   */
  public getRoleInProject(projectId: string): ProjectRole | null {
    return this.memberships.get(projectId) ?? null;
  }

  /**
   * Returns true if the actor holds the specific project role in the specified project.
   */
  public hasProjectRole(projectId: string, role: ProjectRole): boolean {
    return this.memberships.get(projectId) === role;
  }

  /**
   * Returns an array of all project IDs the actor is currently a member of.
   */
  public getProjectIds(): string[] {
    return Array.from(this.memberships.keys());
  }

  /**
   * Returns true if the actor holds the global ADMIN role.
   */
  public isAdmin(): boolean {
    return this.globalRole === 'ADMIN';
  }

  /**
   * Returns true if the actor holds the global ANALYST role.
   */
  public isAnalyst(): boolean {
    return this.globalRole === 'ANALYST';
  }

  /**
   * Returns true if the actor holds the global DEVELOPER role.
   */
  public isDeveloper(): boolean {
    return this.globalRole === 'DEVELOPER';
  }
}

/**
 * Creates a synthetic ActorContext instance for deterministic unit/integration testing.
 * Strictly forbidden from being used with untrusted transport inputs in production.
 */
export function createSyntheticActorContext(params: ActorContextParams): ActorContext {
  return new ActorContext(params);
}
