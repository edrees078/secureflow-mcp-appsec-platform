# Gate 3D Implementation Note: Concurrency Architecture, Lock Ordering & Freshness

**Status:** Approved Handoff Specification from Gate 3C to Gate 3D
**Applies to:** `packages/domain` Transactional Service Layer (`ProjectService`, `FindingService`, `TaskService`, `AuditService`)
**Related Documents:** [docs/02-architecture.md](../02-architecture.md) · [docs/03-data-model.md](../03-data-model.md) · [docs/04-authorization-matrix.md](../04-authorization-matrix.md)

---

## 1. Context & Motivation

During Phase 3 Gate 3C, object-level authorization policies (`ProjectPolicy`, `FindingPolicy`, `TaskPolicy`, `AuditPolicy`) and internal `ActorContext` were established. Automated integration testing against PostgreSQL confirmed:
1. Re-deriving `ActorContext` from PostgreSQL at a request boundary immediately enforces project member removal with `404 Not Found` existence hiding.
2. Conversely, reusing an unrefreshed in-memory `ActorContext` snapshot across requests fails to detect real-time database revocations (the "Stale Context Trap").

While per-request dynamic context reconstruction prevents cross-request stale cache reuse, intra-request concurrent mutations introduce potential race conditions under PostgreSQL's default `READ COMMITTED` transaction isolation level.

### 1.1 ActorContext Trust Boundary & Defense-in-Depth Responsibilities

A PostgreSQL `project_members` row-lock check establishes current membership for a user ID, but **does not authenticate the caller controlling that identity**. Database row locks alone cannot and do not reject forged actor identities.

SecureFlow strictly enforces defense-in-depth by partitioning distinct security responsibilities across layers:

1. **Cryptographic Authentication (Phase 4):**
   Keycloak OIDC verifies caller identity cryptographically via RS256 Bearer JWTs (`sub`, `iss`, `aud`, `exp`). Only transport middleware with verified tokens can initiate domain requests.
2. **Authoritative PostgreSQL Lookups:**
   Server-side middleware performs authoritative queries against PostgreSQL `users` and `project_members` tables to derive current account status (`is_active`), global role (`global_role`), and active project memberships. Client-supplied headers (e.g. `x-user-id`, `x-role`) or request-body role assertions are rejected fail-closed.
3. **Transactional Freshness Revalidation (Gate 3D):**
   Intra-transaction checks revalidate authorization-sensitive attributes (e.g., executing `SELECT ... FOR SHARE` on `project_members` or verifying `users.is_active = true`) under database locks to eliminate TOCTOU authorization races against concurrent administrative actions.
4. **Authorization Container Contract:**
   `ActorContext` is an immutable in-memory authorization-data container carrying verified identity and permissions, **not cryptographic authentication evidence**. Possession of an `ActorContext` instance does not imply caller authentication.
5. **Transport Handler Invariant:**
   Production transport handlers (Express API routes, MCP daemon handlers) must never accept caller-supplied `ActorContext` instances or arbitrary role claims. Transport handlers must reconstruct or receive `ActorContext` solely from trusted authentication middleware.
6. **Synthetic Actor Testing Isolation:**
   Synthetic actor factories (`createSyntheticActorContext`, `createTestAdminActor`, etc.) are strictly isolated to `@secureflow/domain/testing` and are forbidden in production application code by ESLint boundary rules.

---

## 2. Canonical Hierarchical Database Row Lock Ordering

To prevent deadlocks and ensure consistent serialization across concurrent transactions, all domain service operations implemented in Sub-Gates 3D.2–3D.6 must strictly adhere to the following global lock hierarchy:

$$\text{USERS (Level 0)} \longrightarrow \text{PROJECT (Level 1)} \longrightarrow \text{PROJECT\_MEMBERS (Level 2)} \longrightarrow \text{FINDINGS (Level 3)} \longrightarrow \text{REMEDIATION\_TASKS (Level 4)}$$

### Lock Acquisition Sequence by Operation Category

| Operation Category | Lock Hierarchy Sequence | Lock Modes & Coordination Mechanism |
|---|---|---|
| **Project Administration** (`updateProject`, `archiveProject`) | 1. `projects` | `SELECT id FROM projects WHERE id = $1 FOR UPDATE` |
| **Membership Addition** (`addMember`) | 1. `projects`<br>2. `project_members` | 1. `SELECT id FROM projects WHERE id = $1 FOR SHARE`<br>2. Insert into `project_members` (unique key `project_members_project_id_user_id_key` prevents race) |
| **Membership Removal** (`removeMember`) | 1. `projects`<br>2. `project_members` | 1. `SELECT id FROM projects WHERE id = $1 FOR SHARE`<br>2. `SELECT id FROM project_members WHERE project_id = $1 AND user_id = $2 FOR UPDATE`<br>3. Delete row + insert audit event |
| **Finding Mutations** (`triage`, `assign`, `verify`, `close`) | 1. `project_members`<br>2. `findings`<br>3. `remediation_tasks` | 1. `SELECT role FROM project_members WHERE project_id = $1 AND user_id = $2 FOR SHARE` (authoritative freshness check)<br>2. `UPDATE findings ... SET version = version + 1 WHERE id = $3 AND version = $4` (atomic OCC row lock)<br>3. `UPDATE remediation_tasks ... FOR UPDATE` (if task is affected) |
| **Task Progress Notes** (`updateTaskNotes`) | 1. `project_members`<br>2. `remediation_tasks` | 1. Verify finding/project; `SELECT role FROM project_members WHERE project_id = $1 AND user_id = $2 FOR SHARE`<br>2. `SELECT id FROM remediation_tasks WHERE id = $3 FOR UPDATE`<br>3. Update notes + insert audit event |
| **Multiple-Member Operations** | 1. `projects`<br>2. `project_members` | 1. `SELECT id FROM projects WHERE id = $1 FOR SHARE`<br>2. Sort all target `user_id` values in ascending lexical order: `SELECT id FROM project_members WHERE project_id = $1 AND user_id = ANY($2::uuid[]) ORDER BY user_id ASC FOR UPDATE` |
| **User Deactivation / Global Role Changes** | 1. `users`<br>2. `project_members` | 1. `SELECT id FROM users WHERE id = $1 FOR UPDATE`<br>2. Update user status / cascade membership updates |

---

## 3. Coordination of Row Locks with Concurrent Revocation (Eliminating TOCTOU)

- **Operational Row Lock:** Operational mutations (e.g. `submitRemediation`, `verifyFinding`, `updateTaskNotes`) acquire a `FOR SHARE` lock on the actor's `project_members` record within the transaction.
- **Administrative Row Lock:** Concurrent membership revocation (`removeMember`) acquires a `FOR UPDATE` lock on that same `project_members` record.
- **PostgreSQL Lock Conflicts:** In PostgreSQL, `FOR UPDATE` and `FOR SHARE` conflict:
  - If the operational mutation starts first: It holds `FOR SHARE`, blocking `removeMember` until the operational transaction commits. Authorization is verified and linearized before revocation.
  - If `removeMember` starts first: It holds `FOR UPDATE`, blocking the operational transaction. Once `removeMember` commits and deletes the membership row, the operational transaction's `FOR SHARE` query returns zero rows, immediately failing closed with `403 Forbidden` (`FORBIDDEN_NOT_MEMBER`) and rolling back.
- **Account Deactivation & Global-Role Changes:**
  - Administrative user deactivation sets `users.is_active = false` under `SELECT FOR UPDATE` on `users`.
  - Privileged operations re-verify `users.is_active = true` and `global_role = 'ADMIN'` within the transaction boundary.
- **Scope of Row-Locking Guarantees:**
  - Membership row-locking alone does *not* solve all authorization races. While row-locking on `project_members` linearizes concurrent project-level membership revocation against operational mutations on that project, authorization races involving global roles, account deactivations, or project lifecycle transitions require locking on their respective parent rows (`users` at Level 0, `projects` at Level 1).
  - Furthermore, database row locks only operate within the boundary of active transactions; cryptographic caller authentication is handled upstream at the transport boundary (Phase 4).

---

## 4. Safe Concurrency Failure Handling (No "Deadlocks Are Impossible" Claims)

Deadlocks and concurrency conflicts can occur in high-concurrency systems despite hierarchical lock ordering. The domain service layer handles all failure modes safely:

1. **Deadlock Detection (`40P01`):**
   - Caught by transaction manager; transaction immediately aborted and rolled back.
   - Mapped to domain error: `SecureFlowError('Concurrent transaction conflict, please retry', 'TRANSACTION_DEADLOCK', 409)`.
2. **Serialization Failure (`40001`):**
   - Under `REPEATABLE READ` or `SERIALIZABLE` isolation, commit conflicts abort cleanly.
   - Mapped to domain error: `SecureFlowError('Transaction serialization conflict, please retry', 'SERIALIZATION_FAILURE', 409)`.
3. **Lock Acquisition Timeouts (`55P03`):**
   - PostgreSQL `lock_timeout` (e.g. 5000ms) and `statement_timeout` prevent threads from blocking indefinitely.
   - Mapped to domain error: `SecureFlowError('Lock acquisition timed out', 'TRANSACTION_TIMEOUT', 504)`.
4. **Optimistic Concurrency Control (OCC) Version Conflicts:**
   - When `FindingRepository.updateAtomic` updates zero rows due to a mismatched `expectedVersion`, it raises `ConcurrencyConflictError` (HTTP 409 Conflict) detailing expected vs actual versions.

---

## 5. Separation of Duties (SoD) Stored Evidence Across Repeated Cycles

In accordance with Invariant OLI-7 and [`docs/03-data-model.md §4`](../03-data-model.md), the Analyst verifying a remediation must not be the developer who submitted it.

### Authoritative Query Strategy
1. **Querying Submission Actor:**
   ```sql
   SELECT actor_id FROM finding_events
   WHERE finding_id = $1 AND new_status = 'READY_FOR_REVIEW'
   ORDER BY created_at DESC
   LIMIT 1;
   ```
2. **Repeated Remediation Cycles:**
   If a finding is rejected (`READY_FOR_REVIEW -> REOPENED`) and later re-submitted (`IN_PROGRESS -> READY_FOR_REVIEW`), ordering by `created_at DESC LIMIT 1` guarantees that `remediationSubmitterId` accurately identifies the actor who submitted the *most recent* fix in the current remediation cycle.
3. **Cross-Check with Active Task:**
   The active remediation task for the finding must have `status = 'SUBMITTED'` and `assigned_to_id = remediationSubmitterId`.
4. **Fail-Closed Rule:**
   If no `READY_FOR_REVIEW` event exists, or if `remediationSubmitterId` is null, unrecorded, or ambiguous, verification **fails closed immediately** with `SEPARATION_OF_DUTIES_VIOLATION` (HTTP 403).

---

## 6. Audit Metadata Minimization & Secret Protection

In compliance with data privacy and security audit standards:
- **Redaction of Sensitive Data:** Passwords, tokens, Bearer credentials, API keys, and session cookies are strictly excluded from `audit_events.beforeState`, `afterState`, and `finding_events.metadata`.
- **Minimal State Capture:** Only modified fields and identifiers (`id`, `status`, `severity`, `category`, `assignedToId`, `justification`) are recorded.
- **Append-Only Immutability:** Application code possesses no `UPDATE` or `DELETE` methods for `audit_events` or `finding_events`.

---

## 7. Concurrency Test Matrix for Gate 3D

Gate 3D transactional integration tests against `secureflow_test` must verify:
1. **Committed Prior Revocation:** Membership removed prior to request admission -> Returns `404 Not Found` existence hiding.
2. **In-Flight Concurrent Revocation:** Membership removal racing with mutation -> Serializes safely with `FOR SHARE` / `FOR UPDATE` lock conflict, either committing authorized or failing closed with 403.
3. **Concurrent Assignment:** Two Analysts attempting to assign the same finding -> Serialized via OCC version counter, second fails with 409 Conflict.
4. **Deadlock / Serialization Abort:** Transaction rolls back completely; zero partial database writes committed.

---

## 8. Sub-Gate 3D.2 Transactional ProjectService Architecture Requirements

When authorized, the transactional `ProjectService` implementation in Sub-Gate 3D.2 must adhere to the following design requirements:

1. **Account Deactivation & Global-Role Changes:**
   - User state modifications must acquire Level 0 row locks (`SELECT id FROM users WHERE id = $1 FOR UPDATE`).
   - Deactivation (`is_active = false`) and global-role changes must cascade or cause concurrent operations verifying actor freshness to abort fail-closed.

2. **Project Membership Addition & Revocation:**
   - Membership additions must acquire a Level 1 `FOR SHARE` lock on `projects` before inserting into `project_members`, relying on the composite unique constraint `project_members_project_id_user_id_key` to serialize duplicates.
   - Membership revocations must acquire a Level 1 `FOR SHARE` lock on `projects` followed by a Level 2 `FOR UPDATE` lock on `project_members`, safely deleting the record and logging an audit event.

3. **Authorization Freshness Within Transactions:**
   - Every mutating project operation must re-verify the calling actor's authorization (account active status, global role, or project membership) within the transaction under lock, rather than relying solely on the pre-transaction `ActorContext` snapshot.

4. **Strict Hierarchical Row-Lock Ordering:**
   - All repository methods participating in transactions must strictly enforce the hierarchy:
     $$\text{USERS (0)} \longrightarrow \text{PROJECT (1)} \longrightarrow \text{PROJECT\_MEMBERS (2)} \longrightarrow \text{FINDINGS (3)} \longrightarrow \text{REMEDIATION\_TASKS (4)}$$
   - Actual repository operations must be verified against this canonical order; reverse-order lock acquisition is prohibited.

5. **Concurrent Project Administration:**
   - Operations mutating project metadata or archiving projects must acquire Level 1 `FOR UPDATE` locks on `projects`.
   - Operations modifying multiple members simultaneously must sort all target `user_id` values in ascending lexical order prior to lock acquisition to eliminate deadlock cycles.

6. **Audit Atomicity:**
   - All administrative actions (`PROJECT_CREATED`, `PROJECT_UPDATED`, `PROJECT_ARCHIVED`, `MEMBER_ADDED`, `MEMBER_REMOVED`) must write their corresponding `audit_events` rows within the exact same database transaction as the entity mutation.
   - Transaction rollback must completely undo both entity changes and audit records.

7. **Safe Concurrency Failure Handling:**
   - Deadlocks (`40P01`), serialization failures (`40001`), and lock acquisition timeouts (`55P03`) must be trapped, logged with correlation IDs, and mapped to standardized HTTP 409 Conflict or HTTP 504 Gateway Timeout domain errors.
   - Under no circumstances should unhandled database lock exceptions leak raw internal database errors or leave connections hanging.
