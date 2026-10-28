# Gate 3D Implementation Note: Authorization Freshness & Concurrent-Revocation Linearization

**Status:** Approved Handoff Specification from Gate 3C to Gate 3D
**Applies to:** `packages/domain` Transactional Service Layer (`FindingService`, `ProjectService`, `TaskService`)
**Related Documents:** [docs/02-architecture.md](../02-architecture.md) · [docs/04-authorization-matrix.md](../04-authorization-matrix.md)

---

## 1. Context & Motivation

During Phase 3 Gate 3C, object-level authorization policies (`ProjectPolicy`, `FindingPolicy`, `TaskPolicy`, `AuditPolicy`) and internal `ActorContext` were implemented. Automated integration testing against PostgreSQL confirmed:
1. Re-deriving `ActorContext` from PostgreSQL at a request boundary immediately enforces project member removal with `404 Not Found` existence hiding.
2. Conversely, reusing an unrefreshed in-memory `ActorContext` snapshot across requests fails to detect real-time database revocations (the "Stale Context Trap").

While per-request dynamic context reconstruction prevents cross-request stale cache reuse, intra-request concurrent mutations introduce potential race conditions under PostgreSQL's default `READ COMMITTED` transaction isolation level.

---

## 2. Gate 3D Core Concurrency & Freshness Requirements

When implementing transactional service methods in Gate 3D, the following requirements must be enforced:

### A. Intra-Transaction Membership Revalidation
- For sensitive state mutations (`triage`, `assign`, `submit_remediation`, `verify`, `close`, `reopen`, `soft_delete`), the service must verify membership inside the transactional unit of work (`RepositoryContainer`).
- Rechecking membership inside the transaction is necessary to defend against revocation occurring after request admission.

### B. Linearization Point & Isolation Strategy
- Under PostgreSQL default `READ COMMITTED` isolation, a simple `SELECT` on `project_members` does not prevent a concurrent transaction from removing the member immediately before or during the finding update.
- Gate 3D must explicitly define the authorization linearization point and locking/isolation strategy:
  - **Option 1 (Pessimistic Row Share):** Execute `SELECT 1 FROM project_members WHERE project_id = $1 AND user_id = $2 FOR SHARE` to lock the membership record against concurrent deletion during the transaction.
  - **Option 2 (Optimistic Concurrency Control / Serializable Validation):** Track membership revision or evaluate within a `REPEATABLE READ` / `SERIALIZABLE` transaction that fails-closed upon concurrent revocation.
  - **Option 3 (Foreign Key / Invariant Guard):** Enforce state transitions such that concurrent membership changes force transaction replay or fail-closed rejection.

### C. Concurrency Test Matrix for Gate 3D
Gate 3D transactional integration tests against `secureflow_test` must distinctly test and separate:
1. **Committed Prior Revocation:** Member was deleted and committed in PostgreSQL prior to the mutation request starting -> Must immediately return `404 Not Found` (EntityNotFoundError).
2. **In-Flight Concurrent Revocation:** A concurrent transaction deletes the project member while an in-flight mutation transaction has already begun -> Must linearize safely (either complete authorized if serialized first, or safely rollback/abort if serialized second).
3. **Deadlock & Serialization Failure Safety:** PostgreSQL serialization failures (`40001`) or deadlock detections (`40P01`) must be handled cleanly via fail-closed transaction abort or controlled retry, without ever allowing unauthorized writes to bypass policy evaluation.

---

## 3. Summary of Gate 3C Invariants Carried into Gate 3D

- `ActorContext` instances must never be cached across distinct requests.
- Client transport inputs cannot manufacture or override membership scopes.
- All unauthorized access attempts must preserve `404 Not Found` existence hiding for cross-project resources.
- Missing remediation submitter evidence must strictly fail-closed on finding verification.
