# SecureFlow — Authorization Matrix

**Document version:** 1.0 — 2026-10-15  
**Status:** Draft — pending Phase 1 gate approval  
**Related docs:** [Product Requirements §6–7](01-product-requirements.md) · [Architecture §8](02-architecture.md) · [Data Model §4](03-data-model.md)

---

## 1. Authorization Principles

1. **Deny by default.** All actions are forbidden unless an explicit allow condition is met.
2. **Role + Project Membership + Resource Ownership.** Role alone is never sufficient for project-scoped actions.
3. **Server-side derivation.** The caller's identity and role are always derived from the server-side session or validated Bearer token — never from client-supplied fields.
4. **Object-level checks.** Every resource access verifies the resource belongs to a project the caller is a member of *and* that the caller has the required role in that project.
5. **Assignment-level checks.** For Developer operations, the finding or task must also be assigned to that specific Developer.
6. **REST/MCP parity.** MCP tools enforce the same policy as REST endpoints by calling the same `packages/domain` service functions.
7. **Existence hiding.** Resources outside the caller's authorization are returned as `404 Not Found`, not `403 Forbidden`, to prevent existence disclosure.

---

## 2. Global Role × Action Matrix

> **Legend:**
> - ✅ Allowed (subject to additional conditions in §3)
> - ❌ Denied
> - ⚠️ Allowed with conditions (see note)

### 2.1 Project Operations

| Action | Admin | Analyst | Developer | Conditions |
|---|---|---|---|---|
| Create project | ✅ | ❌ | ❌ | — |
| List all projects | ✅ | ❌ | ❌ | Admin sees all |
| List own projects | ✅ | ✅ | ✅ | Only projects where caller is a member |
| View project details | ✅ | ⚠️ | ⚠️ | Analyst/Developer must be project member |
| Update project | ✅ | ❌ | ❌ | — |
| Archive/deactivate project | ✅ | ❌ | ❌ | — |
| Add project member | ✅ | ❌ | ❌ | — |
| Remove project member | ✅ | ❌ | ❌ | — |
| View project members | ✅ | ⚠️ | ⚠️ | Must be member of the project |

### 2.2 Finding Operations

| Action | Admin | Analyst | Developer | Conditions |
|---|---|---|---|---|
| Create finding | ❌ | ✅ | ❌ | Analyst must be project member |
| List findings (project) | ✅ | ⚠️ | ⚠️ | Analyst: all findings in own projects; Developer: only assigned findings in own projects |
| View finding details | ✅ | ⚠️ | ⚠️ | Analyst: must be project member; Developer: must be assignee |
| Update finding metadata | ❌ | ⚠️ | ❌ | Analyst must be project member; not for status |
| Triage finding (OPEN→TRIAGED) | ❌ | ⚠️ | ❌ | Analyst must be project member |
| Assign finding to developer | ❌ | ⚠️ | ❌ | Analyst must be project member; Developer must be project member |
| Submit remediation (IN_PROGRESS→READY) | ❌ | ❌ | ⚠️ | Developer must be the assignee |
| Verify finding (READY→VERIFIED) | ❌ | ⚠️ | ❌ | Analyst must be project member; must not be the submitting developer |
| Close finding (VERIFIED→CLOSED) | ❌ | ⚠️ | ❌ | Analyst must be project member |
| Reopen finding | ❌ | ⚠️ | ❌ | Analyst must be project member |
| Force close/reopen (exceptional) | ✅ | ❌ | ❌ | Admin only; always audited |
| Soft-delete finding | ❌ | ⚠️ | ❌ | Analyst must be project member |

> **Note on Admin Finding Creation (F-13):** Admin's organization-wide role governs access governance, system administration, and project lifecycle management, not operational content creation. Findings are operational security artifacts scoped to the Analyst role within authorized projects. Admin calling `POST /api/v1/findings` returns `403 Forbidden` (verified in NEG-13).

### 2.3 Remediation Task Operations

| Action | Admin | Analyst | Developer | Conditions |
|---|---|---|---|---|
| Create remediation task | ❌ | ⚠️ | ❌ | Analyst must be project member; finding must be TRIAGED |
| View remediation task | ✅ | ⚠️ | ⚠️ | Analyst: project member; Developer: task assignee |
| Update task notes | ❌ | ❌ | ⚠️ | Developer must be task assignee |
| Submit task (mark SUBMITTED) | ❌ | ❌ | ⚠️ | Developer must be task assignee |
| Verify/reject task | ❌ | ⚠️ | ❌ | Analyst must be project member |

### 2.4 Audit Events

| Action | Admin | Analyst | Developer |
|---|---|---|---|
| View audit events (project) | ✅ | ❌ | ❌ |
| View audit events (org-wide) | ✅ | ❌ | ❌ |
| Create audit event (system) | System only | System only | System only |
| Delete/modify audit events | ❌ | ❌ | ❌ |

### 2.5 MCP Tool Operations

| Tool | Admin | Analyst | Developer | Conditions |
|---|---|---|---|---|
| `list_my_findings` | ✅ | ✅ | ✅ | Returns only findings the caller is authorized to see per their role + membership |
| `get_finding_details` | ✅ | ⚠️ | ⚠️ | Same conditions as REST GET finding |
| `get_remediation_summary` | ✅ | ⚠️ | ⚠️ | Analyst: project member; Developer: assignee |
| `propose_remediation_task` | ❌ | ⚠️ | ❌ | Phase 6+; Analyst project member; creates pending record only |

---

## 3. Object-Level Authorization Invariants

The following invariants must hold for **every** request. Violation of any invariant shall result in `403 Forbidden` (or `404 Not Found` where existence hiding applies).

| # | Invariant | Enforcement Point |
|---|---|---|
| OLI-1 | A user may only access findings in projects where they have an active `project_members` record | `ProjectMembershipPolicy` in `packages/domain` |
| OLI-2 | A Developer may only read finding details for findings where `findings.assigned_to_id = principal.userId` | `FindingAccessPolicy` — assignee check |
| OLI-3 | A Developer may only update remediation progress for tasks where `remediation_tasks.assigned_to_id = principal.userId` | `TaskAccessPolicy` |
| OLI-4 | An Analyst may only triage, assign, verify, or close findings in projects where they hold the `ANALYST` project role | `FindingPolicy` + `ProjectMembershipPolicy` |
| OLI-5 | Only Admin may add or remove project members | `ProjectMembershipPolicy` — role gate |
| OLI-6 | A Developer may not call any status transition except `submit-remediation`, and only when assigned | `FindingTransitionPolicy` |
| OLI-7 | An Analyst may not self-complete a finding they submitted a remediation for (if Analyst also performs dev work) | `FindingVerifyPolicy` — actor ≠ submitter |
| OLI-8 | The project membership API must accept only `ANALYST` or `DEVELOPER` as valid role values. No request may grant a project-scoped `ADMIN` role (which does not exist in the data model) | `ProjectMembershipPolicy` validates role enum before insertion |
| OLI-9 | The MCP server must re-derive authorization from the validated Bearer token; it cannot inherit or trust the browser session | `McpAuthPolicy` — independent token validation |
| OLI-10 | Project member removal must immediately revoke access; cached session must reflect current membership state | `SessionInvalidationService` — on membership change |
| OLI-11 | An MCP proposed action must re-authorize the original requesting principal at execution time, not just at proposal time | `McpActionExecutionPolicy` |
| OLI-12 | Soft-deleted findings are excluded from all queries unless the caller is Admin and explicitly requests deleted records | `FindingRepository` — default filter `is_deleted = false` |

---

## 4. Negative Authorization Test Scenarios

The following scenarios must **all** result in access denial. Each should have a corresponding automated test.

| # | Scenario | Actor | Action Attempted | Expected Result | REST Test | MCP Test |
|---|---|---|---|---|---|---|
| NEG-01 | Developer reads another project's finding by guessing UUID | Developer (ProjectA member) | `GET /api/v1/findings/{ProjectB-finding-uuid}` | `404 Not Found` (existence hidden) | ✓ Required | ✓ Required |
| NEG-02 | Developer calls verify/close on their own assigned finding | Developer (assignee) | `POST /api/v1/findings/:id/verify` | `403 Forbidden` | ✓ Required | N/A |
| NEG-03 | Analyst in ProjectA accesses a finding in ProjectB | Analyst (ProjectA member only) | `GET /api/v1/findings/{ProjectB-finding-uuid}` | `404 Not Found` | ✓ Required | ✓ Required |
| NEG-04 | Developer attempts to create a finding | Developer | `POST /api/v1/findings` | `403 Forbidden` | ✓ Required | N/A |
| NEG-05 | Unauthenticated request to a protected endpoint | Anonymous | `GET /api/v1/findings` | `401 Unauthorized` | ✓ Required | ✓ Required |
| NEG-06 | Developer attempts to add a project member | Developer | `POST /api/v1/projects/:id/members` | `403 Forbidden` | ✓ Required | N/A |
| NEG-07 | Analyst attempts to add a project member | Analyst | `POST /api/v1/projects/:id/members` | `403 Forbidden` | ✓ Required | N/A |
| NEG-08 | Developer submits remediation for a finding assigned to a different developer | Developer (non-assignee) | `POST /api/v1/findings/:id/submit-remediation` | `403 Forbidden` (or `404`) | ✓ Required | N/A |
| NEG-09 | MCP client calls `get_finding_details` with another project's finding ID | MCP caller (ProjectA principal) | MCP tool: `get_finding_details({id: ProjectB-uuid})` | `403` / tool error | N/A | ✓ Required |
| NEG-10 | MCP client with an expired Bearer token calls any tool | Any MCP caller | Any MCP tool call | `401 Unauthorized` / tool auth error | N/A | ✓ Required |
| NEG-11 | Developer attempts to directly transition finding to VERIFIED by sending a crafted PATCH | Developer | `PATCH /api/v1/findings/:id` with `{"status": "VERIFIED"}` | `403 Forbidden` | ✓ Required | N/A |
| NEG-12 | Analyst attempts to view audit events of a project they are not admin of | Analyst | `GET /api/v1/audit-events?projectId=X` | `403 Forbidden` | ✓ Required | N/A |
| NEG-13 | Admin calls `POST /api/v1/findings` directly (only Analyst may create) | Admin | `POST /api/v1/findings` | `403 Forbidden` | ✓ Required | N/A |
| NEG-14 | Removed project member attempts to access a finding in the project they were removed from | Former member | `GET /api/v1/findings/{uuid}` | `404 Not Found` | ✓ Required | N/A |
| NEG-15 | MCP proposed action is executed without re-authorization of the original principal | Any | Direct execution call without approval | `403 Forbidden` / denied | N/A | ✓ Required |

---

## 5. Privilege Escalation Scenarios

These must be explicitly tested in Phase 4 and Phase 7:

| # | Scenario | Expected Outcome |
|---|---|---|
| PE-01 | Client submits `{"role": "ADMIN"}` in a request body | Server ignores client-supplied role; derives role from session/token only |
| PE-02 | Client sets `x-user-id` or `x-role` header to impersonate another user | Server ignores all client-supplied identity headers; derives identity from validated session/token |
| PE-03 | Client forges a session cookie by guessing its value | Session secret makes this infeasible; secure session library required |
| PE-04 | Developer modifies `assigned_to_id` in a PATCH body to re-assign to themselves | Field is not updatable by Developer; Analyst-only operation; server ignores unknown/forbidden fields |
| PE-05 | MCP client passes `principal_override` argument to a tool | Tool argument validated by Zod; no such field accepted; domain service derives identity from token |

---

## 6. Cross-Project Access Scenarios

| # | Scenario | Expected Outcome |
|---|---|---|
| CP-01 | Analyst triages a finding in a project they are not a member of | 404 Not Found |
| CP-02 | Developer views finding list with no `projectId` filter — should not see other project findings | Response scoped to caller's authorized projects + assignments only |
| CP-03 | Admin views finding list — sees all projects' findings | Admin has read-all access; still audited |
| CP-04 | MCP `list_my_findings` called by a user who is a member of ProjectA and ProjectB | Returns findings from both, filtered by membership and assignment rules |

---

## 7. Implementation Guidance for `packages/domain`

The domain package should implement a single `can(principal, action, resource)` function or equivalent policy service for each resource type. Example structure:

```
packages/domain/src/policy/
  FindingPolicy.ts          ← can(principal, FindingAction, finding | projectId)
  ProjectPolicy.ts          ← can(principal, ProjectAction, project)
  TaskPolicy.ts             ← can(principal, TaskAction, task)
  AuditEventPolicy.ts       ← can(principal, AuditAction)
  McpActionPolicy.ts        ← can(principal, McpAction, mcpActionRequest)
```

Each policy function:
1. Checks if the principal is authenticated (not null/anonymous).
2. Checks if the principal's global role permits the action.
3. Checks if the principal has the required project-scoped membership role.
4. Checks assignment/ownership for assignment-scoped operations.
5. Returns `{ allowed: true }` or throws a typed `ForbiddenError` / `NotFoundError`.

All route handlers and MCP tool handlers call only domain services which invoke these policy functions — no authorization logic in controllers, and no direct repository access (`packages/domain/src/db/`) is permitted from callers outside the domain package (enforcing F-08).

---

## 8. Audit Requirements for Authorization Decisions

All **denied** access attempts shall be logged in `audit_events` with:
- `event_category`: `AUTH`
- `event_type`: `access.denied`
- `actor_id`: authenticated principal (or null if unauthenticated)
- `resource_id` + `resource_type`: what was attempted
- `after_state`: `{ action, reason }` — no sensitive data

This ensures failed privilege escalation attempts are detectable and reviewable.
