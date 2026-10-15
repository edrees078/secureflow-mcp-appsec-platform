# SecureFlow — Product Requirements

**Document version:** 1.0 — 2026-10-15  
**Status:** Draft — pending Phase 1 gate approval  
**Roadmap reference:** [PROJECT_ROADMAP.md §3](../PROJECT_ROADMAP.md) · [Architecture](02-architecture.md) · [Authorization Matrix](04-authorization-matrix.md)

---

## 1. Product Vision

SecureFlow is a **security findings and remediation management platform** for software engineering teams. It provides a structured workflow for recording application-security vulnerabilities, assigning remediation work to authorized project members, tracking progress, verifying fixes, and maintaining an append-only audit trail (application-layer immutability; cryptographic tamper evidence is out of scope for MVP).

A separately exposed **MCP (Model Context Protocol) server** allows an AI client to access a caller's authorized findings under strict authorization controls, and to propose — but never silently execute — remediation changes.

### 1.1 Value Proposition

| Stakeholder | Problem Solved |
|---|---|
| Security Analyst | Structured place to record, triage and track findings across projects without using spreadsheets or unstructured ticket fields |
| Developer | Clear view of what security work is assigned to them, without exposure to findings they are not authorized to see |
| Admin | Audit trail of all finding state changes and access events; project membership management |
| AI/MCP Client User | Ability to ask an authorized AI agent about security findings, get structured summaries, and receive proposed remediations for review |

### 1.2 Target Audience

**Primary:** Technical recruiters, software engineers, application security engineers, and developers evaluating the repository as a portfolio project demonstrating production-oriented engineering practices.

**Secondary:** A small security team or AppSec practitioner who wants to evaluate the platform for actual use in a single-organization context.

---

## 2. Assumptions

1. A single organization with multiple projects is sufficient for the MVP. Full multi-tenant SaaS is explicitly out of scope.
2. Users authenticate via an external OIDC provider (Keycloak for local development). SecureFlow does not implement password storage or an OAuth authorization server.
3. All environment configuration (DB credentials, OIDC client secrets, etc.) is provided via `.env` files that are **never committed to version control**.
4. The MCP client used in the demo is a real AI client (e.g., Claude Desktop or a CLI test harness), not a mock.
5. Findings represent real or synthetic security vulnerabilities — not live exploit payloads or actual vulnerable code.
6. The system operates at low traffic volumes appropriate for a team/portfolio environment; horizontal scaling is not an MVP concern.
7. Developers see **only findings assigned to them** within their authorized projects (not all findings in a project), per approved architecture decision D4 (principle of least privilege).

---

## 3. MVP Boundaries

### In Scope
- User authentication via OIDC (Keycloak)
- Project creation and member management (Admin)
- Finding lifecycle: create, triage, assign, remediate, verify, close, reopen
- Remediation task management
- Role-based access control (Admin, Security Analyst, Developer)
- Object-level authorization (project membership + resource ownership)
- Audit event trail for all state changes
- MCP server with read-only tools for authorized findings
- MCP proposed write action (pending approval workflow) — Phase 6
- Structured operational and security audit logs
- Docker Compose local development environment
- GitHub Actions CI pipeline
- OWASP security tooling (CodeQL, ZAP baseline)

### Out of Scope (Non-Goals for MVP)
- Multi-organization SaaS tenancy
- Billing or subscription management
- Real-time chat or collaboration features
- Kubernetes or microservices deployment
- Autonomous AI remediation without explicit human approval
- Building a custom OAuth authorization server or password manager
- Vulnerability exploitation or intentionally insecure endpoints
- Mobile application
- Integrations with external scanners (Burp Suite, Nessus, etc.) — future feature

---

## 4. Roles and Personas

### 4.1 Role Definitions

| Role | Scope | Description |
|---|---|---|
| **Admin** | Organization-wide | Creates and manages projects; manages project membership; can view all findings in any project they administer; reviews audit events; cannot self-elevate further |
| **Security Analyst** | Project-scoped | Creates, triages and manages findings in their authorized projects; creates remediation tasks; assigns work to Developers; verifies and closes findings; sees all findings in their project |
| **Developer** | Project-scoped + assignment-scoped | Sees only findings assigned to them in their authorized projects; updates remediation progress; submits proposed resolution for review; cannot self-approve closure |

> **Important:** Roles are stored and enforced server-side. A role claim from the client is never trusted without server-side derivation from the session/token.

### 4.2 Personas

#### Alex — Admin
Alex is a security program manager responsible for setting up projects and ensuring the right people have access. Alex needs to add or remove project members quickly and review the audit log when something unexpected happens.

#### Sam — Security Analyst
Sam is an application security engineer who runs security assessments. Sam records findings discovered during code review or DAST scanning, triages severity, creates remediation assignments, and later verifies that developers actually fixed the issues correctly.

#### Dev — Developer
Dev is a software engineer assigned to remediate findings. Dev needs a clear, focused view of what security issues they are responsible for, the ability to describe what they did to fix each one, and a way to submit their work for analyst review.

#### AI — MCP Client (Claude Desktop or CLI harness)
The AI client connects to the MCP server using its own OAuth credentials (not Dev's browser session). It can list and summarize findings the authenticated principal is authorized to see, and propose remediation tasks. All proposed changes require explicit human approval — the AI cannot silently mutate state.

---

## 5. User Stories

### Admin Stories

| ID | As an Admin, I want to… | So that… |
|---|---|---|
| US-A01 | Create a new project with a name and description | I can organize findings by application or assessment scope |
| US-A02 | Add a user to a project with a specified role (Analyst or Developer) | Team members can access the project they need |
| US-A03 | Remove a user from a project | Access is revoked when a team member leaves |
| US-A04 | View the audit event log for a project | I can review who made what changes and when |
| US-A05 | View all projects in the organization | I have full visibility to manage access |

### Security Analyst Stories

| ID | As a Security Analyst, I want to… | So that… |
|---|---|---|
| US-S01 | Create a finding with title, description, severity, and category | The vulnerability is formally recorded |
| US-S02 | Triage an open finding (set severity, assign to project) | Finding moves from raw report to actionable item |
| US-S03 | Create a remediation task and assign it to a Developer | The right developer knows they have work to do |
| US-S04 | View all findings in my authorized projects | I can manage my project's security posture |
| US-S05 | Mark a finding as READY_FOR_REVIEW when the Developer submits | The workflow is tracked |
| US-S06 | Verify a finding is fixed and close it | Finding lifecycle is complete |
| US-S07 | Reopen a finding that was not properly fixed | The developer is notified and must re-remediate |
| US-S08 | Filter and search findings by status, severity, or assignee | I can focus on the most critical or overdue items |

### Developer Stories

| ID | As a Developer, I want to… | So that… |
|---|---|---|
| US-D01 | See only the findings assigned to me in my projects | I am not exposed to findings outside my responsibility |
| US-D02 | View the full details of a finding assigned to me | I understand what needs to be fixed |
| US-D03 | Update the remediation progress (add notes, change progress status) | The analyst can track my work |
| US-D04 | Submit a proposed resolution for analyst review | My fix is formally submitted for verification |
| US-D05 | See that a finding I submitted was verified/closed or reopened | I know whether my fix was accepted |

### MCP / AI Client Stories

| ID | As an authorized MCP client, I want to… | So that… |
|---|---|---|
| US-M01 | List findings the authenticated principal is authorized to see | An AI assistant can summarize the security posture |
| US-M02 | Retrieve full details of a specific authorized finding | The AI can analyze a specific vulnerability |
| US-M03 | Retrieve a remediation summary for an authorized finding | The AI can describe what action was taken |
| US-M04 | Propose a remediation task (pending human approval) | The AI can suggest fixes without silently mutating state |

---

## 6. Functional Requirements

### Finding Management

| ID | Requirement | Priority |
|---|---|---|
| FR-001 | The system shall allow a Security Analyst to create a finding with: title (required, ≤500 chars), description (required, ≤10,000 chars), severity (CRITICAL/HIGH/MEDIUM/LOW/INFO), category (e.g., INJECTION, AUTH, ACCESS_CONTROL, CRYPTO, etc.), CVSS score (optional, 0.0–10.0), and associated project | Must |
| FR-002 | A new finding shall be assigned status `OPEN` automatically upon creation | Must |
| FR-003 | The system shall enforce finding status transitions as defined in the state machine (see §7 and [Data Model §4](03-data-model.md)) | Must |
| FR-004 | Each status transition shall be recorded as an audit event with: actor, previous state, new state, timestamp, and optional notes | Must |
| FR-005 | A Security Analyst shall be able to reassign a finding to a different Developer within the same project | Should |
| FR-006 | A Security Analyst shall be able to set a due date on a remediation task | Should |
| FR-007 | The system shall support soft-deletion of findings (mark as deleted, retain record for audit) rather than hard deletion | Must |
| FR-008 | Findings shall be paginated; default page size is 25; maximum is 100 | Must |
| FR-009 | Findings shall be filterable by: status, severity, project, assignee, date range | Should |

### User and Project Management

| ID | Requirement | Priority |
|---|---|---|
| FR-010 | Only an Admin shall be able to create projects | Must |
| FR-011 | Only an Admin shall be able to add or remove project members | Must |
| FR-012 | A project member shall have exactly one role per project (Analyst or Developer) | Must |
| FR-013 | A user may be a member of multiple projects with different roles | Should |
| FR-014 | Project membership removal shall immediately revoke all access to that project's findings and tasks | Must |

### Authentication and Session

| ID | Requirement | Priority |
|---|---|---|
| FR-015 | All users shall authenticate via OIDC authorization-code flow with PKCE | Must |
| FR-016 | The server shall derive the user's identity and roles from the validated OIDC token/session; client-supplied identity is never trusted | Must |
| FR-017 | Sessions shall expire after a configurable idle timeout; expiry causes re-authentication | Must |
| FR-018 | A logout action shall invalidate the server-side session and clear the session cookie | Must |

### Audit Logging

| ID | Requirement | Priority |
|---|---|---|
| FR-019 | The system shall produce an immutable append-only audit event for every finding state change, membership change, and admin action | Must |
| FR-020 | Audit events shall include: event type, actor user ID, target resource ID and type, timestamp (UTC), IP address (if available), and before/after state where applicable | Must |
| FR-021 | Sensitive data (tokens, passwords, session IDs) shall never appear in audit or operational logs | Must |
| FR-022 | Audit events shall be queryable by Admin for a given project, paginated, with date-range filtering | Should |

### MCP Server

| ID | Requirement | Priority |
|---|---|---|
| FR-023 | The MCP server shall expose at minimum three read-only tools: `list_my_findings`, `get_finding_details`, `get_remediation_summary` | Must |
| FR-024 | Every MCP tool call shall authenticate the caller via a validated OAuth 2.0 Bearer token (distinct from the browser session) | Must |
| FR-025 | The MCP server shall reuse the same domain service authorization layer as the REST API | Must |
| FR-026 | The MCP server shall log all tool invocations with caller identity, tool name, arguments (redacted if sensitive), and outcome | Must |
| FR-027 | A write-capable MCP tool (`propose_remediation_task`) shall create a pending action record, not directly mutate finding state | Later |
| FR-028 | Pending MCP action records shall require explicit human approval before execution | Later |

---

## 7. Nonfunctional and Security Requirements

### Performance

| ID | Requirement |
|---|---|
| NFR-001 | API responses for paginated finding lists shall complete within 500ms at MVP load levels |
| NFR-002 | The system shall handle at least 50 concurrent authenticated users without degradation |

### Reliability

| ID | Requirement |
|---|---|
| NFR-003 | The system shall use database transactions for all multi-step state changes |
| NFR-004 | All unhandled errors shall be caught, logged operationally, and return a consistent error response without leaking stack traces or internal details |

### Security Requirements

| ID | Requirement | ASVS 5.0.0 Reference* |
|---|---|---|
| SEC-001 | Every state-changing request shall be authenticated and authorized server-side before execution; no client-side role or identity claim is trusted | ASVS V1 Architecture §1.4 |
| SEC-002 | Authorization shall check both role **and** project membership **and** resource ownership (deny by default) | ASVS V4 Access Control §4.1 |
| SEC-003 | Finding IDs shall use non-sequential UUIDs (UUID v4) as a defense-in-depth measure against enumeration. Object-level authorization (SEC-002) is the primary IDOR protection — every access must be authorized regardless of ID format. | ASVS V4 §4.1 |
| SEC-004 | All HTTP responses shall include appropriate security headers (Content-Security-Policy, X-Content-Type-Options, Referrer-Policy, X-Frame-Options) | ASVS V14 §14.4 |
| SEC-005 | Session cookies shall be HttpOnly, Secure (HTTPS only in production), and SameSite=Lax | ASVS V3 Session Management §3.4 |
| SEC-006 | CSRF protection shall be applied to all cookie-authenticated state-changing requests | ASVS V4 §4.3 |
| SEC-007 | All user-controlled input shall be validated with Zod schemas on the server before processing | ASVS V5 Validation §5.1 |
| SEC-008 | SQL queries shall use parameterized queries (enforced by Prisma); no string-interpolated SQL | ASVS V5 §5.3 |
| SEC-009 | Authentication-sensitive endpoints (login, token refresh) shall be rate-limited | ASVS V11 §11.1 |
| SEC-010 | MCP tool arguments shall be validated with Zod schemas before being passed to domain services | ASVS V5 §5.1 |
| SEC-011 | The MCP server shall validate the Bearer token's issuer, audience, and expiry before servicing any tool call | ASVS V6 §6.3 (token validation) |
| SEC-012 | Sensitive finding descriptions and AI-produced text shall be treated as untrusted data and never interpreted as server instructions | MCP Security Cheat Sheet — Prompt Injection |
| SEC-013 | All audit events shall be append-only; no API endpoint shall allow deletion or modification of audit records | ASVS V7 §7.1 |
| SEC-014 | Secrets (DB credentials, OIDC client secret, session secret) shall be loaded from environment variables; no secrets shall be hardcoded or committed | ASVS V2 §2.10 |
| SEC-015 | Dependency vulnerabilities shall be monitored via Dependabot/SCA; critical/high unresolved vulnerabilities block release | ASVS V10 §10.2 |

> *ASVS section references are provided as navigational guidance. Verify exact requirement numbers against the published OWASP ASVS 5.0.0 document before claiming conformance.*

### Maintainability

| ID | Requirement |
|---|---|
| NFR-005 | All authorization logic shall reside in `packages/domain`; no authorization checks in Express controllers or MCP tool handlers |
| NFR-006 | All runtime validation schemas shall be shared between frontend and backend via `packages/schemas` |
| NFR-007 | TypeScript strict mode shall be enabled for all packages |

---

## 8. Acceptance Criteria

The following criteria must be demonstrably met at the Phase 1 gate (documentation) and again at their respective implementation phases:

| Phase | Criterion | How Verified |
|---|---|---|
| P1 | All seven design documents exist, are cross-consistent, and contain no invented test results | Manual review of documents |
| P1 | All open decisions (D1–D10 in planning artifact) are documented and flagged | Visible open-decision blocks in docs |
| P4 | A Developer authenticated as ProjectA member cannot read a finding from ProjectB | Automated negative test + Burp Suite manual check |
| P4 | A Developer cannot call the `verify` endpoint to close a finding | Automated negative test returning 403 |
| P4 | A Security Analyst in ProjectA cannot manage membership of ProjectB | Automated negative test |
| P5 | A user can complete the full Analyst → Developer → Analyst workflow via browser | Playwright e2e test |
| P6 | An MCP client with valid credentials can list only their authorized findings | Recorded MCP session with synthetic data |
| P6 | An MCP client with another project's finding ID receives a denial | Automated MCP negative test |
| P6 | A finding description containing `<script>` or AI prompt injection text is treated as data | Test verifying no elevated action occurs |
| P7 | CI pipeline passes lint, typecheck, unit, integration tests on each PR | Green GitHub Actions run |
| P7 | No hardcoded secrets exist in the repository | Secret scanning + manual review |

---

## 9. Glossary

| Term | Definition |
|---|---|
| **Finding** | A recorded security vulnerability or weakness discovered during assessment |
| **Remediation Task** | A work item assigned to a Developer to fix a specific Finding |
| **Project** | A named scope (application, service, or assessment) within which Findings and Members are organized |
| **Project Member** | A User who has been granted a role (Analyst or Developer) within a specific Project |
| **MCP** | Model Context Protocol — a standard for exposing application capabilities as structured tools to AI clients |
| **OIDC** | OpenID Connect — identity layer on top of OAuth 2.0 used for user authentication |
| **BFF** | Backend For Frontend — server-side session pattern that prevents browser-accessible token storage |
| **STRIDE** | Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege — threat modelling framework |
| **BOLA/IDOR** | Broken Object-Level Authorization / Insecure Direct Object Reference — accessing another user's resources by guessing/manipulating IDs |
| **Audit Event** | An immutable record of a security-relevant or data-changing action, including actor, resource, and timestamp |
