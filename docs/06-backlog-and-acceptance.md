# SecureFlow — Backlog and Acceptance Criteria

**Document version:** 1.0 — 2026-10-15  
**Status:** Draft — pending Phase 1 gate approval  
**Related docs:** [Product Requirements](01-product-requirements.md) · [Architecture](02-architecture.md) · [Data Model](03-data-model.md) · [Authorization Matrix](04-authorization-matrix.md) · [Threat Model](05-threat-model.md) · [PROJECT_ROADMAP.md §4](../PROJECT_ROADMAP.md)

> **Priority labels:** **Must** = MVP blocker · **Should** = important but deferrable · **Later** = post-MVP

---

## Phase 1 — Product Definition, Architecture, and Security Design

**Target:** Week 1  
**Gate requirement:** Developer review and sign-off on all open decisions (D1–D10) before Phase 2 begins.

### Backlog Items

| ID | Item | Priority | Status |
|---|---|---|---|
| P1-01 | Review and approve `docs/01-product-requirements.md` | Must | ⏳ Awaiting review |
| P1-02 | Review and approve `docs/02-architecture.md` | Must | ⏳ Awaiting review |
| P1-03 | Review and approve `docs/03-data-model.md` | Must | ⏳ Awaiting review |
| P1-04 | Review and approve `docs/04-authorization-matrix.md` | Must | ⏳ Awaiting review |
| P1-05 | Review and approve `docs/05-threat-model.md` | Must | ⏳ Awaiting review |
| P1-06 | Review and approve `docs/06-backlog-and-acceptance.md` | Must | ⏳ Awaiting review |
| P1-07 | Review and approve `docs/decisions/0001-modular-monolith.md` | Must | ⏳ Awaiting review |
| P1-08 | Resolve open decisions D1–D10 (ORM, OIDC, session, visibility, MCP transport, demo, license, client, statuses) | Must | ⏳ Awaiting decisions |

### Phase 1 Acceptance Criteria

- [ ] All seven documents exist under `docs/` and `docs/decisions/` in the workspace root.
- [ ] No application code, package files, migrations, containers, or commands were created or executed.
- [ ] Each document cross-links to related documents and does not duplicate content that belongs in another doc.
- [ ] The ERD covers all entities specified in the roadmap.
- [ ] The authorization matrix contains at least 15 negative test scenarios (this document has 15).
- [ ] The threat model covers BOLA/IDOR, privilege escalation, session/CSRF, injection, sensitive log data, secrets, CI supply chain, MCP token misuse, prompt injection, confused-deputy, and unauthorized AI writes.
- [ ] No ASVS IDs are invented; all references point to published ASVS v5.0.0 section areas.
- [ ] All open decisions are flagged in documents and listed in this backlog.

### ✅ Phase 1 Gate Decisions (Authoritative — Approved D1–D10)

> Full architectural rationale and specifications are detailed in [Architecture §13](02-architecture.md#13-architecture-decision-register-authoritative--10-decisions).

| Decision | Approved Selection | Status |
|---|---|---|
| **D1 — ORM** | **Prisma 7** with PostgreSQL driver adapter (`@prisma/adapter-pg`) | ✅ Approved |
| **D2 — OIDC provider** | **Keycloak 26.x** in Docker Compose (supports PKCE and OAuth 2.1) | ✅ Approved |
| **D3 — Session model** | **BFF server-managed session** with HttpOnly/Secure cookies and session rotation | ✅ Approved |
| **D4 — Developer visibility** | **Assigned findings only** (principle of least privilege) | ✅ Approved |
| **D5 — MCP transport & auth** | **Streamable HTTP** via MCP SDK v2 (`@modelcontextprotocol/express`) + OAuth 2.1 | ✅ Approved |
| **D6 — Public demo** | **Defer live public deployment**; use local Docker Compose + recorded demo | ✅ Approved |
| **D7 — License** | **MIT License**; file creation deferred until release packaging | ✅ Approved |
| **D8 — MCP verification client** | **MCP Inspector** (dev debugging) + **Claude Desktop** (real-client demo) | ✅ Approved |
| **D9 — Finding statuses** | **Defer `WONT_FIX` and `DUPLICATE` as future dispositions**; keep core MVP lifecycle focused | ✅ Approved |
| **D10 — Multi-org architecture** | **Single-org MVP** (no speculative `organization_id` column; migration path documented) | ✅ Approved |

---

## Phase 2 — Monorepo Foundation, Tooling, and Local Services

**Target:** Week 2  
**Dependencies:** Phase 1 gate approved; open decisions D1–D10 resolved.

### Backlog Items

| ID | Item | Priority | Deliverable |
|---|---|---|---|
| P2-01 | Initialize Git repository locally; create `.gitignore` | Must | `.gitignore`, local git history |
| P2-02 | Set up pnpm workspace with `apps/web`, `apps/api`, `apps/mcp-server`, `packages/domain`, `packages/schemas`, `packages/shared`; pin Node.js 24 LTS in `.nvmrc` (`24`) and `package.json` `engines` field (`>=24.0.0`), standardizing on stable TypeScript (`>=5.7.0`) | Must | `pnpm-workspace.yaml`, root `package.json`, `.nvmrc` |
| P2-03 | Configure TypeScript strict mode for all packages (project references) | Must | `tsconfig.json` per package |
| P2-04 | Configure ESLint + Prettier + `eslint-plugin-boundaries` for module boundary enforcement | Must | `.eslintrc`, `.prettierrc` |
| P2-05 | Scaffold `apps/api`: Express server, health check endpoint, error handler | Must | `apps/api/src/server.ts`, `/health/ready` |
| P2-06 | Scaffold `apps/web`: Vite + React + TypeScript starter | Must | `apps/web/src/main.tsx` |
| P2-07 | Scaffold `apps/mcp-server`: MCP SDK v2 server stub | Should | `apps/mcp-server/src/server.ts` |
| P2-08 | Scaffold `packages/domain`, `packages/schemas`, `packages/shared` with placeholder exports | Must | Package index files |
| P2-09 | Add Docker Compose for PostgreSQL (dev only); health check; no real secrets | Must | `compose.yaml` |
| P2-10 | Add `.env.example` with all required variables, placeholder values, documentation | Must | `.env.example` |
| P2-11 | Add GitHub Actions CI workflow: lint, typecheck, build, smoke test | Must | `.github/workflows/ci.yml` |
| P2-12 | Add Keycloak to Docker Compose (dev only; decision D2 must be resolved first) | Should | `compose.yaml` Keycloak service |
| P2-13 | Write bootstrap `README.md` with setup instructions | Should | `README.md` |

### First 5 Phase 2 Development Tasks (plan only — do not implement in Phase 1)

> These are the recommended first five tasks to give Antigravity at the start of Phase 2.

1. **P2-T1:** Create `pnpm-workspace.yaml` and root `package.json` with workspace configuration and shared scripts (`lint`, `typecheck`, `build`, `test`). No code logic yet.
2. **P2-T2:** Create TypeScript `tsconfig.base.json` at root with `strict: true`; add per-package `tsconfig.json` files extending it. Verify `tsc --noEmit` passes on empty packages.
3. **P2-T3:** Scaffold `apps/api` with Express, a `/health/ready` route returning `{ status: "ok" }`, global error handler, and a Vitest smoke test that starts the server and calls the health endpoint.
4. **P2-T4:** Create `compose.yaml` with a PostgreSQL service using an official image, a named volume, health check, and environment variables loaded from `.env`; add `.env.example` with all required placeholder keys.
5. **P2-T5:** Create `.github/workflows/ci.yml` that runs on push and pull_request; jobs: `lint` (ESLint), `typecheck` (tsc --noEmit), `test` (Vitest). Pin all third-party Actions to full commit SHA.

### Phase 2 Acceptance Criteria

- [ ] `pnpm install && pnpm lint && pnpm typecheck && pnpm test` succeeds from workspace root.
- [ ] `docker compose up -d` starts PostgreSQL and (if approved) Keycloak; health checks pass.
- [ ] No real credentials in any committed file; `.env` is in `.gitignore`.
- [ ] GitHub Actions CI runs green on a test push.
- [ ] `eslint-plugin-boundaries` (or equivalent) reports a violation if `apps/api` imports directly from `packages/domain/src/db` bypassing the service layer.
- [ ] Another developer can clone, set up `.env` from `.env.example`, and reproduce the environment.

---

## Phase 3 — PostgreSQL Models, Domain Services, REST API

**Target:** Weeks 3–4  
**Dependencies:** Phase 2 gate passed.

### Backlog Items

| ID | Item | Priority |
|---|---|---|
| P3-01 | Write Prisma schema for all entities (users, projects, members, findings, tasks, events, audit_events) | Must |
| P3-02 | Run and test Prisma migrations; verify constraints and indexes | Must |
| P3-03 | Implement `packages/domain` services: `FindingService`, `ProjectService`, `TaskService`, `AuditService` | Must |
| P3-04 | Implement authorization policies: `FindingPolicy`, `ProjectPolicy`, `TaskPolicy` (stub; no real OIDC yet) | Must |
| P3-05 | Implement REST endpoints for findings CRUD, status transitions, project management | Must |
| P3-05.1 | Define and document API response schema (success envelope and error shape `{ error: { code, message, details } }`), HTTP status code contract, and API versioning policy (`/api/v1/`) | Must |
| P3-06 | Add Zod validation middleware for all request bodies, query params, and path params | Must |
| P3-07 | Implement pagination and filtering for finding list endpoint | Must |
| P3-08 | Write Vitest unit tests for domain service business rules | Must |
| P3-09 | Write Supertest integration tests for REST endpoints (with test DB) | Must |
| P3-10 | Implement audit event writing for all state changes | Must |
| P3-11 | Add seed script with synthetic demo data | Should |

### Phase 3 Acceptance Criteria

- [ ] All Prisma migrations run cleanly from scratch.
- [ ] Domain service unit tests cover finding status transitions including invalid transitions.
- [ ] Supertest integration tests verify that unauthorized finding IDs return 404, not 403.
- [ ] `pnpm test` passes all unit and integration tests.
- [ ] Audit event is created for every finding state change (verified by integration test).
- [ ] No business logic resides in Express route handlers (verified by code review).

---

## Phase 4 — OIDC Authentication, Secure Sessions, RBAC + Object Authorization

**Target:** Weeks 5–6 (**High-risk security gate**)  
**Dependencies:** Phase 3 gate passed; D2 (OIDC provider) and D3 (session model) decisions confirmed.

### Backlog Items

| ID | Item | Priority |
|---|---|---|
| P4-01 | Integrate Keycloak OIDC authorization-code + PKCE flow into `apps/api` | Must |
| P4-02 | Implement BFF server-side session (HttpOnly cookie, session secret, idle expiry) | Must |
| P4-03 | Validate OIDC token: issuer, audience, expiry, signature (JWKS) | Must |
| P4-04 | JIT user provisioning on first login (create/update `users` record from OIDC claims) | Must |
| P4-05 | Implement logout: server-side session invalidation + cookie clearing + Keycloak logout | Must |
| P4-06 | Replace stub authorization policies with real session-derived principal checks | Must |
| P4-07 | Add CSRF protection for cookie-authenticated state-changing requests | Must |
| P4-08 | Add rate limiting: authentication endpoints + API endpoints | Must |
| P4-09 | Standardize 401/403/404 error responses to prevent information leakage | Must |
| P4-10 | Add security response headers (CSP, X-Content-Type-Options, X-Frame-Options, etc.) | Must |
| P4-11 | Write all 15 negative authorization test cases from [Authorization Matrix §4](04-authorization-matrix.md) | Must |
| P4-12 | Run manual AppSec checks: Burp Suite for cross-project, role escalation, CSRF | Must |

### Phase 4 Acceptance Criteria

- [ ] All 15 negative authorization tests (NEG-01 to NEG-15) pass.
- [ ] All privilege escalation scenarios (PE-01 to PE-05) are tested and denied.
- [ ] Burp Suite: intercepted session cookie cannot be replayed from a different browser without triggering session validation failure.
- [ ] Burp Suite: modified request body with `"role": "ADMIN"` has no effect on server-side authorization.
- [ ] Session expires after configured idle timeout; expired session returns 401.
- [ ] Logout clears cookie and invalidates server-side session; replaying old cookie returns 401.
- [ ] All security headers present in API responses.
- [ ] CSRF protection blocks state-changing requests without valid CSRF token.

---

## Phase 5 — React Frontend and Complete Human Workflow

**Target:** Weeks 7–8  
**Dependencies:** Phase 4 gate passed.

### Backlog Items

| ID | Item | Priority |
|---|---|---|
| P5-01 | Implement login/logout page and OIDC redirect flow in React | Must |
| P5-02 | Projects list and project detail page | Must |
| P5-03 | Findings list with filtering by status, severity | Must |
| P5-04 | Finding detail page with history/events | Must |
| P5-05 | Create finding form (Analyst only; client-side role-sensitive rendering) | Must |
| P5-06 | Assignment UI: assign finding to Developer | Must |
| P5-07 | Developer remediation submission form | Must |
| P5-08 | Analyst verify/reopen workflow | Must |
| P5-09 | Admin: project membership management page | Must |
| P5-10 | Audit event viewer (Admin only) | Should |
| P5-11 | Typed API client (shared Zod schemas) | Must |
| P5-12 | Accessible components; keyboard navigation; responsive layout | Should |
| P5-13 | Playwright e2e tests: Analyst → Developer → Analyst full workflow | Must |
| P5-14 | Playwright e2e tests: denied access scenarios (non-member, wrong role) | Must |

### Phase 5 Acceptance Criteria

- [ ] Full analyst-developer-analyst workflow completable in browser end-to-end.
- [ ] Role-sensitive UI elements hidden for unauthorized roles (UI only; API is authoritative).
- [ ] No unsafe `dangerouslySetInnerHTML` for user-controlled content.
- [ ] Playwright: happy-path workflow test passes.
- [ ] Playwright: denied-access scenarios return appropriate UI error states (not raw 403/500 JSON).
- [ ] First real application screenshots captured (not mockups).

---

## Phase 6 — MCP Server and Agentic AI Integration

**Target:** Weeks 9–10 (**Second high-risk security gate**)  
**Dependencies:** Phase 5 gate passed; D5 (MCP transport), D8 (MCP client) decisions confirmed.

### Backlog Items

| ID | Item | Priority |
|---|---|---|
| P6-01 | Confirm current MCP TypeScript SDK v2 API from official docs | Must |
| P6-02 | Implement MCP server with **Streamable HTTP transport** using `@modelcontextprotocol/express` adapter (replacing deprecated HTTP+SSE) | Must |
| P6-03 | Implement RFC 9728 Protected Resource Metadata (PRM) discovery and OAuth 2.1 Bearer token validation (JWKS, issuer, audience, expiry) | Must |
| P6-04 | Implement `list_my_findings` tool reusing `FindingService` | Must |
| P6-05 | Implement `get_finding_details` tool | Must |
| P6-06 | Implement `get_remediation_summary` tool | Must |
| P6-07 | Validate all tool arguments with Zod schemas | Must |
| P6-08 | Log all MCP tool invocations (caller, tool, redacted args, outcome) | Must |
| P6-09 | Test with real MCP client (Claude Desktop or CLI harness); record session | Must |
| P6-10 | Automated tests: unauthorized tool calls, expired token, wrong project finding | Must |
| P6-11 | Implement `propose_remediation_task` as pending-only write tool | Later |
| P6-12 | Implement approval endpoint for pending MCP action requests | Later |
| P6-13 | Prompt injection test: finding with AI instructions in description | Must |

### Phase 6 Acceptance Criteria

- [ ] Real MCP client can list and retrieve the authenticated principal's authorized findings.
- [ ] MCP client with another project's finding UUID receives a denial.
- [ ] Expired/invalid Bearer token returns tool auth error.
- [ ] Finding description containing AI instruction text is treated as data; no elevated backend action occurs.
- [ ] All 7 mandatory abuse cases from [PROJECT_ROADMAP.md §6](../PROJECT_ROADMAP.md) are demonstrated.
- [ ] MCP tool invocation log entry created for every call (verified by integration test).

---

## Phase 7 — DevSecOps, Penetration Tests, and Evidence

**Target:** Weeks 11–13  
**Dependencies:** Phase 6 gate passed; controls should have been added incrementally in Phases 2–6.

### Backlog Items

| ID | Item | Priority |
|---|---|---|
| P7-01 | Complete GitHub Actions pipeline: lint, typecheck, unit, integration, build, Docker smoke test | Must |
| P7-02 | Enable CodeQL default setup for the repository | Must |
| P7-03 | Enable Dependabot (dependency graph + SCA alerts + PRs) | Must |
| P7-04 | Enable GitHub secret scanning | Must |
| P7-05 | Run OWASP ZAP baseline passively against isolated test deployment | Must |
| P7-06 | Manual AppSec review: BOLA/IDOR, role escalation, CSRF, injection, output encoding, session expiry, MCP identity | Must |
| P7-07 | Create verification matrix: threat → control → test → result | Must |
| P7-08 | Triage and document CodeQL + ZAP findings; no silent suppression | Must |
| P7-09 | Harden GitHub Actions: least privilege tokens, pin actions to SHAs | Must |
| P7-10 | Container image scanning (if feasible) | Should |

### Phase 7 Acceptance Criteria

- [ ] CI pipeline green on every PR; no jobs skipped to obtain green status.
- [ ] CodeQL enabled; no unresolved critical/high findings within release scope.
- [ ] Dependabot PRs reviewed and merged or documented as false positive.
- [ ] Secret scanning enabled; no secrets detected in commit history.
- [ ] ZAP baseline report reviewed; findings triaged with documented rationale.
- [ ] Manual AppSec checklist completed and evidence recorded in `tests/security/`.
- [ ] Verification matrix links every threat in the threat model to a control and test result.
- [ ] No claim of "100% secure" or "OWASP certified" in any documentation.

---

## Phase 8 — Release Engineering, Documentation, and Portfolio Launch

**Target:** Weeks 14–16  
**Dependencies:** Phase 7 gate passed.

### Backlog Items

| ID | Item | Priority |
|---|---|---|
| P8-01 | Choose release path: Docker demo + recording OR live demo (decide per D6) | Must |
| P8-02 | Polish `README.md`: setup, architecture summary, known limitations, demo instructions | Must |
| P8-03 | Create `SECURITY.md` with vulnerability reporting policy | Must |
| P8-04 | Create `docs/security-design.md` with architecture/authorization/MCP design summary | Should |
| P8-05 | Record 2–4 minute demo video showing full workflow + MCP tool use | Must |
| P8-06 | Capture final application screenshots (real UI, synthetic data) | Must |
| P8-07 | Remove any secrets/sensitive history; audit commit history | Must |
| P8-08 | Tag `v1.0.0`; verify green CI on tag | Must |
| P8-09 | Pin repository on GitHub | Should |
| P8-10 | If live demo: configure reverse proxy + HTTPS, no DB port exposure, cost controls | Later |

### Phase 8 Acceptance Criteria

- [ ] An unrelated developer/recruiter can understand the use case in 2 minutes from the README.
- [ ] Environment can be reproduced from documented bootstrap instructions.
- [ ] Demo video shows real MCP client interaction with synthetic data.
- [ ] `v1.0.0` tagged with green CI.
- [ ] No secrets, production credentials, or real vulnerability payloads in the published repository.

---

## Release Milestone Summary

| Version | Scope | Evidence |
|---|---|---|
| `v0.1` | Workspace + DB + minimal API + health check | Clone, build, run, test |
| `v0.5` | Full remediation workflow + enforced auth | Negative auth tests + Playwright e2e |
| `v0.8` | Real MCP client + authorized tools | MCP session recording + abuse tests |
| `v1.0.0` | Security gates + polished docs + deployable demo | Public review-ready repository |

---

## Cross-Cutting Mandatory Items (every phase)

| Item | Phase |
|---|---|
| No hardcoded secrets in any committed file | Every phase |
| Authorization logic only in `packages/domain` — never in controllers | Phase 3+ |
| Every state-changing operation writes an audit event | Phase 3+ |
| All request inputs validated with Zod before use | Phase 3+ |
| Security response headers on all responses | Phase 4+ |
| No stack traces or internal paths in error responses | Phase 3+ |
| New dependencies reviewed for security before adding | Every phase |
| No silent test skip to obtain green CI | Every phase |
| PR review before merge to main (even solo project) | Phase 2+ |

---

## Phase Gate Summary

| Gate | What Developer Must Sign Off | Antigravity Stops and Waits |
|---|---|---|
| **P1 → P2** | All documents reviewed; open decisions D1–D10 resolved | ✅ After this document |
| **P2 → P3** | Workspace runnable; CI green; no secrets committed | ✅ |
| **P3 → P4** | API + DB working; all domain service tests passing | ✅ |
| **P4 → P5** | All 15 negative auth tests pass; Burp Suite manual check done | ✅ |
| **P5 → P6** | Full human workflow e2e test passing; real screenshots captured | ✅ |
| **P6 → P7** | Real MCP client demo; abuse tests pass; prompt injection tested | ✅ |
| **P7 → P8** | CodeQL + ZAP + Dependabot clean; manual AppSec checklist done | ✅ |
| **v1.0.0 release** | Demo video + README + secrets audit + tag | ✅ |
