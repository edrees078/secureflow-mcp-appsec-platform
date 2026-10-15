# SecureFlow — Master Development Roadmap

**Repository / workspace:** `secureflow-mcp-appsec-platform`  
**Local Windows project root:** `D:\GitProjects\secureflow-mcp-appsec-platform`  
**Project:** SecureFlow — Secure Findings & Remediation Management Platform with MCP  
**Document version:** 1.0 — 2026-10-15  
**Status:** Proposed plan; architecture and choices require developer approval.

> **How to use this document:** Put this file in the root of the workspace above. Give Antigravity one phase or small task at a time. Require a written plan, review the changes, run relevant tests, and only then advance. The companion `ANTIGRAVITY_FIRST_PROMPT.md` is the first task to paste into Antigravity. This file is not evidence that any code or security control has already been implemented.

---

## 1. Vision, audience, and portfolio objective

SecureFlow is a full-stack web application for tracking application-security findings, assigning remediation work, reviewing resolutions, and keeping an audit trail. A separately exposed MCP server gives an AI client **controlled access to selected application capabilities**. The system is meant to demonstrate realistic engineering decisions, not merely collect buzzwords.

**Target portfolio competencies:**

1. **Software Engineering:** React + TypeScript; Node.js + Express; PostgreSQL; modular design; tested REST API; migrations; maintainable domain services.
2. **Application Security:** OIDC authentication; session protection; backend RBAC and resource authorization; validation; rate limiting; logging; threat modeling; negative tests.
3. **Agentic AI / MCP:** a real MCP server and demonstrated MCP client, scoped tools, prompt-injection boundaries, carefully approved write actions.
4. **DevSecOps:** Docker; GitHub Actions; SAST (CodeQL); SCA (Dependabot/dependency auditing); ZAP; documented security gates and deployment.

**Primary audiences:** a technical recruiter, software engineer, AppSec engineer, and a developer evaluating or running the repository.

**Definition of product value:** a team can create findings, assign remediation work to authorized project members, update status, and show what changed. An AI client can fetch **only the requesting principal's authorized findings** and propose work without silently executing privileged actions.

**Not in the MVP:** payments, chat, real-time multiuser collaboration, microservices, Kubernetes, multi-organization SaaS tenancy, vulnerability exploitation, unrestricted autonomous remediation, or a custom OAuth authorization server.

**Scope decision:** MVP has multiple projects, each with members and project-scoped permissions, inside a single organization/demo environment. Full multi-tenancy is a separate future feature.

---

## 2. Provisional architecture and technology decisions

| Concern | Proposed choice | Why / constraints |
|---|---|---|
| Frontend | React, TypeScript, Vite | Type-safe, focused SPA |
| Backend | Node.js LTS, Express, TypeScript | Familiar ecosystem; small modular-monolith design |
| DB | PostgreSQL | Relationships, constraints, migrations, transactions |
| Database tooling | **Propose Prisma**, confirm in Phase 1 | Pick Prisma *or* Drizzle, not both |
| Monorepo | pnpm workspaces | One lockfile, shared schema/domain packages |
| Runtime validation | Zod | Treat request bodies, query parameters, MCP tool arguments and config as untrusted |
| Identity | Standards-compliant OIDC provider; **Keycloak as local candidate** | Do not implement identity provider or password storage yourself |
| Browser session | BFF/server-managed session; OIDC authorization-code flow + PKCE as appropriate | Minimize browser token exposure; document cookie/CSRF design |
| Authorization | Role + project membership + resource ownership checks in services | UI visibility is never sufficient |
| Logging | Pino plus append-only audit events | Separate diagnostics and security-relevant records; redact secrets |
| MCP | Official TypeScript SDK v2, current MCP specification | Start read-only; implement proper caller identity and authorization before remote release |
| Containers | Docker Compose | Developer-friendly local stack; no production DB port exposure |
| Tests | Vitest, Supertest, Playwright | Unit, API/integration and UI/e2e layers |
| Security tooling | CodeQL, Dependabot/SCA, OWASP ZAP, secret scanning | Layered assurance; no scanner proves absence of vulnerabilities |
| Deployment | Later decision: documented local Docker demo vs small VPS | Choose cost, safety, operational maintenance explicitly |

**Architecture pattern:** `apps/web` -> `apps/api` -> shared application/domain services -> PostgreSQL. `apps/mcp-server` -> **the same shared authorization and domain services** -> PostgreSQL through the approved application data-access layer. Never let MCP bypass application authorization or accept an unauthenticated hardcoded production principal.

**Identity note:** The browser's OIDC login/session and remote MCP OAuth access are related but **different trust boundaries**. Do not assume a browser cookie automatically authenticates an external MCP client. Define a resource-server strategy, token audience validation, user context, and per-tool scope controls before enabling protected HTTP tools.

**MCP note:** An MCP server is **not the AI agent itself**. Version 1.0 should show an actual AI/MCP client calling authorized tools; a custom chatbot interface is optional.

### Intended directory structure (for Phase 2; do not precreate everything in Phase 1)

```text
secureflow-mcp-appsec-platform/
├── apps/
│   ├── web/
│   ├── api/
│   └── mcp-server/
├── packages/
│   ├── domain/
│   ├── schemas/
│   └── shared/
├── docs/
│   ├── decisions/
│   ├── security/
│   └── screenshots/
├── infra/
│   ├── docker/
│   └── zap/
├── tests/
│   ├── e2e/
│   └── security/
├── .github/
│   └── workflows/
├── PROJECT_ROADMAP.md
├── ANTIGRAVITY_FIRST_PROMPT.md
├── README.md
├── SECURITY.md
├── .env.example
├── .gitignore
├── compose.yaml
└── package.json
```

Structure is an architectural intent, not a requirement to add empty files or unnecessary abstractions.

---

## 3. MVP user journeys and business rules

### Roles

- **Admin:** manage project membership; manage findings; review audit events.
- **Security Analyst:** create/triage project findings; assign work; verify remediation where project membership permits.
- **Developer:** access only assigned/authorized projects and findings; update remediation progress; cannot self-approve closure or elevate privileges.

These are *roles*, not substitutes for verifying the specific project/finding on every request.

### Finding workflow

Suggested states: `OPEN -> TRIAGED -> IN_PROGRESS -> READY_FOR_REVIEW -> VERIFIED/CLOSED`, with `REOPENED` when verification fails. A final state transition must be checked against the role, membership, current state, and any assignment requirement. Changes are audited.

**Critical workflows:**

1. Admin creates a project and assigns an Analyst and Developer.
2. Analyst creates a finding and remediation assignment.
3. Developer sees only authorized work and submits a proposed resolution.
4. Analyst verifies and closes/reopens the finding.
5. Admin reviews an audit trail.
6. MCP client retrieves the caller's authorized findings and produces a summary.
7. A write-capable MCP tool (if enabled) creates a **pending proposed action**, not a silent privileged change.

### Sample data model

`users`, `projects`, `project_members`, `findings`, `remediation_tasks`, `finding_events`, `audit_events`, and later `mcp_action_requests`. Clarify uniqueness, FK constraints, soft deletion/retention, UUIDs, indexes, transactional transitions, and concurrency before implementing.

### Security invariants (apply to *every* phase)

- Deny by default; authenticate, authorize, and validate every state-changing request.
- Never trust frontend access control, TypeScript static types, client-supplied role names, or AI-produced arguments.
- Object-level checks must include project membership and permissible action (prevent IDOR/BOLA).
- Use a supported OIDC library/provider; never implement passwords or OAuth provider functionality from scratch.
- Never put real tokens, passwords, `.env` secrets, private data, or production database dumps in git or agent prompts.
- Do not place actual attacker-ready vulnerable endpoints in the public SecureFlow application. Security testing belongs in isolated test environments.
- Tool descriptions, retrieved findings, and LLM output are untrusted; all MCP actions must be enforced by trusted backend code.
- Retain only necessary security-log fields; redact secrets and sensitive data.
- Run dangerous scans only against systems/environments you own or are explicitly authorized to test.

---

## 4. Eight-phase implementation plan

**Estimated schedule:** ~12–16 weeks at ~10–15 focused hours/week, depending on experience, feedback, and tool integration friction. **These are planning estimates, not deadlines.** Build in small feature branches; avoid massive agent-generated commits.

### Phase 1 — Product definition, architecture, and security design

**Target:** Week 1. **Starts now. No app implementation code.**

**Tasks**
- Confirm persona/use cases, MVP and non-goals, workflow and transition rules, privacy assumptions, success metrics.
- Prepare a requirements document with numbered functional and nonfunctional requirements.
- Choose modular-monolith boundaries, service/data-access design, runtime and library candidates; record major decisions as ADRs.
- Define role/resource/action matrix (including negative scenarios and cross-project checks).
- Sketch PostgreSQL ERD, API resource inventory, MCP tool inventory and trust boundaries.
- Draft STRIDE-based threats, mitigations and **testable** evidence; map relevant items to OWASP ASVS 5.0.0 identifiers where validated, avoiding invented IDs.
- Define risks/costs and measurable phase acceptance criteria; decide which choices require explicit approval.

**Deliverables**
- `docs/01-product-requirements.md`
- `docs/02-architecture.md`
- `docs/03-data-model.md`
- `docs/04-authorization-matrix.md`
- `docs/05-threat-model.md`
- `docs/06-backlog-and-acceptance.md`
- `docs/decisions/0001-modular-monolith.md`
- Optional lightweight root `README.md` only after agreeing on naming/scope.

**Gate P1 -> P2:** documents are consistent; user has signed off on scope, data model, roles, session architecture, MCP trust boundaries and implementation order. **Nothing has been installed or deployed.**

### Phase 2 — Monorepo foundation, tooling and local services

**Target:** Week 2.

**Tasks**
- Initialize Git locally (only with approval); confirm repo visibility strategy and `.gitignore`.
- Set up pnpm workspaces; TypeScript strict, lint, formatting, common scripts and centralized configuration checks.
- Scaffold React frontend, Express API, shared domain/schemas (MCP can remain a placeholder until Phase 6).
- Add Docker Compose for **development only** PostgreSQL and, if approved, local OIDC provider. Use volumes, health checks, no real secrets, loopback-only service bindings where appropriate.
- Set up CI lint, type-check, build, fast unit smoke tests and basic README bootstrap.
- Add `.env.example`, never a real `.env`; document supported Node/pnpm versions.

**Deliverables:** runnable development workspace, compose configuration, starter CI workflow, `.env.example`, bootstrap instructions.

**Gate:** another developer can clone, configure local `.env`, start services, pass lint/typecheck/tests and reproduce the environment. No real secrets committed; no unrelated directories touched.

### Phase 3 — PostgreSQL models, domain services, REST API

**Target:** Weeks 3–4.

**Tasks**
- Design migrations/constraints for users, projects, membership, findings, assignments and audit events.
- Implement service boundaries and repository/data-access layer; avoid business rules living only in Express controllers.
- Implement pagination, filtering, status transitions and transactionally safe updates.
- Validate params/body/query using Zod, handle errors consistently, reject unknown forbidden fields, use safe DB operations.
- Implement audit event production for create/update/assignment/status changes.
- Build unit and PostgreSQL-backed integration tests with disposable test data; seed only synthetic demo content.

**Suggested REST endpoints (finalize after P1):**

```http
GET    /api/v1/projects
POST   /api/v1/projects
GET    /api/v1/findings
POST   /api/v1/findings
GET    /api/v1/findings/:id
PATCH  /api/v1/findings/:id
POST   /api/v1/findings/:id/submit-remediation
POST   /api/v1/findings/:id/verify
GET    /api/v1/audit-events
GET    /health/ready
```

**Gate:** API works against PostgreSQL with migrations and tests; validation and domain rules have automated coverage; API access is not exposed publicly before authorization is in place.

### Phase 4 — OIDC authentication, secure sessions, RBAC + object authorization

**Target:** Weeks 5–6. **High-risk security gate.**

**Tasks**
- Integrate a supported OIDC provider; document authorization-code/PKCE flow and audience/issuer validation.
- Design a server-side session/BFF approach; secure cookie attributes, session expiry and logout; CSRF protections where cookie-based mutation requires them.
- Derive the authorized principal server-side; never trust role, tenant/project or user ID submitted by client.
- Enforce membership/permissions in shared domain services; incorporate lifecycle state rules and delegated operations.
- Cover attempted cross-project reads, privilege escalation, self-approval, unassigned developer updates, parameter tampering and role-change races.
- Apply appropriate rate limits to authentication-sensitive and API endpoints; standardize 401/403/404 handling to avoid leaks.

**Gate:** modified requests in Burp Suite and automated tests cannot read/update another project's records; role enforcement is tested on REST and reused by domain services; session/security behavior documented. Do **not** claim security based only on hidden UI controls.

### Phase 5 — React frontend and complete human workflow

**Target:** Weeks 7–8.

**Tasks**
- Build login/logout experience, projects, findings list, finding details, assignment, remediation review and admin membership screens.
- Typed API client, clear loading/error/empty states, forms with validation, accessible components and responsive layout.
- Implement role-sensitive UI while treating API authorization as the real enforcement point.
- Escape/render descriptions safely; no unsafe raw user-controlled HTML; protect against accidental disclosure in error UI.
- Add Playwright tests covering analyst->developer->analyst workflow, authorized access and selected denied interactions.

**Gate:** a user can complete the main scenario through the browser and test cases cover both success and denial. Capture first real application screenshots (not mockups) only when features actually exist.

### Phase 6 — MCP server and Agentic AI integration

**Target:** Weeks 9–10. **Second high-risk security gate.**

**Tasks**
- Confirm current stable MCP specification/TypeScript SDK v2 API and the transport/security model. Avoid outdated v1 tutorials.
- Start with **read-only** tools: `list_my_findings`, `get_finding_details`, `get_remediation_summary`.
- Reuse backend domain services and policy checks; never implement an MCP-specific shortcut to the database.
- Establish authenticated caller identity, appropriate OAuth/access-token resource validation (including issuer, audience, scopes) for remote HTTP use. A local dev-only identity shim, if any, must be explicit and impossible to enable in production.
- Validate every tool argument, limit results, redact sensitive data, log relevant access, prohibit token passthrough.
- Test a real MCP client and record request/response and authorization evidence using only synthetic data.
- Later add `propose_remediation_task` as a **pending approval** action (not automatically mutate findings). Reauthorize at approval/execution time.
- Test prompt injection in finding descriptions, resource escalation, tool abuse and inappropriate writes. Untrusted content must not override backend restrictions.

**Gate:** actual client demonstrates authorized read; denied caller/tool cannot access a forbidden finding; prompt-injection test cannot bypass backend rules; controlled write, if present, requires explicit authorization and approval.

### Phase 7 — DevSecOps, penetration tests, and evidence

**Target:** Weeks 11–13. **Controls and tests should have been added incrementally in P2–P6.**

**Tasks**
- GitHub Actions jobs: lint, type-check, unit/integration tests, build and Docker smoke test.
- Enable CodeQL default setup for an eligible repo first; adopt advanced config only when needed. Avoid duplicate scanning configurations.
- Enable dependency graph, Dependabot/SCA, secret scanning/secret hygiene; scan container images if feasible.
- Run OWASP ZAP baseline passively against isolated test deployment. Active DAST only with explicit consent against disposable/synthetic infrastructure.
- Manual AppSec checks: BOLA/IDOR, role escalation, CSRF, injection, output encoding, sensitive logging, session expiry, MCP identity and action approval.
- Create a verification matrix mapping threat -> security requirement -> control -> test -> result; triage scanner false positives transparently.
- Harden GitHub Actions: least privilege, pin third-party actions to verified full commit SHAs where practical, no secrets for untrusted PR code.

**Gate:** reproducible test runs and scan artifacts; no unresolved critical/high findings within defined release scope; remaining issues documented with rationale and dates. Never claim an app is '100% secure' or 'OWASP certified'.

### Phase 8 — Release engineering, documentation and portfolio launch

**Target:** Weeks 14–16.

**Tasks**
- Choose **one** release presentation path: (A) reproducible Docker demo + recording; or (B) safely operated public demo. Live hosting is optional.
- If public: reverse proxy + HTTPS, database not publicly exposed, least-privilege services, backups/restore test, safe deployment secrets, maintenance and cost limits.
- Prepare `README.md`, `SECURITY.md` (reporting policy), separate `docs/security-design.md`, architecture/ERD, runbook, API/MCP reference, demo users with fake data.
- Include screenshots from the real application, 2–4 minute demonstration, environment bootstrap and teardown instructions, known limitations and release notes.
- Make the repo public only after removing secrets/sensitive history and reviewing all published content.
- Tag `v1.0.0`, confirm green CI, document how to reproduce tests. Pin on GitHub when worthy of review.

**Gate:** an unrelated developer/recruiter can understand the use case in 2 minutes, reproduce a working installation, review the architecture/authorization and security evidence, and watch a successful MCP-powered demonstration.

---

## 5. Incremental release milestones

| Version | Scope | Portfolio evidence |
|---|---|---|
| `v0.1` | Workspace + database + minimal API and UI | Clone, build, run, test |
| `v0.5` | Functional remediation workflow and enforced auth | Negative authorization tests + workflows |
| `v0.8` | Real MCP client and protected tool calls | Demonstration + MCP abuse tests |
| `v1.0.0` | Security gates, polished docs and deployable demo | Public review-ready repo |

**Version labels are targets, not automatic release dates.**

---

## 6. Testing and release criteria (quantitative targets are provisional)

- CI on each PR: dependency installation, lint, strict typecheck, relevant unit/integration tests, production build.
- No known hardcoded production secrets. All committed seed data is fake.
- Critical unauthorized read/write paths (REST **and** MCP) have explicit negative tests; cross-project BOLA/IDOR tests are mandatory.
- Every MCP tool maps to a named capability, caller identity, validated input and authorized service operation.
- Main browser workflow has automated end-to-end coverage; failures documented/reproducible.
- Security checks and scan reports do not get silently bypassed to obtain green CI.
- Critical/high unresolved vulnerabilities block public release unless objectively determined false positives with written evidence; remaining lower-severity risk tracked.
- Documentation includes runnable commands, versions, prerequisites, architecture, known limitations and no fabricated badges/metrics.
- Coverage percentages, latency thresholds, and exact CI scan cadence should be decided from actual code/test risk, not invented early.

### Mandatory demonstrable abuse cases

1. Developer queries another project's finding ID -> denied without sensitive response data.
2. Developer attempts an analyst-only `verify`/close transition -> denied and audited.
3. MCP tool is invoked with another project's finding ID -> denied by the **same application policy**.
4. Finding description contains malicious AI instructions -> treated as data; no elevated backend action.
5. Proposed AI write is executed without authorization/approval -> denied.
6. Invalid or expired sessions/tokens -> appropriate denial.
7. Invalid/oversized input and excessive request rate -> controlled response, no crash/data corruption.

---

## 7. Agent operating agreement — mandatory for every Antigravity task

1. The only workspace is **`D:\GitProjects\secureflow-mcp-appsec-platform`**. Do not read/modify sibling projects in `D:\GitProjects` without explicit authorization.
2. Use plan -> review -> scoped implementation -> verification -> human review -> commit. Do **not** request the entire project in one prompt.
3. Before edits, list intended files, commands, dependencies and their risks. Request approval for new dependencies, migrations, auth architecture, network calls, destructive commands, Git operations and deployment.
4. Never silently delete, overwrite, reset or reformat user files; never push to remote, deploy, alter global environment or open firewall ports without specific approval.
5. No real secrets in source/prompt/logs. Keep `.env` out of Git; provide only `.env.example`.
6. Do not introduce unnecessary abstractions or substitute tools outside the agreed stack without explaining trade-offs.
7. Every change must state: what changed, why, how tested, test output/results, security implications and unresolved questions.
8. A green scanner is not equivalent to authorization correctness. Test with another role and another project.
9. Use public official documentation for security-sensitive standards and current SDK APIs; reference sources.
10. Pause at each phase gate and wait for human approval.

---

## 8. First action: exactly what to do in Antigravity

1. Confirm Antigravity has opened the **existing local folder** `D:\GitProjects\secureflow-mcp-appsec-platform` (not the parent `D:\GitProjects`).
2. Copy this `PROJECT_ROADMAP.md` file and `ANTIGRAVITY_FIRST_PROMPT.md` to that folder's root. You don't need to connect GitHub yet.
3. In Antigravity settings, choose **Request Review** for terminal execution if available, deny/ask for file access outside the project, and keep agent changes reviewable. Avoid broad auto-execute permission settings.
4. Use the agent's **Planning Mode** if available. Paste the **entire prompt body** from `ANTIGRAVITY_FIRST_PROMPT.md` into the agent. On an interface supporting `/plan`, that is also a documented way to initiate structured review, but you may need to approve document writes after the plan is presented.
5. **First result expected:** draft/reviewable Phase 1 documents only. **Not expected:** `node_modules`, package installs, a database, API routes, React components, server credentials, deployment, or a GitHub repo yet.
6. Review the output against the Phase 1 gate. Resolve the open decisions **before** asking Antigravity to scaffold Phase 2.

### What to send back for review

Provide Antigravity's Phase 1 plan/output, proposed tree of files, any questions/architecture choices, and any warnings. Review them before giving it another implementation prompt.

---

## 9. Decisions to explicitly approve at Phase 1 gate

- Name/tagline and exact MVP boundary.
- Single organization with project-scoped roles vs full multi-tenancy (recommend **single organization** for MVP).
- Prisma vs Drizzle (recommend **Prisma** provisionally).
- Session model, OIDC provider and local testing approach.
- Which operations are analyst-only vs developer and whether developer can see all project findings or only assigned findings.
- Finding statuses and valid transitions.
- Whether a public online demo is necessary (recommend decide after stable v0.8).
- Which MCP client to demonstrate and remote authentication details.
- First AI operation: read-only summaries; proposed writes only after review workflow exists.
- License and whether to publish source immediately or after security review.

---

## 10. Official documentation / primary references

The following sources are authoritative starting points. Check published documentation and dependency versions again **when implementing**, because protocols and tooling can change.

1. **Google Antigravity — IDE overview:** https://www.antigravity.google/docs/ide/overview/
2. **Google Antigravity — Settings and project permissions:** https://www.antigravity.google/docs/settings?tab=ide
3. **Google Antigravity — Planning:** https://antigravity.google/docs/plan/
4. **MCP current specification:** https://modelcontextprotocol.io/specification
5. **Official MCP TypeScript SDK v2:** https://ts.sdk.modelcontextprotocol.io/v2/
6. **OWASP MCP Security Cheat Sheet:** https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html
7. **OWASP Application Security Verification Standard, stable 5.0.0:** https://github.com/OWASP/ASVS
8. **OWASP Authorization Cheat Sheet:** https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html
9. **GitHub CodeQL/code scanning setup:** https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/configure-code-scanning/configure-code-scanning
10. **GitHub Actions security guidance:** https://docs.github.com/en/actions/reference/security/secure-use
11. **OWASP ZAP Baseline Scan:** https://www.zaproxy.org/docs/docker/baseline-scan/
12. **OWASP ZAP Automation Framework:** https://www.zaproxy.org/docs/automate/automation-framework/
13. **OpenID Connect specifications:** https://openid.net/developers/specs/
14. **Docker Compose documentation:** https://docs.docker.com/compose/

---

*Project philosophy: evidence over labels; controls over badges; maintainability over technology count; explicit approval over autonomous risky actions.*
