# First Antigravity Prompt — SecureFlow Phase 1

**Instructions for the human developer:** Copy this file and `PROJECT_ROADMAP.md` into `D:\GitProjects\secureflow-mcp-appsec-platform`. Open exactly that folder in Antigravity. Copy the entire text **inside the prompt section below** into the Agent chat. Prefer Planning Mode / reviewable planning artifacts where available. Review any proposed file changes before approving them. This prompt deliberately stops at Phase 1 design — it is **not** a request to build the whole app.

---

## START OF PROMPT — COPY FROM HERE

You are assisting me as a senior full-stack software architect, application security engineer, DevSecOps engineer, and technical mentor. We are starting a new serious GitHub portfolio project. I want production-oriented engineering practices, but a small, finishable MVP.

### Project identity and absolute workspace boundary

- Project name: **SecureFlow — Security Findings & Remediation Management Platform with MCP**.
- Repository folder name: `secureflow-mcp-appsec-platform`.
- My local Windows workspace root: `D:\GitProjects\secureflow-mcp-appsec-platform`.
- This folder is already created and opened in Antigravity; do not create a second nested project folder.
- **Treat this folder as the only approved filesystem scope.** Do not inspect or edit the parent `D:\GitProjects` or any sibling project. Do not use files from my other projects unless I provide them.
- Read `PROJECT_ROADMAP.md` at the workspace root first. It defines the ordered phases, goals, assumptions, security invariants, and phase-gate requirements. If it is missing or conflicts with my instructions, stop and ask rather than inventing a replacement.

### Career and engineering objective

I am building this project to demonstrate competence in:
1. Software Engineering (React/TypeScript, Node.js/Express, PostgreSQL, testing, architecture).
2. Application Security (OIDC, secure sessions, RBAC + object-level checks, audit logging, input validation, rate limiting, threat modeling).
3. Agentic AI (a genuinely working Model Context Protocol server accessed by a real client, with tightly controlled tools).
4. DevSecOps (Docker, GitHub Actions, CodeQL, dependency security/SCA, OWASP ZAP, deployment hardening).

The project must solve a real workflow, not be a generic collection of technologies or an intentionally vulnerable app. Build **a security findings and remediation management application**. Admins manage access, analysts record and verify findings, and developers remediate assigned issues. An MCP server later lets an AI client read authorized findings and propose changes through explicit approval.

### Draft MVP boundaries

- One organization/demo environment with multiple projects and project membership; **no multi-organization SaaS tenancy for MVP**.
- Roles: Admin, Security Analyst, Developer. Backend enforcement is mandatory; resource authorization must account for the caller's project membership and assigned work.
- Finding statuses and authorized transitions must be explicitly designed.
- Essential records: users, projects, project members, findings, remediation tasks, audit events. Optional later: MCP action approval requests.
- Do not add billing, chat, Kubernetes, microservices, autonomous exploitation, payments, or a large multi-agent system.

### Technical direction (provisional; justify alternatives, do not silently switch)

- Frontend: React, TypeScript, Vite.
- Backend: Node.js LTS, Express, TypeScript.
- DB: PostgreSQL; propose Prisma unless you have a compelling reason to recommend Drizzle.
- Monorepo with pnpm workspaces and shared runtime validation schemas using Zod.
- Authentication: a standards-compliant OIDC provider (Keycloak is an option for local development). Use established protocols/libraries; do not build a password manager or OAuth authorization server from scratch.
- Browser security: propose a robust server-managed session/BFF architecture. Address OAuth PKCE/issuer/audience, cookie flags, expiry/logout, CSRF and CORS as applicable.
- Authorization: deny by default, enforce roles **and resource/project membership** in shared domain services for both REST and MCP.
- MCP: official stable TypeScript SDK v2, check current official documentation when we reach the implementation phase. Distinguish MCP server from AI client and distinguish remote MCP OAuth authorization from browser login.
- Logging: structured operational logs and separate security audit events, with sensitive-data redaction.
- DevSecOps: Docker Compose, GitHub Actions, CodeQL, SCA/Dependabot, ZAP baseline, manual authorization checks, OWASP ASVS 5.0.0 verification mapping.

### IMPORTANT: scope of THIS FIRST TASK (Phase 1 ONLY)

**Do not implement application code yet.** No React components, APIs, migrations, runtime package files, Docker images, authentication servers, MCP servers, test runners, dependency installation, Git initialization, remote GitHub actions, environment modification, deployments or shell/terminal commands in this first task.

Your job is to *design and document* the project foundation, ensuring the documents are internally consistent and reviewable. You may propose creating/editing **only** the Markdown files listed below, under the current workspace, after presenting a brief plan for my review. If your Planning Mode is read-only, prepare the plan/artifact first and ask for approval to write the Markdown files; do not bypass the review process.

Please propose and then, when review permits, create:

1. `docs/01-product-requirements.md`:
   - Product vision, target audience, assumptions, MVP/non-goals.
   - Roles/personas and realistic end-to-end user stories.
   - Numbered functional requirements (FR-001...) and nonfunctional/security requirements (NFR/SEC-...).
   - Acceptance criteria phrased so we can test them.
2. `docs/02-architecture.md`:
   - Modular monolith and proposed monorepo boundaries.
   - Browser, API, identity provider, database, MCP client and MCP server trust boundaries.
   - Mermaid diagrams (context and container/service flow) that render correctly in Markdown.
   - Why shared authorization/domain services are necessary and whether MCP calls services directly or through an internal API.
   - Proposed OIDC browser session model and *separate* remote MCP authentication model, explicitly marking open decisions.
3. `docs/03-data-model.md`:
   - A Mermaid ER diagram for users, projects, memberships, findings, tasks, audit logs, and optional pending MCP actions.
   - Proposed fields/relations/constraints/indexes (avoid premature low-level SQL).
   - Status transitions and transactional/concurrency requirements.
4. `docs/04-authorization-matrix.md`:
   - Role x action matrix including project membership, assignee-only permissions, and administrative operations.
   - Object-level authorization invariants, REST and MCP parity.
   - At least 10 negative authorization test scenarios with expected deny outcomes.
5. `docs/05-threat-model.md`:
   - Assets, entry points, data flows, trust boundaries and attacker assumptions.
   - STRIDE-oriented table with threats, impacts, specific mitigations and verification/test evidence.
   - Cover BOLA/IDOR, privilege escalation, session/CSRF, injection, sensitive log data, secrets, CI supply chain, MCP token misuse, prompt injection/tool-output poisoning, confused-deputy risk, and unauthorized agent-driven state changes.
   - Reference validated OWASP ASVS v5.0.0 requirements where possible; do not invent ASVS IDs, requirements, or claims of certification.
6. `docs/06-backlog-and-acceptance.md`:
   - Ordered Phase 1 through Phase 8 backlog with small implementation milestones, dependencies, deliverables, definitions of done, and tests.
   - Label items Must/Should/Later. Include recommended first 5 small development tasks for Phase 2 *only* as a plan; do not implement them.
   - List the phase gates and explicitly flag what needs my approval.
7. `docs/decisions/0001-modular-monolith.md`:
   - Short architecture decision record: context, options, decision recommendation, risks and consequences.

**Avoid duplicate content:** Make each document purposeful and cross-link to related sections; use `PROJECT_ROADMAP.md` as the umbrella plan rather than generating a second incompatible roadmap. Do not modify `PROJECT_ROADMAP.md` or `ANTIGRAVITY_FIRST_PROMPT.md`.

### Explicit security and execution boundaries

- Do not execute commands, install packages, access external accounts, connect APIs, run containers, initialize git, push commits, or deploy anything in this first task.
- Do not create/edit files outside the seven explicitly allowed Markdown paths. Do not modify global or workspace security settings.
- Do not create real credentials, copy sensitive data, or generate production `.env` files.
- Do not silently overwrite existing files; list any existing files and ask first.
- Do not enable high-autonomy/auto-approval behavior or invoke external agents/tools without asking.
- Treat security advice as recommendations to be verified against official specs rather than as guarantees.
- If tools cannot create the files without executing commands, present the full Markdown content for review rather than using a prohibited command.

### Required order of work and reporting

**Step A — Read and inspect (read-only):** Confirm the current project root, whether `PROJECT_ROADMAP.md` exists and whether the seven target files already exist. Do not inspect parent/sibling folders.

**Step B — Planning artifact:** Summarize understanding of SecureFlow, document boundaries, proposed choices, inconsistencies, and specific questions requiring approval. Show the precise list of files you intend to create. Do not start Phase 2.

**Step C — Documentation:** Once allowed by the review workflow, create *only* the Phase 1 Markdown files above. Prefer concrete, technically realistic details and diagrams rather than marketing-style prose.

**Step D — Self-review:** Verify paths, relative links, Markdown and Mermaid syntax, cross-document consistency, no invented test results, no secrets, and no unwanted files. Do not claim any tests or applications ran.

**Step E — Final status:** Give me:
- The complete list of new/changed files.
- A short overview of the proposed product and trust boundaries.
- Architecture tradeoffs and decisions I must approve (ORM, OIDC/session model, per-project permissions, MCP transport/auth, public demo choice).
- Any unresolved security or scope questions.
- Clear Phase 1 acceptance criteria and a proposed starting task for Phase 2.
- An explicit statement that **no application code, dependencies, commands, databases, or deployments were executed or created** (if true).

**Stop after Phase 1 and wait for my approval.** Do not proceed to implementation just because the design seems complete.

## END OF PROMPT

---

## What a successful first response looks like

- Antigravity understands that `secureflow-mcp-appsec-platform` is the root and that the Markdown roadmap is authoritative.
- It proposes a design and the **seven named Markdown documents**; it may ask a few focused architecture questions.
- It does **not** install packages or create a new nested `secureflow` directory.
- It waits for review at the Phase 1 gate; no actual features are falsely represented as built.

**Next human action:** Review the Phase 1 outputs; only then commission Phase 2 workspace scaffolding in a *new, bounded prompt*.
