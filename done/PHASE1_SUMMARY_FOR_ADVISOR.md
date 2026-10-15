# SecureFlow — Phase 1 Work Summary Report

**Prepared by:** Antigravity AI (Google DeepMind)  
**Date:** 2026-10-15  
**Project:** SecureFlow — Security Findings & Remediation Management Platform with MCP  
**Repository:** `D:\GitProjects\secureflow-mcp-appsec-platform`  
**Report purpose:** Summary of all work completed in Phase 1 for advisor review

---

## 1. What Is This Project?

**SecureFlow** is a full-stack web application being built as a serious portfolio project. It is designed to demonstrate competence in four areas simultaneously:

1. **Software Engineering** — React/TypeScript frontend, Node.js/Express backend, PostgreSQL database
2. **Application Security** — OIDC authentication, RBAC + object-level authorization, audit logging, threat modeling
3. **Agentic AI / MCP** — A real Model Context Protocol (MCP) server that gives an AI assistant controlled, authorized access to the application's data
4. **DevSecOps** — Docker, GitHub Actions, SAST (CodeQL), SCA (Dependabot), OWASP ZAP penetration testing

The application tracks security vulnerabilities (called "findings") found in software projects. A team of Admins, Security Analysts, and Developers can record vulnerabilities, assign remediation work, verify fixes, and maintain an append-only audit trail (application-layer immutability; cryptographic tamper-evidence is out of scope for MVP). An AI client (like Claude Desktop) can connect via the MCP server to read authorized findings and propose remediation actions — but **never execute changes silently**.

---

## 2. What Phase 1 Was About

Phase 1 is **entirely a design and documentation phase**. No application code, no database, no packages, no containers, no commands were executed. The purpose was to think through the entire system architecture, security model, and implementation plan *before* writing a single line of code — a professional engineering practice.

The instructions explicitly said:
> *"Do not implement application code yet. Your job is to design and document the project foundation."*

---

## 3. Starting Point

When I began, the repository folder contained only **two files**:

| File | Purpose |
|---|---|
| `ANTIGRAVITY_FIRST_PROMPT.md` | Instructions for the AI on what to do in Phase 1 |
| `PROJECT_ROADMAP.md` | The master 8-phase development roadmap for the full project |

I read both files completely before doing anything. I then created a **planning artifact** (a review document) and waited for developer approval before writing any files. Only after approval did I create the Phase 1 documents.

---

## 4. What I Created (7 New Files)

All files were created inside the `docs/` folder. **The two original root files were never modified.**

### 4.1 — `docs/decisions/0001-modular-monolith.md`
**Architecture Decision Record (ADR)**

This is a formal architectural decision record — a standard software engineering practice for documenting *why* a major design choice was made. This ADR documents the decision to use a **modular monolith** architecture instead of microservices.

**Key contents:**
- Three options considered: distributed microservices, modular monolith, layered monolith (spaghetti)
- Full justification for why microservices were rejected for the MVP (too complex, authorization policy would have to be duplicated or centralized in yet another service, harder to test)
- Why a modular monolith was chosen: single deployment, enforced module boundaries, shared authorization layer
- Risks and mitigations
- How module boundaries will be enforced with TypeScript project references and ESLint boundary rules

---

### 4.2 — `docs/01-product-requirements.md`
**Product Requirements Document (19.3 KB)**

This is the formal specification of what the product must do. It covers:

**Product Vision and Scope:**
- What SecureFlow is, who it's for, what problems it solves
- MVP boundaries: what's included vs. explicitly excluded (no billing, no microservices, no real-time chat, no autonomous AI, etc.)

**Assumptions:**
- Single organization (not multi-tenant SaaS)
- External OIDC identity provider (Keycloak) — we do not build our own password system
- Developers see only findings assigned to them (not all project findings)

**Roles and Personas:**
- **Alex (Admin):** Creates projects, manages team access, reviews audit logs
- **Sam (Security Analyst):** Records vulnerabilities, triages severity, assigns remediation work, verifies fixes
- **Dev (Developer):** Sees only their assigned work, submits fixes for review
- **AI/MCP Client:** Reads authorized findings, proposes (never executes) changes

**User Stories (17 total):** Specific "As a [role], I want to [action] so that [benefit]" stories covering every major workflow for all four user types.

**Functional Requirements (28 numbered FR-001 to FR-028):** Precise, testable statements of what the system must do — finding creation, status transitions, pagination, authentication, audit logging, MCP tools, etc.

**Security Requirements (15 numbered SEC-001 to SEC-015):** Specific security controls mapped to OWASP ASVS v5.0.0 (Application Security Verification Standard) sections, covering authentication, authorization, input validation, SQL injection prevention, session management, CSRF, rate limiting, MCP token validation, audit log integrity, and secret management.

**Acceptance Criteria:** A table of testable conditions that must be met at each phase — including specific negative tests (e.g., "a Developer cannot read another project's finding") that must pass with automation.

---

### 4.3 — `docs/02-architecture.md`
**Architecture Document (17.0 KB)**

This is the technical architecture design. It uses the **C4 model** (a standard for software architecture diagrams) with Mermaid diagrams that render directly in GitHub and modern Markdown viewers.

**System Context Diagram (C4 Level 1):**
Shows how SecureFlow sits in its environment — connected to the OIDC provider (Keycloak), accessed by browser users and an AI MCP client, and scanned by GitHub Actions CI.

**Container Diagram (C4 Level 2):**
Shows the internal components:
- `apps/web` — React + Vite SPA (the browser UI)
- `apps/api` — Express REST API (the BFF — Backend For Frontend)
- `apps/mcp-server` — MCP server for AI clients
- `packages/domain` — **The shared authorization and business logic layer** (critical design decision)
- PostgreSQL database
- Keycloak OIDC provider

**Monorepo Boundary Table:**
A precise table of which package is allowed to import from which other package — for example, `apps/web` may NOT import from `packages/domain` (server-only code). This is enforced by tooling.

**Trust Boundary Diagram:**
Shows exactly what is trusted vs. untrusted, and where the security enforcement points are.

**Browser Session Flow (Sequence Diagram):**
Step-by-step diagram of the OIDC authorization-code + PKCE login flow. The key design: **the browser never holds an OIDC token** — it only gets an opaque session cookie (HttpOnly, Secure, SameSite=Lax). The token lives only on the server. This is called the BFF (Backend For Frontend) pattern and is a security best practice to prevent token theft.

**MCP Authentication Flow (Sequence Diagram):**
Step-by-step diagram of how an AI client authenticates to the MCP server using OAuth 2.0 Bearer tokens — **completely separate** from the browser session. This distinction is critical for security.

**Why Shared Domain Services Are Necessary:**
A written explanation of why all authorization logic must live in one place (`packages/domain`) and be reused by both the REST API and the MCP server — preventing policy drift that could create security gaps.

**API Endpoint Inventory:**
A draft table of all REST endpoints with their HTTP methods, paths, authentication requirements, and authorized roles.

**MCP Tool Inventory:**
The four MCP tools planned: `list_my_findings`, `get_finding_details`, `get_remediation_summary`, and `propose_remediation_task` (Phase 6+, write-only as pending approval).

**Open Architecture Decisions Table:**
A clear table of 8 decisions that must be resolved by the developer before Phase 2 implementation begins (ORM choice, OIDC provider, session model, etc.).

---

### 4.4 — `docs/03-data-model.md`
**Data Model Document (17.7 KB)**

This is the database design. It contains a full **Entity Relationship Diagram (ERD)** in Mermaid format showing all tables and their relationships.

**8 Database Tables Designed:**

| Table | Purpose |
|---|---|
| `users` | Stores all users; identity from OIDC (no passwords stored) |
| `projects` | Named security assessment scopes |
| `project_members` | Junction table: which user has which role in which project |
| `findings` | The core entity — recorded security vulnerabilities |
| `remediation_tasks` | Work items assigned to developers to fix findings |
| `finding_events` | Immutable append-only history of every finding change |
| `audit_events` | Organization-wide security audit trail |
| `mcp_action_requests` | Pending AI-proposed actions awaiting human approval (Phase 6+) |

**For each table:**
- Every field with its type, constraints (NOT NULL, UNIQUE, FK, CHECK), and purpose
- Recommended database indexes with justification
- Notes on security implications (e.g., UUIDs prevent IDOR enumeration)

**Finding Status State Machine (Diagram):**
A state machine diagram showing all valid states and transitions:
`OPEN → TRIAGED → IN_PROGRESS → READY_FOR_REVIEW → VERIFIED → CLOSED`
with `REOPENED` as an exceptional state when a fix is rejected.

**Transition Authorization Table:**
For every state transition, who is allowed to trigger it and under what conditions. For example: only a Developer who is the assigned developer can submit remediation; only an Analyst (not the submitting developer) can verify/close.

**Transactional Requirements:**
Which operations must be atomic (wrapped in a database transaction) and why — for example, a status change must update the finding AND write an audit event in a single transaction, or both must roll back.

**Data Retention and Privacy Notes:**
How soft deletion works, why audit events are never deleted, and how to handle future GDPR requirements.

---

### 4.5 — `docs/04-authorization-matrix.md`
**Authorization Matrix (13.2 KB)**

This is the most security-critical design document. It specifies exactly who can do what.

**7 Authorization Principles:**
Formal statements of the security model, including "deny by default," "role alone is insufficient," "existence hiding (return 404 not 403 for unauthorized resources)," and "REST/MCP parity."

**Role × Action Matrix (5 sections):**
Tables covering:
- Project operations (create, list, add/remove members, etc.)
- Finding operations (create, triage, assign, submit, verify, close, etc.)
- Remediation task operations
- Audit event access
- MCP tool access

For each operation: which roles are allowed, and what additional conditions apply (e.g., project membership, assignment).

**12 Object-Level Authorization Invariants (OLI-1 to OLI-12):**
Formal invariants that must hold for every request. These are the precise security rules. Example:
> *OLI-2: A Developer may only read finding details for findings where `findings.assigned_to_id = principal.userId`*

**15 Negative Authorization Test Scenarios (NEG-01 to NEG-15):**
These are specific test cases that must result in access denial. They are designed to be turned directly into automated tests. Examples:
- NEG-01: Developer guesses a UUID from another project → must get 404
- NEG-02: Developer calls verify on their own finding → must get 403
- NEG-09: MCP client calls a tool with another project's finding ID → must get denial
- NEG-10: MCP client with expired Bearer token → must get 401

**5 Privilege Escalation Scenarios (PE-01 to PE-05):**
Specific attack scenarios where someone tries to gain elevated access — like sending `{"role": "ADMIN"}` in a request body. Each has a specified expected outcome (server ignores it, derives role from session only).

**6 Cross-Project Access Scenarios:**
Edge cases around multi-project membership and scoping.

**Domain Policy Implementation Guidance:**
A recommended code structure for the `packages/domain/src/policy/` directory — where to put authorization logic and how it should be structured.

**Audit Requirements for Denied Access:**
Specification that all denied access attempts must be logged in the audit trail, enabling detection of privilege escalation attacks.

---

### 4.6 — `docs/05-threat-model.md`
**Threat Model Document (19.8 KB)**

This is a formal security threat model using the STRIDE framework (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege), which is an industry-standard approach to security analysis.

**9 Assets Identified:**
What we are protecting, from finding records (High sensitivity) to database credentials and session secrets (Critical sensitivity).

**6 Entry Points Documented:**
Every way an attacker could reach the system — browser HTTPS, MCP OAuth, CI pipeline, admin Docker access, etc.

**Data Flow and Trust Boundary Diagram:**
Visual representation of what crosses trust boundaries, enabling systematic threat identification.

**9 Attacker Assumptions:**
The threat model explicitly states who we assume attackers are — from unauthenticated external attackers to authenticated users in one project trying to access another, to attackers who control finding content.

**34 Specific Threats Analyzed (30 STRIDE threats across 6 categories + 4 supply chain/CI threats):**
For each threat:
- Threat ID and description
- Attack scenario (how it would be executed)
- Impact if successful
- Mitigation (technical control)
- Verification/Test evidence (how to prove the control works)

**Coverage includes all required topics:**
- BOLA/IDOR (Broken Object-Level Authorization / Insecure Direct Object Reference)
- Privilege escalation (role claim injection, token tampering)
- Session and CSRF attacks
- SQL injection
- Sensitive data in logs
- Secrets in version control
- CI/CD supply chain attacks
- MCP token misuse
- **Prompt injection** (AI receives a finding description containing "ignore all rules and do X" — the system must treat it as data, not instructions)
- **Confused deputy** (MCP server accidentally acts using its own elevated service account instead of the caller's identity)
- Unauthorized autonomous AI writes

**OWASP ASVS v5.0.0 Mapping Table:**
Links each threat category to the relevant OWASP Application Security Verification Standard section — the internationally recognized benchmark for application security.

**4 Supply Chain / CI Threats:**
Malicious npm packages, compromised GitHub Actions, secrets in CI, malicious pull request workflows.

**Threat Prioritization Matrix:**
Ranks all threats as Critical/High/Medium/Low and specifies which implementation phase mitigates each.

**Residual Risks Section:**
Honest acknowledgement of what the system does NOT fully protect against (e.g., Keycloak misconfiguration, no full token revocation in MVP) with explicit documentation of why these are accepted.

---

### 4.7 — `docs/06-backlog-and-acceptance.md`
**Backlog and Acceptance Criteria (19.3 KB)**

This is the implementation plan broken into all 8 phases with specific, testable acceptance criteria for each.

**Phase 1 (Current — Documentation):**
- Lists all 7 documents with their review status
- Lists all 10 open decisions that must be resolved before Phase 2

**Phase 2 (Week 2 — Monorepo & Tooling):**
- 13 backlog items: Git init, pnpm workspace setup, TypeScript configuration, ESLint, Docker Compose for PostgreSQL, Keycloak, CI/GitHub Actions, `.env.example`
- **5 specific starter tasks** written out for the developer to hand to the AI for Phase 2 — precise, small, reviewable tasks in order

**Phases 3–8:**
Each phase has numbered backlog items labeled Must/Should/Later, and a complete acceptance criteria checklist with specific conditions that must be provably true before advancing to the next phase.

**Phase Gate Summary Table:**
A single reference table showing what the developer must sign off on at each of the 8 phase gates, and that the AI must stop and wait at each gate.

**Cross-Cutting Mandatory Items:**
Items that apply to every single phase regardless of which phase is in progress — like "no hardcoded secrets," "authorization logic only in `packages/domain`," "all inputs validated with Zod," etc.

**Release Milestone Summary:**
4 version milestones (v0.1, v0.5, v0.8, v1.0.0) with scope and portfolio evidence for each.

---

## 5. What Was NOT Done (Explicitly)

The following were **not created, installed, executed, or modified** — as required by the Phase 1 scope:

- ❌ No application code (no React components, no Express routes, no TypeScript source files)
- ❌ No package.json, node_modules, or any npm/pnpm package installation
- ❌ No database schemas, migrations, or SQL files
- ❌ No Docker containers or Docker Compose files
- ❌ No GitHub Actions workflows
- ❌ No `.env` files or real credentials of any kind
- ❌ No Git initialization or commits
- ❌ No external API calls or network requests
- ❌ No modifications to `PROJECT_ROADMAP.md` or `ANTIGRAVITY_FIRST_PROMPT.md`
- ❌ No files created outside the `docs/` directory

---

## 6. Key Design Decisions Made (Approved D1–D10)

These are the 10 architecture decisions approved for implementation:

| # | Decision | Approved Selection | Why |
|---|---|---|---|
| D1 | ORM (database toolkit) | **Prisma 7** | Type-safe migrations, Node.js 24 LTS & TypeScript ≥5.7.0 compatibility, official PostgreSQL driver adapter (`@prisma/adapter-pg`), PostgreSQL 17 compatibility |
| D2 | OIDC identity provider | **Keycloak 26.x** (in Docker) | Free, open-source, standards-compliant OIDC + OAuth 2.1; supports PKCE and JWKS |
| D3 | Browser session model | **BFF/server-managed session** | No tokens in the browser — prevents token theft via XSS; HttpOnly/Secure cookies; session rotation on login |
| D4 | Developer visibility scope | **Assigned findings only** | Principle of least privilege; developers only see findings explicitly assigned to them |
| D5 | MCP transport & auth | **Streamable HTTP + OAuth 2.1** | Replaces deprecated HTTP+SSE; official TypeScript SDK v2 (`@modelcontextprotocol/express`) |
| D6 | Public demo | **Defer live public deployment** | Local Docker Compose + video recording; defer live deployment until after Phase 7 security verification |
| D7 | License | **MIT License** | Standard permissive license for public portfolio; license file created at release packaging |
| D8 | MCP demo client | **MCP Inspector + Claude Desktop** | MCP Inspector for development debugging; Claude Desktop for real-client integration demo |
| D9 | Extra finding statuses | **Defer `WONT_FIX` and `DUPLICATE`** | Keep MVP state machine focused on core operational lifecycle; document future dispositions in data model |
| D10 | Multi-org future | **Single-org MVP** | Focused single-organization schema for MVP; clean future multi-tenancy migration path formally documented in data model |

---

## 7. Architecture Summary for Advisor

The core architectural insight of this design is the **shared domain services pattern**:

```
Browser (React/Vite)
        │
        ▼ HTTPS + HttpOnly session cookie (no tokens in browser)
Express REST API  ─────────────────────────────────────────┐
        │                                                   │
        ▼                                                   ▼
 packages/domain  ◄──── This is the ONLY authorization     │
  (AuthZ layer)          enforcement point                  │
        │                                                   │
        ▼                                                   │
   PostgreSQL         MCP Server ─── Bearer Token ─────────┘
                      (AI Client)    (OAuth, separate from browser session)
```

Both the web API and the AI/MCP server go through the **same authorization code** — there is no way to bypass the security controls by using the AI interface instead of the web interface. This is a critical security property that must be demonstrated and tested.

---

## 8. Engineering Practices Demonstrated in Phase 1

Even though no code was written, the following professional engineering practices were applied:

1. **Architecture Decision Records (ADRs)** — Formal documentation of why major architectural choices were made
2. **C4 Model Diagrams** — Industry-standard way to document software architecture at multiple levels
3. **STRIDE Threat Modeling** — Systematic security analysis before implementation begins
4. **OWASP ASVS mapping** — Requirements traced to international security standards
5. **Numbered, testable requirements** — Every requirement has an ID and can be traced to a test
6. **Negative test scenarios** — 15 specific "what should be denied" test cases designed alongside the features
7. **Phase gates** — Formal stop points requiring human review before the next phase
8. **Scope control** — Explicit MVP boundaries and non-goals documented upfront
9. **Adversarial thinking** — 34 specific threat scenarios considered before writing any code (30 STRIDE + 4 supply chain)
10. **Separation of concerns** — Browser session vs. MCP auth designed as independent, non-overlapping trust boundaries

---

## 9. Next Steps (Phase 2 — awaiting developer approval)

Phase 2 will set up the actual code repository structure. The first 5 tasks are documented in [docs/06-backlog-and-acceptance.md](../docs/06-backlog-and-acceptance.md):

1. Create pnpm workspace and root package.json
2. Configure TypeScript strict mode across all packages
3. Scaffold the Express API with a health check and first test
4. Create Docker Compose with PostgreSQL + .env.example
5. Create GitHub Actions CI pipeline (lint, typecheck, test)

**Phase 2 will NOT begin until the developer has reviewed the Phase 1 documents and resolved the 10 open decisions listed above.**

---

*This report was generated by Antigravity AI on 2026-10-15. All design choices are recommendations pending developer approval. No application code, infrastructure, or deployments were created.*
