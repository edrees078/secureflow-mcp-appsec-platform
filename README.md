# SecureFlow — AppSec Finding & Remediation Management Platform

> An enterprise-grade Application Security (AppSec) findings and remediation lifecycle platform featuring strict architectural boundaries, granular role- and object-level authorization, and Model Context Protocol (MCP) integration for secure, audited AI agent interactions.

---

## 1. Project Overview

SecureFlow is designed to bridge the operational gap between security teams, software developers, and emerging agentic AI assistants. The platform provides a centralized, auditable system of record for tracking vulnerabilities, assigning remediation tasks, verifying security fixes, and enabling AI-assisted remediation workflows under strict authorization boundaries.

### Current Implementation Status (Phase 2 Foundation)

SecureFlow is currently in **Phase 2 (Monorepo Foundation, Tooling, and Local Services)**. The foundational architecture has been fully implemented, locally verified, and validated via GitHub Actions CI:

* **Monorepo Architecture:** Pnpm workspace orchestrating six discrete packages with strict TypeScript solution references (including TypeScript boundary scaffolds for `apps/web` and `apps/mcp-server`, with React/Vite UI and MCP runtime implementations deferred to Phases 5 and 6).
* **Architectural Boundary Enforcement:** ESLint 9 combined with `eslint-plugin-boundaries` and an automated test suite enforcing clean separation between frontend, backend APIs, domain services, database access layers, and shared utilities.
* **Express 5 API Foundation:** Hardened Express server baseline featuring Helmet security headers, CORS origin restriction, Pino structured logging with multi-level sensitive credential redaction, UUID v4 request tracing with header sanitization, standardized error envelope handling, and a readiness health-check probe (`/health/ready`).
* **Isolated PostgreSQL 17 Docker Environment:** Declarative `compose.yaml` running PostgreSQL 17.11 Alpine bound strictly to host loopback `127.0.0.1:5433`, eliminating port collisions with native host database services (such as PostgreSQL 15 on port 5432).
* **Prisma ORM 7 Configuration:** Modern Prisma 7 architecture utilizing `prisma.config.ts` for database connectivity and schema validation.
* **Supply-Chain-Hardened GitHub Actions CI:** Continuous integration pipeline running on Ubuntu 24.04 with pinned commit SHAs, unprivileged read-only permissions (`contents: read`), and frozen-lockfile execution.

### Planned Capabilities (Deferred to Later Phases)

To maintain strict engineering rigor, business workflows and external integrations are scheduled in sequential phases:

* **Finding & Remediation Lifecycle (Phase 3):** Full PostgreSQL data models, Prisma migrations, transactional status transitions (`OPEN` → `TRIAGED` → `IN_PROGRESS` → `READY_FOR_REVIEW` → `VERIFIED`/`CLOSED`), and REST CRUD endpoints.
* **OIDC Authentication & Object-Level Authorization (Phase 4):** Keycloak OIDC integration (Authorization Code + PKCE), BFF server-managed HttpOnly sessions, CSRF protection, API rate limiting, and project-membership-aware authorization policies preventing IDOR/BOLA.
* **React Web Application (Phase 5):** Interactive Vite + React SPA providing role-sensitive interfaces for Security Analysts, Developers, and Administrators.
* **Model Context Protocol (MCP) Server (Phase 6):** Streamable HTTP MCP server compliant with the MCP TypeScript SDK, RFC 9728 Protected Resource Metadata (PRM) discovery, OAuth 2.1 token validation, and pending-action approval workflows for AI tools.
* **DevSecOps & Penetration Testing (Phase 7):** Automated static/dynamic security scanning, CodeQL pipelines, and documented penetration test evidence.

---

## 2. Technology Stack

| Layer | Technology | Specification / Version |
|---|---|---|
| **Runtime Environment** | Node.js | `24.x` LTS (enforced in `.nvmrc` and `engines`) |
| **Package Management** | pnpm | `9.15.4` (frozen lockfile enforcement) |
| **Language & Compilation** | TypeScript | `6.0.3` (Strict mode, solution project references) |
| **Code Quality & Linting** | ESLint | `9.39.5` with `eslint-plugin-boundaries` `7.2.0` |
| **HTTP API Framework** | Express | `5.3.0` (with native async error handling) |
| **API Security Middleware** | Helmet, CORS | `helmet` `8.3.0`, `cors` `2.8.6` |
| **Structured Logging** | Pino | `pino` `10.4.0`, `pino-http` `11.0.0` (redaction enabled) |
| **Runtime Validation** | Zod | `4.6.7` (environment and payload schema validation) |
| **Test Automation** | Vitest | `5.0.5` with Supertest `7.3.1` (17 unit/integration tests) |
| **Database Engine** | PostgreSQL | `17.11` Alpine (containerized via Docker Compose) |
| **Database ORM** | Prisma ORM | `7.10.1` (`@prisma/client`, `@prisma/adapter-pg`) |
| **Continuous Integration** | GitHub Actions | Ubuntu 24.04 runner, SHA-pinned actions, read-only permissions |

---

## 3. Monorepo Topology & Architectural Boundaries

SecureFlow follows a modular monolith architecture. All packages reside in a single repository but maintain compile-time and lint-time physical boundaries:

```
secureflow-mcp-appsec-platform/
├── .github/
│   └── workflows/
│       └── ci.yml               # Hardened GitHub Actions CI pipeline
├── apps/
│   ├── api/                     # Express 5 REST API application
│   │   ├── src/
│   │   │   ├── config/          # Zod environment validation (env.ts)
│   │   │   ├── middleware/      # Error handler, request ID, security headers
│   │   │   ├── routes/          # API route definitions (/health/ready)
│   │   │   ├── logger/          # Pino logger with credential redaction
│   │   │   ├── app.ts           # Express application factory
│   │   │   └── server.ts        # HTTP server entrypoint & graceful shutdown
│   │   └── tests/               # Vitest suite (17 API integration tests)
│   ├── mcp-server/              # Model Context Protocol server scaffold (Phase 6 deferred)
│   └── web/                     # Web frontend TypeScript scaffold (Phase 5 React/Vite deferred)
├── packages/
│   ├── domain/                  # Business entities, domain services, and database
│   │   ├── prisma/              # Prisma 7 schema definition (schema.prisma)
│   │   ├── prisma.config.ts     # Modern Prisma 7 database configuration
│   │   └── src/
│   │       ├── db/              # Database connection probe & client adapter
│   │       └── services/        # Business service abstractions
│   ├── schemas/                 # Shared validation schemas & API contracts
│   └── shared/                  # Leaf utility functions, constants, and types
├── tests/
│   └── boundaries/              # Architectural boundary enforcement test suite
├── docs/                        # Specifications, architecture, threat model, guides
├── compose.yaml                 # Docker Compose specification for PostgreSQL 17
├── .env.example                 # Environment configuration template
├── package.json                 # Monorepo root scripts and devDependencies
├── pnpm-workspace.yaml          # Pnpm workspace definition
└── tsconfig.base.json           # Base TypeScript configuration (strict mode)
```

### Dependency Rules

To prevent coupling and architectural drift, dependency flows are strictly enforced by ESLint:

| Package | May Import From | Must NOT Import From | Rationale |
|---|---|---|---|
| `apps/web` | `packages/schemas`, `packages/shared` | `apps/api`, `apps/mcp-server`, `packages/domain` | Client bundle must never leak server-side code or DB logic. |
| `apps/api` | `packages/domain` (services only), `packages/schemas`, `packages/shared` | `packages/domain/src/db/*`, `apps/web`, `apps/mcp-server` | API handlers must interact through domain services, never bypassing directly to raw database queries. |
| `apps/mcp-server` | `packages/domain` (services only), `packages/schemas`, `packages/shared` | `packages/domain/src/db/*`, `apps/web`, `apps/api` | MCP tools reuse domain service logic under identical security invariants. |
| `packages/domain` | `packages/schemas`, `packages/shared` | `apps/*` | Core business logic remains decoupled from delivery mechanisms. |
| `packages/schemas` | `packages/shared` | `packages/domain`, `apps/*` | Contracts remain independent of business implementations. |
| `packages/shared` | *None* | `packages/*`, `apps/*` | Leaf utility package; zero workspace dependencies allowed. |

Boundary rules are tested automatically via `pnpm run test:boundaries`.

---

## 4. Prerequisites

Before setting up SecureFlow locally, ensure your workstation meets the following prerequisites:

1. **Node.js 24 LTS:** Version `>=24.0.0 <25.0.0` (validated with `v24.18.0`).
   ```bash
   node --version
   ```
2. **pnpm 9.15.4:** Pinned package manager.
   ```bash
   corepack enable
   corepack prepare pnpm@9.15.4 --activate
   pnpm --version
   ```
3. **Docker Desktop:** Running with Linux containers (WSL 2 on Windows or native Docker on Linux/macOS). Docker Engine `29.x`+ and Docker Compose `v2.x`+ / `v5.x`+.
   ```bash
   docker --version
   docker compose version
   ```

> [!NOTE]
> **Host Port Isolation:** The SecureFlow PostgreSQL container is configured to bind to host port **`5433`** (`127.0.0.1:5433`). If you have a native PostgreSQL installation (such as PostgreSQL 15 on port `5432`), it can run simultaneously without port conflict.

---

## 5. Local Setup & Configuration

### Step 1: Clone the Repository

```bash
git clone https://github.com/edrees078/secureflow-mcp-appsec-platform.git
cd secureflow-mcp-appsec-platform
```

### Step 2: Install Workspace Dependencies

Use the frozen lockfile to ensure reproducible package installation:

```bash
pnpm install --frozen-lockfile
```

### Step 3: Configure Environment Variables

Create your local `.env` file from `.env.example`:

**PowerShell (Windows):**
```powershell
Copy-Item .env.example .env
```

**Bash (Linux / macOS):**
```bash
cp .env.example .env
```

Review `.env` to verify the configuration:
```ini
POSTGRES_USER=secureflow
POSTGRES_PASSWORD=secureflow_dev_password_change_me
POSTGRES_DB=secureflow_dev
POSTGRES_PORT=5433

DATABASE_URL=postgresql://secureflow:secureflow_dev_password_change_me@127.0.0.1:5433/secureflow_dev?schema=public
NODE_ENV=development
```

> [!IMPORTANT]
> **Secrets Management:** The `.env` file is excluded from Git via `.gitignore`. Never commit `.env` files or hardcode credentials into the codebase.

---

## 6. Database Operations

Local database services are managed declaratively using Docker Compose.

### Start PostgreSQL 17

Start the isolated PostgreSQL container in the background:

```bash
pnpm run db:up
# Or: docker compose up -d
```

### Verify Container Health & Status

Check that the container is healthy:

```bash
pnpm run db:status
# Or: docker compose ps
```

Expected output indicates container `secureflow-postgres` is `Up (healthy)` on port `127.0.0.1:5433->5432/tcp`.

### Test Database Connectivity (Smoke Check)

Verify authenticated connectivity from the Node.js domain layer:

```bash
pnpm run db:smoke
```

Expected output:
```text
==================================================
SecureFlow — PostgreSQL Connectivity Smoke Check
==================================================
STATUS:             CONNECTED (SUCCESS)
Host Port:          5433
Database:           secureflow_dev
Authenticated User: secureflow
PostgreSQL Version: PostgreSQL 17.11 ...
Major Version:      17 (VERIFIED ISOLATED FROM PG 15)
==================================================
```

### View Database Logs

```bash
pnpm run db:logs
```

### Safe Database Shutdown

Stop the container while preserving database data:

```bash
pnpm run db:down
# Or: docker compose down
```

> [!WARNING]
> **Data Preservation:** NEVER execute `docker compose down -v` or `docker volume prune`. The `-v` flag removes the named volume `postgres_data`, permanently destroying all stored database tables and development data.

---

## 7. Express API Execution & Health Check

### Start the API Development Server

Start the Express API server with automatic hot-reloading:

```bash
pnpm run dev:api
```

By default, the server listens on port `3000` (or the port specified by the `PORT` environment variable).

### Health Check Endpoint

Query the readiness health probe:

**HTTP Request:**
```http
GET http://127.0.0.1:3000/health/ready
```

**PowerShell Probe:**
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:3000/health/ready" -Method Get | ConvertTo-Json
```

**cURL Probe:**
```bash
curl -s http://127.0.0.1:3000/health/ready | jq .
```

**Expected JSON Response (HTTP 200 OK):**
```json
{
  "status": "ready",
  "service": "secureflow-api",
  "uptime": 1.482,
  "timestamp": "2026-10-19T00:00:00.000Z",
  "checks": {
    "http": "ok"
  }
}
```

---

## 8. Development & Verification Commands

All standard development tasks are orchestrated through root `package.json` scripts:

| Command | Action | Description |
|---|---|---|
| `pnpm run build` | TypeScript Compile | Compiles all packages and applications via `tsc -b`. |
| `pnpm run typecheck` | Type Checking | Verifies static typing across all packages without emitting output. |
| `pnpm run lint` | ESLint Verification | Runs ESLint 9 across the monorepo, verifying code style and boundary rules. |
| `pnpm test` | Complete Test Suite | Executes all architectural boundary tests and API integration tests. |
| `pnpm run test:boundaries` | Boundary Tests | Runs the 12 positive and negative architectural boundary enforcement tests. |
| `pnpm run test:api` | API Integration Tests | Runs all 17 Express API tests using Vitest (security, logging, health, errors). |
| `pnpm run prisma:validate` | Schema Validation | Validates `schema.prisma` offline using Prisma 7 CLI. |
| `pnpm run db:validate` | Compose Validation | Validates Docker Compose configuration against `.env` requirements. |
| `pnpm run db:smoke` | DB Smoke Test | Verifies authenticated connection to PostgreSQL 17 on port 5433. |

---

## 9. Continuous Integration (CI)

SecureFlow uses GitHub Actions for continuous integration. The pipeline is defined in `.github/workflows/ci.yml`.

### Pipeline Characteristics

* **Trigger Events:** Triggers on `push` to `main` and all pull requests targeting `main`.
* **Runner Environment:** Ubuntu 24.04 (`ubuntu-24.04`).
* **Supply-Chain Security:** All third-party GitHub Actions are pinned to immutable full-length commit SHAs with release tags in comments (`actions/checkout`, `pnpm/action-setup`, `actions/setup-node`).
* **Least Privilege:** The workflow operates with read-only permissions (`permissions: contents: read`).
* **Credential Hygiene:** GitHub checkout explicitly sets `persist-credentials: false`. No repository secrets or credentials are required for CI execution.
* **Deterministic Builds:** Dependency installation enforces `--frozen-lockfile`.
* **Verification Stages:** Docker Compose configuration validation, TypeScript compilation (`tsc -b`), ESLint 9 verification, 12 architectural boundary tests, Prisma 7 schema validation, and 17 Vitest API tests.

---

## 10. Project Roadmap

SecureFlow is developed through an eight-phase plan defined in [PROJECT_ROADMAP.md](PROJECT_ROADMAP.md):

```mermaid
flowchart LR
    P1[Phase 1: Architecture & Security Design] --> P2[Phase 2: Foundation & Tooling]
    P2 --> P3[Phase 3: PostgreSQL Models & REST API]
    P3 --> P4[Phase 4: OIDC, Sessions & RBAC]
    P4 --> P5[Phase 5: React Frontend Application]
    P5 --> P6[Phase 6: MCP Server & AI Agent Tools]
    P6 --> P7[Phase 7: DevSecOps & Pen Testing]
    P7 --> P8[Phase 8: Hardening & Showcase]

    classDef complete fill:#1b4332,stroke:#40916c,stroke-width:2px,color:#d8f3dc;
    classDef inProgress fill:#1e3d59,stroke:#17b978,stroke-width:2px,color:#e8ffff;
    classDef pending fill:#2b2d42,stroke:#8d99ae,stroke-width:1px,color:#edf2f4;

    class P1 complete;
    class P2 inProgress;
    class P3,P4,P5,P6,P7,P8 pending;
```

1. **Phase 1 — Product Definition, Architecture, and Security Design** `[COMPLETED & SIGNED OFF]`
   System architecture, data model ERD, role/action matrix, STRIDE threat model, and architecture decision records (ADRs D1–D10).
2. **Phase 2 — Monorepo Foundation, Tooling, and Local Services** `[CURRENT — IN GATE ACCEPTANCE]`
   Pnpm workspace, strict TypeScript configuration, boundary enforcement, Express 5 API baseline, Docker PostgreSQL 17 environment, Prisma 7 setup, GitHub Actions CI, and documentation.
3. **Phase 3 — PostgreSQL Models, Domain Services, REST API** `[PLANNED]`
   Prisma entities, transactional status transitions, finding and remediation domain services, audit event generation, and REST CRUD endpoints.
4. **Phase 4 — OIDC Authentication, Secure Sessions, RBAC + Object Authorization** `[PLANNED]`
   Keycloak OIDC integration, BFF HttpOnly session cookies, CSRF protection, rate limiting, and project-membership-aware authorization policies.
5. **Phase 5 — React Frontend and Complete Human Workflow** `[PLANNED]`
   Vite + React frontend with role-sensitive user interfaces for Analysts, Developers, and Administrators, and Playwright end-to-end tests.
6. **Phase 6 — MCP Server and Agentic AI Integration** `[PLANNED]`
   Streamable HTTP MCP server, RFC 9728 discovery, OAuth 2.1 token validation, MCP tools (`list_my_findings`, `get_finding_details`), and prompt injection defenses.
7. **Phase 7 — DevSecOps, Penetration Tests, and Evidence** `[PLANNED]`
   Automated security scanning, CodeQL pipelines, and documented penetration testing evidence.
8. **Phase 8 — Hardening, Portfolio Readiness, and Showcase** `[PLANNED]`
   End-to-end audit, deployment documentation, video demonstration, and release packaging.

---

## 11. Security Architecture & Invariants

SecureFlow enforces the following non-negotiable security principles across all phases:

* **Deny by Default:** All routes, resources, and state transitions default to denied unless an explicit authorization policy evaluates to true.
* **Server-Authoritative Authorization:** Frontend UI visibility rules and client-supplied attributes are untrusted. Every state-changing request must be authorized on the server using verified session context.
* **Object-Level & Tenant Isolation:** Project membership and assigned finding ownership are validated on every operation to eliminate BOLA / IDOR vulnerabilities.
* **Zero Real Secrets in Source Control:** Passwords, API tokens, session secrets, and private keys must never be committed. Active `.env` files are ignored by Git.
* **Log Sanitization:** Sensitive credentials, authorization bearer tokens, cookie headers, and passwords are automatically redacted from application logs by Pino.
* **Bounded AI Interaction:** AI models interacting through MCP are treated as untrusted callers. AI inputs are strictly validated, tool executions are logged with attribution, and high-impact write operations require human-in-the-loop confirmation.

---

## 12. Documentation Index

Detailed architectural and design documentation is maintained in the `docs/` directory:

* [Product Requirements](docs/01-product-requirements.md) — Functional and nonfunctional requirements.
* [Architecture Specification](docs/02-architecture.md) — Modular monolith topology, ADRs, and component design.
* [Data Model Specification](docs/03-data-model.md) — Relational schema, indexes, constraints, and audit trails.
* [Authorization Matrix](docs/04-authorization-matrix.md) — Role permissions, negative test cases, and IDOR defenses.
* [Threat Model](docs/05-threat-model.md) — STRIDE threat analysis and OWASP ASVS v5.0.0 mappings.
* [Backlog and Acceptance Criteria](docs/06-backlog-and-acceptance.md) — Detailed phase deliverables and gate acceptance criteria.
* [Local Database Setup Guide](docs/guides/local-database-setup.md) — Detailed operational guide for Docker PostgreSQL 17 on Windows.
