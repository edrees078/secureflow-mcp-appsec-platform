# ADR 0001 — Modular Monolith Architecture

| Field | Value |
|---|---|
| **ID** | 0001 |
| **Title** | Adopt a modular monolith over microservices for the SecureFlow MVP |
| **Status** | Accepted (Phase 1 Gate Approved) |
| **Date** | 2026-10-15 |
| **Deciders** | Developer (you) + Antigravity |
| **Related docs** | [Architecture](../02-architecture.md) · [Backlog](../06-backlog-and-acceptance.md) |

---

## Context

SecureFlow is a portfolio project that must demonstrate real engineering competence across software engineering, application security, agentic AI, and DevSecOps. We need to:

- Ship a **working, reviewable MVP** in ≈12–16 weeks at ≈10–15 hours/week.
- Demonstrate **genuine architectural discipline**, not just technology assembly.
- Enforce **consistent authorization** across REST and MCP without duplicating policy logic.
- Keep operational complexity low enough for a single developer to operate, test, and explain.

The three primary structural options are:

1. **Distributed microservices** — separate deployable services communicating over HTTP/gRPC.
2. **Modular monolith** — a single deployable process with strongly bounded internal modules that never reach across module boundaries except through explicit service interfaces.
3. **Layered monolith (spaghetti)** — single process with no enforced module boundaries.

---

## Decision

**We adopt a modular monolith** for SecureFlow's `apps/api` and `apps/mcp-server`, sharing a `packages/domain` library that contains all authorization enforcement and business-logic services.

```
apps/
  api/          ← Express HTTP entrypoint; thin controllers
  mcp-server/   ← MCP entrypoint; thin tool handlers
packages/
  domain/       ← Authorization, business rules, service interfaces  ← SHARED
  schemas/      ← Zod schemas for runtime validation; shared with web
  shared/       ← Common types, utilities, errors
```

Both `api` and `mcp-server` import from `packages/domain` and are prohibited from writing business logic or authorization checks in their entrypoint layers. Each package is a separate TypeScript compilation unit in the pnpm workspace.

---

## Options Considered

### Option A — Microservices

**Pros:**
- Independent deployment and scaling per service.
- Technology diversity possible.
- Mirrors patterns used at large organizations.

**Cons:**
- Requires a service mesh, inter-service authentication, distributed tracing, and a much heavier local Docker Compose stack.
- Authorization policy must be either centralized (another service) or duplicated — both are significant complexity for a solo MVP.
- Network latency for every cross-service call; harder to write integration tests.
- Dramatically increases time-to-first-working-feature for a portfolio project.
- A portfolio evaluator will expect evidence of working software, not just topology diagrams.

**Verdict:** Rejected for MVP. Domain boundaries should be proven by clean module boundaries first; extract services later if warranted.

### Option B — Modular Monolith (chosen)

**Pros:**
- A single deployment unit for local Docker Compose development.
- Module boundaries enforced by TypeScript import rules and separate workspace packages — refusal of cross-cutting imports is statically checkable.
- Authorization logic lives **once** in `packages/domain`; REST and MCP reuse the exact same services.
- Integration tests can call domain services directly without HTTP round-trips.
- If load or isolation requires it, individual modules can be extracted into services after the data model and interfaces are proven.

**Cons:**
- A single process failure brings down all HTTP and MCP surfaces (acceptable at MVP scale).
- Shared database schema between API and MCP server (mitigated by the domain layer as the only data-access path).
- Requires discipline to maintain module boundaries; must be enforced via lint rules (`eslint-plugin-boundaries` or equivalent) in Phase 2.

**Verdict:** Chosen. Provides demonstrable architecture discipline while remaining operable by a single developer.

### Option C — Layered Monolith

**Pros:** Fast initial scaffolding.

**Cons:** Authorization logic scatters across controllers; impossible to reuse for MCP without duplication; fails the portfolio objective of demonstrating software engineering discipline.

**Verdict:** Rejected.

---

## Consequences

### Positive
- A recruiter or engineer reading the repository can trace every authorization decision to a single `packages/domain` call.
- Phase 3–4 tests can verify authorization at the service layer, independent of HTTP transport.
- MCP server tools call the same service methods as REST endpoints — demonstrated in code, not just claimed.
- Future extraction to microservices is low-risk if boundaries are clean from the start.

### Negative / Risks
- Requires upfront investment in workspace configuration (pnpm, TypeScript project references, lint boundaries) in Phase 2.
- Developer must consciously resist the temptation to write authorization logic in Express middleware rather than in domain services.

### Mitigations
- Phase 2 includes a lint rule (or TypeScript path alias restriction) that forbids `apps/api` from importing database clients directly, enforcing the domain layer indirection.
- Code review checklist item: "Does this authorization check live in `packages/domain`?"
- Phase 7 manual AppSec check explicitly verifies that MCP and REST paths exercise the same policy function.

---

## Follow-On Decisions (Resolved for Phase 2)

| Decision | Selection | Notes |
|---|---|---|
| Prisma vs Drizzle (D1) | **Prisma 7** | Official Prisma 7 with PostgreSQL driver adapter (`@prisma/adapter-pg`); data access lives strictly inside `packages/domain` |
| Module boundary enforcement tooling | `eslint-plugin-boundaries` | Prohibits `apps/*` from importing `packages/domain/src/db/*` |
| Shared database or separate schemas per app | Single schema | Domain layer is the authoritative enforcement boundary |

