# Phase 5A React Authentication & Browser Verification Guide

**Status:** Implemented (Phase 5A)**Scope:** Same-origin React SPA (`apps/web`), Vite dev proxy (`127.0.0.1:5173` -> `127.0.0.1:3000`), Express BFF (`apps/api`), Keycloak 26.8.2 (`infra/keycloak/secureflow-realm.json`), and PostgreSQL 17.11 (`secureflow_test`).

---

## 1. Local Development URLs & Loopback Alignment

- Frontend Vite dev server runs at `http://127.0.0.1:5173` (`host: '127.0.0.1'`, `port: 5173`, `strictPort: true`).
- Vite proxies `/api` and `/health` same-origin to `http://127.0.0.1:3000` with `changeOrigin: false`.
- Use `http://127.0.0.1:5173` consistently in the browser (rather than mixing `localhost` and `127.0.0.1`) so host-only `sf_oidc_txn` and `sf_session` cookies remain readable across local BFF ports.
- Production mode (`NODE_ENV=production`) continues enforcing HTTPS-only allowlists, relative callback redirects, and `__Host-` prefixed cookies (`Secure`, `HttpOnly`, `SameSite=Lax`, no `Domain`).

---

## 2. Running Offline Frontend Checks

Run unit, component, Vite config, and production bundle verification without PostgreSQL, Keycloak, or Chromium:

```bash
pnpm run test:web
pnpm --filter @secureflow/web run build
```

---

## 3. Running the Reproducible Real-Browser E2E Smoke Test

### Prerequisites

1. PostgreSQL 17.11 and Keycloak 26.8.2 running cleanly via Docker Compose:
   ```bash
   pnpm run db:validate
   pnpm run db:up
   ```
2. Local `.env` (excluded from Git) providing:
   - `TEST_DATABASE_URL` pointing strictly to `secureflow_test` (on port `5433`)
   - `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_ALLOW_INSECURE_HTTP=true`
   - `KEYCLOAK_DEV_DEVELOPER_PASSWORD` (used to log in as `dev@secureflow.example`)
3. Google Chrome or Chromium installed locally (override detection with `CHROME_BIN=/path/to/chrome` if needed).

### Optional Overrides

| Variable | Default | Purpose |
| --- | --- | --- |
| `SECUREFLOW_WEB_URL` | `http://127.0.0.1:5173` | Vite dev origin used by Chromium |
| `SECUREFLOW_API_URL` | `http://127.0.0.1:3000` | Express BFF bind origin and callback host |
| `KEYCLOAK_DEV_USERNAME` | `dev@secureflow.example` | Synthetic Keycloak test account |
| `CHROME_BIN` | Auto-detected | Path to Chrome/Chromium executable |

### Execute

```bash
pnpm run test:web:browser
```

The smoke runner (`tests/e2e/phase5a-browser-auth-smoke.mts`) verifies:
1. Anonymous `/workspace` redirects to `/login` with zero web storage or cookies.
2. Top-level SSO login navigation via Vite proxy sets `HttpOnly` `sf_oidc_txn`.
3. Real Keycloak login returns via BFF callback to `/workspace` with `HttpOnly` `SameSite=Lax` `sf_session` and in-memory CSRF token.
4. Protected read probe (`GET /api/v1/projects?limit=1`) succeeds (`200`).
5. Disposable authorized fixture mutation (`PATCH /api/v1/tasks/:id/notes`) is rejected without `X-CSRF-Token` (`403`) and succeeds with `X-CSRF-Token` (`200`).
6. Browser reload restores the session via `/api/v1/auth/me` and rehydrates the in-memory CSRF token.
7. Logout attaches `X-CSRF-Token`, revokes the BFF session, completes Keycloak SSO logout, clears `sf_session` and `KEYCLOAK_IDENTITY`, and returns cleanly to `/login`.
8. All disposable fixtures, JIT rows, sessions, transactions, and audit events created during the smoke run are rolled back/cleaned and exact pre-run PostgreSQL table counts are verified.
