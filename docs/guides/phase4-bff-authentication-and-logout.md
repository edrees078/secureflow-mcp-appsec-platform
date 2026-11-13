# Phase 4 BFF Authentication & Logout Contract

**Status:** Implemented (Gate 4B.1 – Gate 4B.3, verified in Gate 4B.4)  
**Scope:** Browser authentication via Integrated Express BFF (`apps/api`) and Keycloak 26.8.2 (`infra/keycloak/secureflow-realm.json`)

> **Note on Phase 1 Design Documents:** Early Phase 1–2 planning files (`README.md`, `docs/02-architecture.md`, `docs/03-data-model.md`, `docs/05-threat-model.md`, `docs/06-backlog-and-acceptance.md`) still contain preliminary notes (e.g., `express-session`, unprefixed `/auth/*` routes, and pre-implementation `[PLANNED]` badges). This guide documents the **actual implemented Gate 4B behavior**.

---

## 1. BFF Session Model

- **Server-Managed Sessions:** Browser clients never receive or store OIDC access tokens, refresh tokens, or ID tokens. Authenticated state lives solely in PostgreSQL (`user_sessions`, hashed with SHA-256) and is bound to an opaque random token in an `HttpOnly`, `SameSite=Lax`, `Path=/` cookie.
- **Production vs. Development Cookie Separation:**
  - **Production (`NODE_ENV=production`):** Uses `__Host-sf_session` and `__Host-sf_oidc_txn` (`Secure=true`, `HttpOnly=true`, `SameSite=Lax`, no `Domain` attribute). Downgrade fallback to unprefixed development cookie names is disabled.
  - **Development:** Uses `sf_session` and `sf_oidc_txn`.
- **CSRF Defense-in-Depth:** Every state-changing `/api/v1/*` request and `POST /api/v1/auth/logout` enforces `Origin`/`Referer` allowlisting, `Sec-Fetch-Site` (`same-origin` / `same-site`) validation, duplicate-header rejection, and constant-time validation of `X-CSRF-Token` against the session's bound CSRF secret (`csrf_token` exposed cleanly via callback JSON or `GET /api/v1/auth/me`).
- **Database-Authoritative Principal Resolution:** `resolveSessionActor` loads fresh `globalRole`, `isActive`, and `projectMemberships` from PostgreSQL on every request. Global role changes and user deactivation immediately revoke active sessions; project membership removals take effect on the very next request without waiting for OIDC token expiry.

---

## 2. Logout Contract (`POST /api/v1/auth/logout`)

1. **Immediate Local BFF Revocation:**
   - Caller must present both a valid session cookie and a valid anti-CSRF token + trusted `Origin`.
   - `POST /api/v1/auth/logout` validates optional `{ postLogoutRedirectUri }` against `OIDC_ALLOWED_POST_LOGOUT_REDIRECT_URIS`, marks the PostgreSQL `user_sessions` row revoked (`revoked_at = now`, `revoke_reason = 'USER_LOGOUT'`), clears both the session cookie and OIDC transaction cookie (`Max-Age=0`), and emits an atomic `auth.logout` audit event.
   - Replaying the cleared/revoked session cookie immediately returns `HTTP 401 UNAUTHORIZED`, regardless of whether the browser proceeds to Keycloak.

2. **Keycloak RP-Initiated SSO Logout (`endSessionUrl`):**
   - The response returns HTTP `200`:
     ```json
     {
       "data": {
         "loggedOut": true,
         "endSessionUrl": "https://idp.example/realms/secureflow/protocol/openid-connect/logout?client_id=secureflow-bff&post_logout_redirect_uri=..."
       }
     }
     ```
   - **Frontend (`apps/web`, Phase 5) Requirement:** After `POST /api/v1/auth/logout` succeeds, if `data.endSessionUrl` is non-null, the frontend MUST navigate top-level (`window.location.assign(endSessionUrl)`) so Keycloak terminates the upstream SSO session.
   - **Intentional Omission of `id_token_hint` & Confirmation Screen:** SecureFlow does not persist raw OIDC ID tokens in `user_sessions` or echo them in URLs. Because `id_token_hint` is omitted, Keycloak 26.8.2 displays its native logout confirmation prompt before clearing `KEYCLOAK_IDENTITY` / `KEYCLOAK_SESSION` and redirecting to `post_logout_redirect_uri`.

3. **Failure, Cancellation, and IdP-Unavailability Guarantees:**
   - **IdP Unavailable During `POST /api/v1/auth/logout`:** If OIDC discovery or `end_session_endpoint` resolution fails transiently, local BFF session revocation and cookie clearing still succeed (`HTTP 200` with `endSessionUrl: null`).
   - **User Cancels / Aborts Keycloak Confirmation:** If the browser never visits `endSessionUrl`, dismisses Keycloak's confirmation page, or encounters an IdP error during `end_session`, the local BFF session remains permanently revoked (`401`). Only completing a fresh OIDC login flow (`GET /api/v1/auth/login` -> Keycloak -> `GET /api/v1/auth/callback`) can issue a new session.

---

## 3. OIDC Back-Channel Logout 1.0 Status

- Domain and schema primitives (`UserSession.oidcSid`, `SessionRepository.revokeActiveByOidcSid()`, and `AuthService.revokeSessionsByOidcSid()`) exist from Gate 4B.1.
- **Not yet exposed over HTTP in Gate 4B:** No `/api/v1/auth/backchannel-logout` endpoint, `logout_token` JWT verifier (`typ: logout+jwt`, `events`, `nonce` prohibition, `sid`/`sub` validation), or `jti` replay cache is implemented yet. Keycloak back-channel logout URLs remain unconfigured until explicitly authorized.

