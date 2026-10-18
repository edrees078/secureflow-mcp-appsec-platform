# SecureFlow — Local Database Environment Setup & Windows Troubleshooting Guide

**Applicable Phase:** Phase 2 — Task 4 (Database and Docker Environment Foundation)<br>
**Database Engine:** PostgreSQL 17 (Official Alpine Docker Image: `postgres:17-alpine`)<br>
**ORM Tooling:** Prisma ORM 7 (`prisma.config.ts` + `packages/domain/prisma/schema.prisma`)<br>
**Network Isolation:** Bound exclusively to `127.0.0.1` (loopback interface only)<br>
**Persistence Volume:** Named Docker volume `postgres_data`

---

## 1. Architecture Overview

SecureFlow uses an isolated PostgreSQL database for local development and automated testing:

```
[apps/api] / [apps/mcp-server]
         │ (Service Layer Calls Only)
         ▼
[@secureflow/domain]
  ├── src/db/smoke-check.ts  ──────▶ Authenticated Query Probe (pg)
  ├── prisma.config.ts       ──────▶ Prisma ORM 7 Config (reads DATABASE_URL)
  └── prisma/schema.prisma   ──────▶ Prisma 7 Schema (provider = "prisma-client")
                                                │
                                                ▼ (127.0.0.1:5433)
                                   ┌───────────────────────────────┐
                                   │ Docker: secureflow-postgres   │
                                   │ Engine: PostgreSQL 17 Alpine  │
                                   │ Volume: postgres_data         │
                                   └───────────────────────────────┘
```

### Safety & Scope Boundaries
- **Preserve Native PostgreSQL 15:** Port `5433` is standard for SecureFlow Docker PostgreSQL 17 to prevent interference with native PostgreSQL 15 running on Windows host port `5432`.
- **No Entity Models / Migrations in Task 4:** Business entity models (`Finding`, `Scan`, `User`, etc.), migrations, and runtime Prisma Client initialization are deferred to Phase 3.
- **Strict Network Isolation:** PostgreSQL is mapped exclusively to `127.0.0.1:${POSTGRES_PORT:-5433}:5432` to prevent unintentional exposure to external or local network interfaces.
- **Fail-Fast Configuration:** Docker Compose uses `${POSTGRES_PASSWORD:?error}` syntax so containers will refuse to start with empty or missing credentials.

---

## 2. Windows Prerequisites & Installation

### Step 2.1: Verify Docker Desktop on Windows
Open Windows PowerShell (Run as Administrator or regular user) and check if Docker is installed:
```powershell
docker --version
docker compose version
```

If Docker is not recognized:
1. Download **Docker Desktop for Windows** from [docker.com](https://www.docker.com/products/docker-desktop/).
2. Run the installer and ensure **Use WSL 2 instead of Hyper-V (recommended)** is checked.
3. Restart Windows if prompted by the installer.
4. Launch Docker Desktop and verify the status icon in the system tray shows "Engine Running".
5. In Docker Desktop Settings (`⚙` > General), ensure **Use the WSL 2 based engine** is checked.
6. Under Settings > Resources > WSL Integration, enable integration with your default WSL distro.

---

## 3. First-Time Database Initialization

### Step 3.1: Create Local `.env` Configuration
The Git repository tracks `.env.example` as a template and ignores `.env`. Create your active configuration file:

```powershell
# In PowerShell at the repository root:
Copy-Item .env.example .env
```

Review the values inside `.env`:
```env
POSTGRES_USER=secureflow
POSTGRES_PASSWORD=secureflow_dev_password_change_me
POSTGRES_DB=secureflow_dev
POSTGRES_PORT=5433

DATABASE_URL=postgresql://secureflow:secureflow_dev_password_change_me@127.0.0.1:5433/secureflow_dev?schema=public
NODE_ENV=development
```

> [!IMPORTANT]
> Change `secureflow_dev_password_change_me` to a secure development password before initial container startup.

### Step 3.2: Start the PostgreSQL Container
Use the root pnpm lifecycle script to start the container in detached mode:
```powershell
pnpm run db:up
# Or directly: docker compose up -d postgres
```

### Step 3.3: Verify Container Health
Check the container status and readiness health check:
```powershell
pnpm run db:status
# Or directly: docker compose ps
```
The output should report:
- State: `Up`
- Health: `healthy` (evaluated by `pg_isready -U secureflow -d secureflow_dev -h 127.0.0.1`)
- Ports: `127.0.0.1:5433->5432/tcp`

### Step 3.4: Verify End-to-End Authenticated Database Connectivity
Run the SecureFlow database smoke check:
```powershell
pnpm run db:smoke
```
This executes a real SQL query (`SELECT 1 AS connected, current_database(), current_user, version(), NOW();`) through `node-postgres` and outputs:
```
==================================================
SecureFlow — PostgreSQL Connectivity Smoke Check
==================================================
STATUS:             CONNECTED (SUCCESS)
Host Port:          5433
Database:           secureflow_dev
Authenticated User: secureflow
PostgreSQL Version: PostgreSQL 17.x on x86_64-pc-linux-musl...
Major Version:      17 (VERIFIED ISOLATED FROM PG 15)
Server Time:        ...
==================================================
```

---

## 4. Troubleshooting Common Windows Issues

### Issue 1: Port Conflict (Port 5432 Already in Use)
**Symptom:** Docker Compose reports `bind: address already in use` or connection connects to an unintended local database (e.g., existing Windows PostgreSQL service).

**Root Cause:** Windows often has a local PostgreSQL installation running as a background Windows service (e.g., `postgresql-x64-15`).

**Diagnosis:**
```powershell
# Check what is listening on port 5432:
Get-NetTCPConnection -LocalPort 5432 -ErrorAction SilentlyContinue | Select-Object LocalAddress, LocalPort, OwningProcess, State
```

**Resolution (Recommended — Zero Disruption):**
1. Change the host port mapping in `.env`:
   ```env
   POSTGRES_PORT=5433
   DATABASE_URL=postgresql://secureflow:secureflow_dev_password_change_me@127.0.0.1:5433/secureflow_dev?schema=public
   ```
2. Restart the container:
   ```powershell
   pnpm run db:down
   pnpm run db:up
   ```
3. Verify connectivity on the new port:
   ```powershell
   pnpm run db:smoke
   ```

---

### Issue 2: Password Changed in `.env` After Initial Volume Creation
**Symptom:** `pnpm run db:smoke` reports `password authentication failed for user "secureflow"` (Error Code: `28P01`).

**Root Cause:** Official PostgreSQL Docker images only use `POSTGRES_PASSWORD` and `POSTGRES_USER` during **first-time database cluster initialization** when the data volume (`/var/lib/postgresql/data`) is completely empty. Changing `.env` afterward does not alter the already-initialized database role password inside the persistent volume.

**Resolution:**
Update the user's password inside the running container using `psql`:
```powershell
# Execute ALTER USER inside the container:
docker compose exec postgres psql -U secureflow -d secureflow_dev -c "ALTER USER secureflow WITH PASSWORD 'your_new_password';"
```
Ensure `.env` matches `your_new_password`.

---

### Issue 3: Docker Daemon Is Not Running
**Symptom:** `error during connect: This error may indicate that the docker daemon is not running.`

**Resolution:**
1. Start the Docker Desktop application from the Windows Start menu.
2. Wait for the taskbar icon to show that the Docker engine is running.
3. If running inside WSL 2 directly, ensure the WSL distro is running (`wsl --status`).

---

## 5. Container Lifecycle & Prohibited Destructive Commands

### Safe Container Operations
| Operation | Command | Effect |
|---|---|---|
| **Start Database** | `pnpm run db:up` | Starts PostgreSQL container in background |
| **Stop Database** | `pnpm run db:down` | Gracefully stops container; **preserves all volume data** |
| **Pause Database** | `docker compose stop` | Pauses execution without stopping Docker network |
| **Resume Database** | `docker compose start` | Resumes paused container |
| **View Logs** | `pnpm run db:logs` | Streams live PostgreSQL engine logs |
| **Check Health** | `pnpm run db:status` | Shows status, port bindings, and health state |
| **Connectivity Smoke Test** | `pnpm run db:smoke` | Executes real authenticated query probe |

### ⚠️ STRICT PROHIBITION: Destructive Volume Reset
> [!CAUTION]
> **NEVER EXECUTE `docker compose down -v` WITHOUT EXPLICIT USER APPROVAL.**
> The `-v` flag permanently deletes the named volume `postgres_data`, resulting in **unrecoverable data loss** of all local databases, schemas, audit records, and test fixtures.

If a complete clean re-initialization is genuinely required and approved:
1. Export any critical development data: `docker compose exec postgres pg_dump -U secureflow secureflow_dev > backup.sql`
2. Stop and remove volumes with approval: `docker compose down -v`
3. Restart: `docker compose up -d`

---

## 6. Prisma ORM 7 Monorepo Configuration

SecureFlow follows the official modern **Prisma ORM 7** configuration standard:

### Configuration Separation
1. **`packages/domain/prisma.config.ts`**:
   - Manages connection URL resolution via `env("DATABASE_URL")`.
   - Uses `dotenv` with relative monorepo path resolution (`../../.env` and `.env`) so configuration is seamlessly discovered whether commands are run from the monorepo root or package subdirectories.
2. **`packages/domain/prisma/schema.prisma`**:
   - Declares `datasource db { provider = "postgresql" }` **without inline URL** (Prisma 7 standard).
   - Declares `generator client { provider = "prisma-client"; output = "../src/generated/prisma" }`.

### Validating Prisma Schema
Validate the Prisma configuration and schema without executing migrations:
```powershell
pnpm run prisma:validate
```

Output:
```
Loaded Prisma config from prisma.config.ts.
Prisma schema loaded from prisma\schema.prisma.
The schema at prisma\schema.prisma is valid 🚀
```

---

## 7. Phase 3 Integration Roadmap
When business data models and migrations are implemented in Phase 3:
1. Define entities in `packages/domain/prisma/schema.prisma` (`Finding`, `Project`, `Scan`, `User`, `AuditLog`).
2. Install `@prisma/adapter-pg` and generate Prisma Client to `packages/domain/src/generated/prisma`.
3. Initialize the Prisma Client adapter using the authenticated `pg.Pool` connection.
4. Execute Prisma migrations (`prisma migrate dev`).
