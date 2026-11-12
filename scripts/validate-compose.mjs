import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const composePath = path.resolve(__dirname, '../compose.yaml');

console.log('=== SecureFlow Docker Compose Configuration Validation ===');

if (!fs.existsSync(composePath)) {
  console.error(`❌ FAIL: compose.yaml not found at ${composePath}`);
  process.exit(1);
}

const content = fs.readFileSync(composePath, 'utf-8');

const checks = [
  {
    name: 'Service name: postgres defined',
    pass: /postgres:\s*\n/.test(content),
    details: 'Defines postgres service container',
  },
  {
    name: 'PostgreSQL Image: postgres:17-alpine',
    pass: /image:\s*postgres:17-alpine/.test(content),
    details: 'Pins official lightweight PostgreSQL 17 Alpine image',
  },
  {
    name: 'Container Name: secureflow-postgres',
    pass: /container_name:\s*secureflow-postgres/.test(content),
    details: 'Explicit container naming for deterministic management',
  },
  {
    name: 'Network Isolation: 127.0.0.1:5433 loopback binding',
    pass: /-\s*["']127\.0\.0\.1:\$\{POSTGRES_PORT:-5433\}:5432["']/.test(content),
    details: 'Guarantees database binds to loopback on isolated port 5433 to protect native PostgreSQL 15',
  },
  {
    name: 'Env Validation: Required POSTGRES_USER with error directive',
    pass: /POSTGRES_USER:\s*\$\{POSTGRES_USER:\?[^}]+\}/.test(content),
    details: 'Fails container startup if POSTGRES_USER is unset or empty',
  },
  {
    name: 'Env Validation: Required POSTGRES_PASSWORD with error directive',
    pass: /POSTGRES_PASSWORD:\s*\$\{POSTGRES_PASSWORD:\?[^}]+\}/.test(content),
    details: 'Fails container startup if POSTGRES_PASSWORD is unset or empty',
  },
  {
    name: 'Env Validation: Required POSTGRES_DB with error directive',
    pass: /POSTGRES_DB:\s*\$\{POSTGRES_DB:\?[^}]+\}/.test(content),
    details: 'Fails container startup if POSTGRES_DB is unset or empty',
  },
  {
    name: 'Volume Persistence: Named volume postgres_data',
    pass: /volumes:\s*\n(?:\s*#[^\n]*\n)*\s*-\s*postgres_data:\/var\/lib\/postgresql\/data/.test(content) &&
          /volumes:\s*\n[\s\S]*postgres_data:\s*\n\s*driver:\s*local/.test(content),
    details: 'Data persists across container stop/recreate cycles',
  },
  {
    name: 'Health Check: Authenticated pg_isready probe configured',
    pass: /test:\s*\["CMD-SHELL",\s*"pg_isready\s+-U\s+\$\$\{POSTGRES_USER\}\s+-d\s+\$\$\{POSTGRES_DB\}\s+-h\s+127\.0\.0\.1"\]/.test(content),
    details: 'Docker healthcheck confirms readiness before dependent services connect',
  },
  {
    name: 'Safety Warning: Explicit prohibition of down -v',
    pass: /docker compose down -v/.test(content),
    details: 'Contains explicit documentation prohibiting destructive volume deletion',
  },
  {
    name: 'Service name: keycloak defined',
    pass: /keycloak:\s*\n/.test(content),
    details: 'Defines Keycloak IAM service container',
  },
  {
    name: 'Keycloak Image: quay.io/keycloak/keycloak:26.8.2',
    pass: /image:\s*quay\.io\/keycloak\/keycloak:26\.8\.2/.test(content),
    details: 'Pins patched official Keycloak 26.8.2 container image',
  },
  {
    name: 'Keycloak Admin: Required bootstrap env vars without fallback or deprecated aliases',
    pass:
      /KC_BOOTSTRAP_ADMIN_USERNAME:\s*\$\{KEYCLOAK_ADMIN_USER:\?/.test(content) &&
      /KC_BOOTSTRAP_ADMIN_PASSWORD:\s*\$\{KEYCLOAK_ADMIN_PASSWORD:\?/.test(content) &&
      !content.includes(':-admin') &&
      !/^\s*KEYCLOAK_ADMIN(?:_PASSWORD)?:/m.test(content),
    details: 'Requires KEYCLOAK_ADMIN_USER/KEYCLOAK_ADMIN_PASSWORD with no default fallback',
  },
  {
    name: 'Keycloak Realm Env: Required client secret and dev synthetic passwords without hardcoded secrets',
    pass:
      /OIDC_CLIENT_SECRET:\s*\$\{OIDC_CLIENT_SECRET:\?/.test(content) &&
      /KEYCLOAK_DEV_ADMIN_PASSWORD:\s*\$\{KEYCLOAK_DEV_ADMIN_PASSWORD:\?/.test(content) &&
      /KEYCLOAK_DEV_ANALYST_PASSWORD:\s*\$\{KEYCLOAK_DEV_ANALYST_PASSWORD:\?/.test(content) &&
      /KEYCLOAK_DEV_DEVELOPER_PASSWORD:\s*\$\{KEYCLOAK_DEV_DEVELOPER_PASSWORD:\?/.test(content) &&
      /-Dkeycloak\.migration\.replace-placeholders=true/.test(content),
    details: 'Passes required Keycloak client and dev user secret placeholders from .env',
  },
  {
    name: 'Keycloak Container Name: secureflow-keycloak',
    pass: /container_name:\s*secureflow-keycloak/.test(content),
    details: 'Explicit container naming for Keycloak service',
  },
  {
    name: 'Keycloak Network Isolation: 127.0.0.1:8080 loopback binding',
    pass: /-\s*["']127\.0\.0\.1:\$\{KEYCLOAK_PORT:-8080\}:8080["']/.test(content),
    details: 'Guarantees Keycloak binds to loopback interface on port 8080',
  },
  {
    name: 'Keycloak Dependency: Depends on healthy postgres',
    pass: /depends_on:\s*\n\s*postgres:\s*\n\s*condition:\s*service_healthy/.test(content),
    details: 'Keycloak startup waits for postgres container to report healthy',
  },
];

let failed = 0;
for (const check of checks) {
  if (check.pass) {
    console.log(`✅ PASS: ${check.name}`);
  } else {
    console.error(`❌ FAIL: ${check.name} (${check.details})`);
    failed++;
  }
}

console.log('==========================================================');
if (failed === 0) {
  console.log(`Summary: All ${checks.length} Docker Compose validation rules passed!`);
  process.exit(0);
} else {
  console.error(`Summary: ${failed} out of ${checks.length} validation checks failed.`);
  process.exit(1);
}
