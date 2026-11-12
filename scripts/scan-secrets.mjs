import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const defaultRepoRoot = path.resolve(__dirname, '..');

/**
 * Narrowly scoped allowlist for verified synthetic single-segment RFC 7519 JWT
 * header fixtures. Matched by normalized relative file path AND exact SHA-256
 * digest of the token segment so that any new or modified token in those files
 * still triggers a failure.
 *
 * Note: This pattern scanner operates as a defense-in-depth layer alongside
 * Gitleaks and does not claim exhaustive coverage of all possible credential formats.
 */
export const VERIFIED_SYNTHETIC_JWT_HEADER_ALLOWLIST = [
  {
    file: 'apps/api/tests/unit/audit-controller.test.ts',
    digest: [
      '61effba38add3bf51fd9f9a77b5a5a16',
      '5ebcf948aaf73a45a0a525c3b0c9b4cc',
    ].join(''),
    reason:
      'Verified synthetic 36-char RFC 7519 RS256 header fixture (no payload, no signature)',
  },
  {
    file: 'apps/api/tests/unit/auth-guard.test.ts',
    digest: [
      'd328d517e09060d1aad34f3fb12d82ab',
      '8e9a15d81032638698758add385a9454',
    ].join(''),
    reason:
      'Verified synthetic 36-char RFC 7519 HS256 header fixture (malformed Bearer rejection test)',
  },
];

/**
 * Approved local development, CI dummy, and unit-test synthetic PostgreSQL URI
 * password placeholders.
 */
export const APPROVED_POSTGRES_URI_PLACEHOLDERS = new Set([
  'secureflow_dev_password_change_me',
  'ci_dummy_pass',
  'pass',
  'dummy-token',
  'super_secret_dev_pass',
  'super_secret_test_pass',
  'synthetic_prod_fixture_placeholder',
  '<PASSWORD>',
  'password]',
  '[REDACTED]',
]);

export const ALLOWED_ENV_TEMPLATES = new Set([
  '.env.example',
  'apps/api/.env.example',
]);

export const FORBIDDEN_FILE_PATTERNS = [
  /^\.env(?:\..+)?$/,
  /(?:^|\/)\.env(?:\..+)?$/,
  /\.(?:pem|key|pfx|p12|jks|keystore|kdbx|cert)$/i,
];

export const SECRET_RULES = [
  {
    id: 'FULL_JWT_TOKEN',
    description: 'Complete 3-segment JWT (header.payload.signature)',
    regex: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
  },
  {
    id: 'PRIVATE_KEY_HEADER',
    description: 'PEM or OpenSSH private key block header',
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----/g,
  },
  {
    id: 'GITHUB_TOKEN',
    description: 'GitHub Personal, OAuth, App, or Fine-Grained Token',
    regex: /\b(?:(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})\b/g,
  },
  {
    id: 'AWS_ACCESS_KEY_ID',
    description: 'AWS IAM Access Key ID',
    regex: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
  },
  {
    id: 'GOOGLE_API_KEY',
    description: 'Google Cloud / Firebase API Key',
    regex: /\bAIza[0-9A-Za-z_-]{35}\b/g,
  },
  {
    id: 'SLACK_TOKEN',
    description: 'Slack Bot/User/Workspace Token',
    regex: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g,
  },
  {
    id: 'LIVE_API_SECRET_KEY',
    description: 'Stripe Live or AI Provider Secret Key',
    regex: /\b(?:sk_live_[0-9A-Za-z]{20,}|sk-proj-[0-9A-Za-z_-]{20,}|sk-ant-[0-9A-Za-z_-]{20,})\b/g,
  },
];

export function normalizeRepoPath(filePath) {
  return String(filePath).replace(/\\/g, '/').replace(/^\.\//, '');
}

export function sha256Hex(value) {
  return crypto.createHash('sha256').update(value, 'utf8').digest('hex');
}

export function isForbiddenTrackedFile(rawRelPath) {
  const relPath = normalizeRepoPath(rawRelPath);
  return (
    FORBIDDEN_FILE_PATTERNS.some((pattern) => pattern.test(relPath)) &&
    !ALLOWED_ENV_TEMPLATES.has(relPath)
  );
}

/**
 * Scans a single file's text content and returns structured, redacted findings
 * (never including raw secret strings).
 */
export function scanContentForSecrets(rawRelPath, content) {
  const relPath = normalizeRepoPath(rawRelPath);
  const violations = [];
  const allowlistedHits = [];

  if (isForbiddenTrackedFile(relPath)) {
    violations.push({
      file: relPath,
      line: 1,
      ruleId: 'FORBIDDEN_SECRET_FILE',
      description: 'Tracked environment or private key file is prohibited in Git',
      digestPrefix: 'n/a',
      length: 0,
    });
    return { violations, allowlistedHits };
  }

  const lines = content.split(/\r?\n/);

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNo = i + 1;

    // 1. Evaluate high-confidence secret patterns
    for (const rule of SECRET_RULES) {
      const regex = new RegExp(rule.regex.source, rule.regex.flags);
      let match;
      while ((match = regex.exec(line)) !== null) {
        const candidate = match[0];
        const digest = sha256Hex(candidate);
        violations.push({
          file: relPath,
          line: lineNo,
          ruleId: rule.id,
          description: rule.description,
          digestPrefix: digest.slice(0, 16),
          length: candidate.length,
        });
      }
    }

    // 2. Evaluate single-segment or partial JWT-like candidates (eyJ...)
    const jwtSegmentRegex = /\beyJ[A-Za-z0-9_-]{15,}\b/g;
    let jwtMatch;
    while ((jwtMatch = jwtSegmentRegex.exec(line)) !== null) {
      const candidate = jwtMatch[0];
      const digest = sha256Hex(candidate);
      const allowEntry = VERIFIED_SYNTHETIC_JWT_HEADER_ALLOWLIST.find(
        (entry) => entry.file === relPath && entry.digest === digest,
      );

      if (allowEntry) {
        allowlistedHits.push({
          file: relPath,
          line: lineNo,
          digestPrefix: digest.slice(0, 16),
          length: candidate.length,
          reason: allowEntry.reason,
        });
      } else {
        violations.push({
          file: relPath,
          line: lineNo,
          ruleId: 'UNAPPROVED_JWT_CANDIDATE',
          description: 'Unapproved JWT or Base64 JSON token candidate',
          digestPrefix: digest.slice(0, 16),
          length: candidate.length,
        });
      }
    }

    // 3. Evaluate PostgreSQL connection URI passwords
    const pgUriRegex = /postgres(?:ql)?:\/\/[^:\s'"`]+:([^@\s'"`]+)@/g;
    let pgMatch;
    while ((pgMatch = pgUriRegex.exec(line)) !== null) {
      const passwordCandidate = pgMatch[1];
      if (
        !passwordCandidate ||
        passwordCandidate.startsWith('${') ||
        APPROVED_POSTGRES_URI_PLACEHOLDERS.has(passwordCandidate)
      ) {
        continue;
      }

      const digest = sha256Hex(passwordCandidate);
      violations.push({
        file: relPath,
        line: lineNo,
        ruleId: 'UNAPPROVED_POSTGRES_URI_PASSWORD',
        description: 'Unapproved password in PostgreSQL connection URI',
        digestPrefix: digest.slice(0, 16),
        length: passwordCandidate.length,
      });
    }

    // 4. Evaluate Keycloak realm JSON imports for hardcoded client secrets or passwords
    if (/^infra\/keycloak\/.*\.json$/i.test(relPath)) {
      const realmCredRegex = /"(secret|value)"\s*:\s*"([^"]+)"/g;
      let realmMatch;
      while ((realmMatch = realmCredRegex.exec(line)) !== null) {
        const fieldName = realmMatch[1];
        const candidate = realmMatch[2];
        if (/^\$\{[A-Z0-9_]+\}$/.test(candidate)) {
          continue;
        }
        const digest = sha256Hex(candidate);
        violations.push({
          file: relPath,
          line: lineNo,
          ruleId: 'HARDCODED_KEYCLOAK_REALM_CREDENTIAL',
          description: `Hardcoded '${fieldName}' credential in Keycloak realm import (must use \${ENV_VAR} substitution)`,
          digestPrefix: digest.slice(0, 16),
          length: candidate.length,
        });
      }
    }

    // 5. Evaluate Compose configurations for fallback admin/secret defaults
    if (/^compose\.ya?ml$/i.test(relPath)) {
      const composeFallbackRegex =
        /(?:KEYCLOAK_ADMIN(?:_USER|_PASSWORD)?|KC_BOOTSTRAP_ADMIN_(?:USERNAME|PASSWORD)|OIDC_CLIENT_SECRET|KEYCLOAK_DEV_[A-Z0-9_]+_PASSWORD)\s*:\s*\$\{[A-Z0-9_]+:-([^}]+)\}/gi;
      let composeMatch;
      while ((composeMatch = composeFallbackRegex.exec(line)) !== null) {
        const candidate = composeMatch[1];
        const digest = sha256Hex(candidate);
        violations.push({
          file: relPath,
          line: lineNo,
          ruleId: 'HARDCODED_COMPOSE_FALLBACK_CREDENTIAL',
          description: 'Default fallback credential in Compose configuration (must use :? required error syntax)',
          digestPrefix: digest.slice(0, 16),
          length: candidate.length,
        });
      }
    }
  }

  return { violations, allowlistedHits };
}

export function listGitScopedFiles(repoRoot = defaultRepoRoot) {
  const trackedFilesRaw = execFileSync(
    'git',
    ['ls-files', '--cached', '--others', '--exclude-standard'],
    {
      cwd: repoRoot,
      encoding: 'utf8',
    },
  );

  return trackedFilesRaw
    .split(/\r?\n/)
    .map((f) => normalizeRepoPath(f.trim()))
    .filter(Boolean);
}

export function scanRepositoryFiles(repoRoot = defaultRepoRoot, customRelPaths) {
  const relPaths = customRelPaths
    ? customRelPaths.map(normalizeRepoPath)
    : listGitScopedFiles(repoRoot);

  const allViolations = [];
  const allAllowlistedHits = [];

  for (const relPath of relPaths) {
    if (isForbiddenTrackedFile(relPath)) {
      const { violations } = scanContentForSecrets(relPath, '');
      allViolations.push(...violations);
      continue;
    }

    const absPath = path.resolve(repoRoot, relPath);
    if (!fs.existsSync(absPath) || fs.statSync(absPath).isDirectory()) {
      continue;
    }

    const content = fs.readFileSync(absPath, 'utf8');
    const { violations, allowlistedHits } = scanContentForSecrets(relPath, content);
    allViolations.push(...violations);
    allAllowlistedHits.push(...allowlistedHits);
  }

  return {
    scannedCount: relPaths.length,
    violations: allViolations,
    allowlistedHits: allAllowlistedHits,
  };
}

function runCli() {
  console.log('=== SecureFlow Automated Secret & Credential Scanner ===');
  const args = process.argv.slice(2);
  let customPaths;
  const targetIdx = args.indexOf('--target');
  if (targetIdx !== -1 && args[targetIdx + 1]) {
    customPaths = [args[targetIdx + 1]];
  }

  const result = scanRepositoryFiles(defaultRepoRoot, customPaths);

  console.log(`Scanned ${result.scannedCount} Git-scoped file(s).`);
  for (const hit of result.allowlistedHits) {
    console.log(
      `ℹ️  ALLOWLISTED_SYNTHETIC_FIXTURE: ${hit.file}:${hit.line} (len=${hit.length}, sha256=${hit.digestPrefix}...) — ${hit.reason}`,
    );
  }

  if (result.violations.length > 0) {
    console.error('==========================================================');
    console.error(
      `❌ FAIL: ${result.violations.length} potential secret exposure(s) detected:`,
    );
    for (const v of result.violations) {
      console.error(
        `  - [${v.ruleId}] ${v.file}:${v.line} (len=${v.length}, sha256=${v.digestPrefix}...) — ${v.description}`,
      );
    }
    console.error('==========================================================');
    process.exit(1);
  }

  console.log(
    '✅ PASS: Zero real secrets or unapproved credentials detected in scanned files.',
  );
  console.log('==========================================================');
  process.exit(0);
}

if (path.resolve(process.argv[1] ?? '') === __filename) {
  runCli();
}
