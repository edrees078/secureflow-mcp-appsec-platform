import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '../../../..');
const customScannerScript = path.join(repoRoot, 'scripts', 'scan-secrets.mjs');
const gitleaksConfigPath = path.join(repoRoot, '.gitleaks.toml');
const gitleaksBinaryPath = path.join(
  repoRoot,
  '.cache',
  'gitleaks',
  'v8.24.2',
  process.platform === 'win32' ? 'gitleaks.exe' : 'gitleaks',
);

interface CustomScannerModule {
  normalizeRepoPath: (p: string) => string;
  isForbiddenTrackedFile: (p: string) => boolean;
  listGitScopedFiles: (root?: string) => string[];
  scanContentForSecrets: (
    relPath: string,
    content: string,
  ) => {
    violations: Array<{
      file: string;
      line: number;
      ruleId: string;
      description: string;
      digestPrefix: string;
      length: number;
    }>;
    allowlistedHits: Array<{
      file: string;
      line: number;
      digestPrefix: string;
      length: number;
      reason: string;
    }>;
  };
}

async function loadCustomScanner(): Promise<CustomScannerModule> {
  const moduleUrl = new URL(`file:///${customScannerScript.replace(/\\/g, '/')}`);
  return (await import(moduleUrl.href)) as CustomScannerModule;
}

describe('Secret Scanners (Gitleaks v8.24.2 & Custom Defense-in-Depth Scanner)', () => {
  it('passes on the repository with only verified synthetic JWT headers allowlisted', async () => {
    const cliRes = spawnSync(process.execPath, [customScannerScript], {
      cwd: repoRoot,
      encoding: 'utf8',
    });

    expect(cliRes.status).toBe(0);
    expect(cliRes.stdout).toContain('ALLOWLISTED_SYNTHETIC_FIXTURE');
    expect(cliRes.stdout).toContain('Zero real secrets or unapproved credentials detected');
  });

  it('normalizes Windows backslash paths and rejects forbidden tracked .env and private key files while permitting .env.example templates', async () => {
    const scanner = await loadCustomScanner();

    expect(
      scanner.normalizeRepoPath('apps\\api\\tests\\unit\\audit-controller.test.ts'),
    ).toBe('apps/api/tests/unit/audit-controller.test.ts');

    // Allowed templates
    expect(scanner.isForbiddenTrackedFile('.env.example')).toBe(false);
    expect(scanner.isForbiddenTrackedFile('apps\\api\\.env.example')).toBe(false);

    // Forbidden secret files
    expect(scanner.isForbiddenTrackedFile('.env')).toBe(true);
    expect(scanner.isForbiddenTrackedFile('.env.production')).toBe(true);
    expect(scanner.isForbiddenTrackedFile('apps\\api\\.env.local')).toBe(true);
    expect(scanner.isForbiddenTrackedFile('certs\\private.pem')).toBe(true);
    expect(scanner.isForbiddenTrackedFile('keys/service.key')).toBe(true);

    const forbiddenScan = scanner.scanContentForSecrets('apps\\api\\.env.local', 'PORT=3000');
    expect(forbiddenScan.violations).toHaveLength(1);
    expect(forbiddenScan.violations[0]?.ruleId).toBe('FORBIDDEN_SECRET_FILE');
  });

  it('excludes gitignored local secret files (such as .env.local) when enumerating Git-scoped files', async () => {
    const scanner = await loadCustomScanner();
    const tempIgnoredFile = path.join(repoRoot, '.env.local');
    const existedBefore = fs.existsSync(tempIgnoredFile);
    const previousContent = existedBefore ? fs.readFileSync(tempIgnoredFile, 'utf8') : '';

    try {
      if (!existedBefore) {
        fs.writeFileSync(tempIgnoredFile, 'LOCAL_DEV_ONLY=1\n', 'utf8');
      }
      const scopedFiles = scanner.listGitScopedFiles(repoRoot);
      expect(scopedFiles).not.toContain('.env.local');
      expect(scopedFiles).toContain('.env.example');
      expect(scopedFiles).toContain('apps/api/.env.example');
    } finally {
      if (!existedBefore) {
        fs.rmSync(tempIgnoredFile, { force: true });
      } else {
        fs.writeFileSync(tempIgnoredFile, previousContent, 'utf8');
      }
    }
  });

  it('preserves exact SHA-256 fixture allowlist on Windows/POSIX paths and rejects modified or unknown JWT-like candidates even inside audit-controller.test.ts', async () => {
    const scanner = await loadCustomScanner();

    const exactAllowlistedHeader = ['eyJhbGci', 'OiJSUzI1NiIs', 'InR5cCI6IkpXVCJ9'].join('');
    const allowedRes = scanner.scanContentForSecrets(
      'apps\\api\\tests\\unit\\audit-controller.test.ts',
      `const fixture = { accessToken: '${exactAllowlistedHeader}' };`,
    );
    expect(allowedRes.violations).toHaveLength(0);
    expect(allowedRes.allowlistedHits).toHaveLength(1);

    // Modify 1 character in the synthetic header inside the same allowlisted file
    const modifiedHeader = ['eyJhbGci', 'OiJSUzI1NiIs', 'InR5cCI6IkpXVCJ0'].join('');
    const rejectedInSameFile = scanner.scanContentForSecrets(
      'apps/api/tests/unit/audit-controller.test.ts',
      `const fixture = { accessToken: '${modifiedHeader}' };`,
    );
    expect(rejectedInSameFile.violations).toHaveLength(1);
    expect(rejectedInSameFile.violations[0]?.ruleId).toBe('UNAPPROVED_JWT_CANDIDATE');
    expect(JSON.stringify(rejectedInSameFile)).not.toContain(modifiedHeader);

    // Place the exact allowlisted header into a different file -> must be rejected
    const rejectedInOtherFile = scanner.scanContentForSecrets(
      'apps/api/src/server.ts',
      `const leaked = '${exactAllowlistedHeader}';`,
    );
    expect(rejectedInOtherFile.violations).toHaveLength(1);
    expect(rejectedInOtherFile.violations[0]?.ruleId).toBe('UNAPPROVED_JWT_CANDIDATE');
  });

  it('detects synthetic 3-segment JWTs, PEM private keys, GitHub tokens, AWS keys, and unapproved PostgreSQL passwords without leaking raw values in output', async () => {
    const scanner = await loadCustomScanner();

    const syntheticFullJwt = [
      ['eyJhbGci', 'OiJIUzI1NiIs', 'InR5cCI6IkpXVCJ9'].join(''),
      ['eyJzdWIi', 'OiIxMjM0NTY3ODkwIiw', 'ibmFtZSI6IlN5bnRoZXRpYyJ9'].join(''),
      'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
    ].join('.');
    const syntheticPemHeader = ['-----BEGIN RSA ', 'PRIVATE KEY-----'].join('');
    const syntheticGithubPat = ['ghp', '_', 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8'].join('');
    const syntheticAwsKey = ['AKIA', 'IOSFODNN7EXAMPLE'].join('');
    const syntheticPgPass = ['UnapprovedProd', 'DbPass999!'].join('');
    const syntheticPgUri = `postgresql://admin:${syntheticPgPass}@db.internal:5432/prod`;

    const sampleContent = [
      `const jwt = "${syntheticFullJwt}";`,
      `const pem = "${syntheticPemHeader}";`,
      `const gh = "${syntheticGithubPat}";`,
      `const aws = "${syntheticAwsKey}";`,
      `const db = "${syntheticPgUri}";`,
    ].join('\n');

    const res = scanner.scanContentForSecrets('apps/api/tests/unit/sample.ts', sampleContent);
    const ruleIds = res.violations.map((v) => v.ruleId);

    expect(ruleIds).toContain('FULL_JWT_TOKEN');
    expect(ruleIds).toContain('PRIVATE_KEY_HEADER');
    expect(ruleIds).toContain('GITHUB_TOKEN');
    expect(ruleIds).toContain('AWS_ACCESS_KEY_ID');
    expect(ruleIds).toContain('UNAPPROVED_POSTGRES_URI_PASSWORD');

    const serialized = JSON.stringify(res);
    expect(serialized).not.toContain(syntheticFullJwt);
    expect(serialized).not.toContain(syntheticGithubPat);
    expect(serialized).not.toContain(syntheticAwsKey);
    expect(serialized).not.toContain(syntheticPgPass);
  });

  it('returns nonzero exit status from CLI without printing raw secrets when scanning a file with an unallowlisted synthetic credential', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sf-scanner-neg-'));
    try {
      const tmpFile = path.join(tmpDir, 'synthetic-leak.ts');
      const syntheticGhToken = ['ghp', '_', 'Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3i2'].join('');
      fs.writeFileSync(tmpFile, `export const token = '${syntheticGhToken}';\n`, 'utf8');

      const cliRes = spawnSync(
        process.execPath,
        [customScannerScript, '--target', tmpFile],
        {
          cwd: repoRoot,
          encoding: 'utf8',
        },
      );

      expect(cliRes.status).toBe(1);
      const combinedOutput = `${cliRes.stdout}\n${cliRes.stderr}`;
      expect(combinedOutput).toContain('GITHUB_TOKEN');
      expect(combinedOutput).not.toContain(syntheticGhToken);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('verifies Gitleaks v8.24.2 .gitleaks.toml allowlist does NOT mask a new credential or modified generic-api-key placed inside audit-controller.test.ts and redacts output', () => {
    expect(fs.existsSync(gitleaksBinaryPath)).toBe(true);

    const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'sf-gitleaks-neg-'));
    try {
      const nestedTestDir = path.join(tmpRoot, 'apps', 'api', 'tests', 'unit');
      fs.mkdirSync(nestedTestDir, { recursive: true });
      const targetFile = path.join(nestedTestDir, 'audit-controller.test.ts');

      const originalContent = fs.readFileSync(
        path.join(repoRoot, 'apps', 'api', 'tests', 'unit', 'audit-controller.test.ts'),
        'utf8',
      );

      // 1. Exact original audit-controller.test.ts passes Gitleaks with .gitleaks.toml
      fs.writeFileSync(targetFile, originalContent, 'utf8');
      const passRes = spawnSync(
        gitleaksBinaryPath,
        [
          'dir',
          tmpRoot,
          '--config',
          gitleaksConfigPath,
          '--redact',
          '--no-banner',
          '-v',
          '--exit-code',
          '1',
        ],
        { encoding: 'utf8' },
      );
      expect(passRes.status).toBe(0);

      // 2. Injecting an unrelated synthetic GitHub PAT into audit-controller.test.ts is DETECTED (exit code 1)
      const syntheticGhToken = ['ghp', '_', 'M1n2B3v4C5x6Z7a8S9d0F1g2H3j4K5l6Q7w8'].join('');
      fs.writeFileSync(
        targetFile,
        `${originalContent}\nconst injectedSecret = '${syntheticGhToken}';\n`,
        'utf8',
      );

      const failResGh = spawnSync(
        gitleaksBinaryPath,
        [
          'dir',
          tmpRoot,
          '--config',
          gitleaksConfigPath,
          '--redact',
          '--no-banner',
          '-v',
          '--exit-code',
          '1',
        ],
        { encoding: 'utf8' },
      );

      expect(failResGh.status).toBe(1);
      const combinedLogsGh = `${failResGh.stdout}\n${failResGh.stderr}`;
      expect(combinedLogsGh).toContain('github-pat');
      expect(combinedLogsGh).toContain('REDACTED');
      expect(combinedLogsGh).not.toContain(syntheticGhToken);

      // 3. Injecting a modified generic-api-key in audit-controller.test.ts is ALSO DETECTED (exit code 1)
      const modifiedKey = ['eyJhbGci', 'OiJSUzI1NiIs', 'InR5cCI6IkpXVCJ0'].join('');
      fs.writeFileSync(
        targetFile,
        `${originalContent}\nconst anotherFixture = { accessToken: '${modifiedKey}' };\n`,
        'utf8',
      );

      const failResGeneric = spawnSync(
        gitleaksBinaryPath,
        [
          'dir',
          tmpRoot,
          '--config',
          gitleaksConfigPath,
          '--redact',
          '--no-banner',
          '-v',
          '--exit-code',
          '1',
        ],
        { encoding: 'utf8' },
      );

      expect(failResGeneric.status).toBe(1);
      const combinedLogsGeneric = `${failResGeneric.stdout}\n${failResGeneric.stderr}`;
      expect(combinedLogsGeneric).toContain('generic-api-key');
      expect(combinedLogsGeneric).toContain('REDACTED');
      expect(combinedLogsGeneric).not.toContain(modifiedKey);
    } finally {
      fs.rmSync(tmpRoot, { recursive: true, force: true });
    }
  });
});
