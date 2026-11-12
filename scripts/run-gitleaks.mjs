import { execFileSync, spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import https from 'node:https';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '..');

export const GITLEAKS_VERSION = '8.24.2';

/**
 * Official SHA-256 checksums from:
 * https://github.com/gitleaks/gitleaks/releases/download/v8.24.2/gitleaks_8.24.2_checksums.txt
 */
export const OFFICIAL_GITLEAKS_ARCHIVES = {
  'win32:x64': {
    filename: `gitleaks_${GITLEAKS_VERSION}_windows_x64.zip`,
    sha256: 'cc47fdc0364964e2d346fbbcbe4cc87f34d490b2647508fb05930d0ec2fbff07',
    binaryName: 'gitleaks.exe',
  },
  'linux:x64': {
    filename: `gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz`,
    sha256: 'fa0500f6b7e41d28791ebc680f5dd9899cd42b58629218a5f041efa899151a8e',
    binaryName: 'gitleaks',
  },
  'linux:arm64': {
    filename: `gitleaks_${GITLEAKS_VERSION}_linux_arm64.tar.gz`,
    sha256: '574a6d52573c61173add7ddb5e3cc68c0e82cb0735818a1eeb9a0a2de1643fbc',
    binaryName: 'gitleaks',
  },
  'darwin:x64': {
    filename: `gitleaks_${GITLEAKS_VERSION}_darwin_x64.tar.gz`,
    sha256: 'bc3c46f8039ba716ba8461fa6745c9d1cfb90ca2f5f881d8d0cf66b7ba7b742c',
    binaryName: 'gitleaks',
  },
  'darwin:arm64': {
    filename: `gitleaks_${GITLEAKS_VERSION}_darwin_arm64.tar.gz`,
    sha256: '90d13686937ac7429b97a3acbf1e1d0ce90d92ae2d0cf46a690bd8ae5230bea0',
    binaryName: 'gitleaks',
  },
};

function downloadFile(url, destPath) {
  return new Promise((resolve, reject) => {
    const request = (currentUrl, redirectsRemaining = 5) => {
      if (redirectsRemaining <= 0) {
        reject(new Error('Too many redirects while downloading Gitleaks archive'));
        return;
      }
      https
        .get(currentUrl, (res) => {
          if (
            res.statusCode &&
            res.statusCode >= 300 &&
            res.statusCode < 400 &&
            res.headers.location
          ) {
            res.resume();
            request(res.headers.location, redirectsRemaining - 1);
            return;
          }
          if (res.statusCode !== 200) {
            res.resume();
            reject(
              new Error(`Failed to download Gitleaks archive: HTTP ${res.statusCode}`),
            );
            return;
          }
          const fileStream = fs.createWriteStream(destPath);
          res.pipe(fileStream);
          fileStream.on('finish', () => {
            fileStream.close(() => resolve());
          });
          fileStream.on('error', reject);
        })
        .on('error', reject);
    };
    request(url);
  });
}

function computeFileSha256(filePath) {
  const bytes = fs.readFileSync(filePath);
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

export async function ensureGitleaksBinary() {
  const platformKey = `${process.platform}:${process.arch}`;
  const spec = OFFICIAL_GITLEAKS_ARCHIVES[platformKey];
  if (!spec) {
    throw new Error(`Unsupported platform/arch for pinned Gitleaks: ${platformKey}`);
  }

  const cacheDir = path.join(repoRoot, '.cache', 'gitleaks', `v${GITLEAKS_VERSION}`);
  const binaryPath = path.join(cacheDir, spec.binaryName);

  if (fs.existsSync(binaryPath)) {
    return binaryPath;
  }

  fs.mkdirSync(cacheDir, { recursive: true });
  const archivePath = path.join(cacheDir, spec.filename);
  const downloadUrl = `https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/${spec.filename}`;

  console.log(
    `Downloading official Gitleaks v${GITLEAKS_VERSION} (${spec.filename})...`,
  );
  await downloadFile(downloadUrl, archivePath);

  const actualSha256 = computeFileSha256(archivePath);
  if (actualSha256 !== spec.sha256) {
    fs.rmSync(archivePath, { force: true });
    throw new Error(
      `Gitleaks archive SHA-256 verification failed! Expected ${spec.sha256}, got ${actualSha256}`,
    );
  }

  execFileSync('tar', ['-xf', archivePath, '-C', cacheDir], {
    stdio: 'inherit',
  });

  // Remove non-binary files from cache directory so directory scans stay clean
  for (const extra of ['README.md', 'LICENSE', spec.filename]) {
    const extraPath = path.join(cacheDir, extra);
    if (fs.existsSync(extraPath)) {
      fs.rmSync(extraPath, { force: true });
    }
  }

  if (process.platform !== 'win32') {
    fs.chmodSync(binaryPath, 0o755);
  }

  return binaryPath;
}

export function runGitleaksSync(binaryPath, args, options = {}) {
  return spawnSync(binaryPath, args, {
    cwd: options.cwd ?? repoRoot,
    encoding: 'utf8',
    stdio: options.stdio ?? 'pipe',
  });
}

async function main() {
  const mode = process.argv[2] ?? 'all';
  const binaryPath = await ensureGitleaksBinary();
  const configPath = path.join(repoRoot, '.gitleaks.toml');

  const versionRes = runGitleaksSync(binaryPath, ['version']);
  const version = (versionRes.stdout || '').trim();
  console.log(`=== Gitleaks v${version} Official Scanner ===`);

  if (mode === 'version') {
    process.exit(0);
  }

  if (mode === 'git' || mode === 'all') {
    console.log('--- Running Gitleaks Git History Scan (gitleaks git) ---');
    const gitRes = runGitleaksSync(
      binaryPath,
      [
        'git',
        '.',
        '--config',
        configPath,
        '--redact',
        '--no-banner',
        '-v',
        '--exit-code',
        '1',
      ],
      { stdio: 'inherit' },
    );
    if (gitRes.status !== 0) {
      process.exit(gitRes.status ?? 1);
    }
  }

  if (mode === 'dir' || mode === 'all') {
    console.log('--- Running Gitleaks Directory Content Scan (gitleaks dir) ---');
    // Enumerate Git-scoped working-tree files (--cached --others --exclude-standard) so
    // untracked non-ignored files are scanned while gitignored local secret files (e.g. .env)
    // remain excluded from repository content scanning unless accidentally tracked.
    let dirRes;
    const isGitRepo = fs.existsSync(path.join(repoRoot, '.git'));
    if (isGitRepo) {
      const scopedRaw = execFileSync(
        'git',
        ['ls-files', '-z', '--cached', '--others', '--exclude-standard'],
        { cwd: repoRoot, encoding: 'utf8', maxBuffer: 20 * 1024 * 1024 },
      );
      const scopedFiles = scopedRaw.split('\0').filter(Boolean);
      const tmpScanRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'sf-gitleaks-dir-'));
      try {
        for (const relPath of scopedFiles) {
          const srcPath = path.join(repoRoot, relPath);
          if (!fs.existsSync(srcPath)) {
            continue;
          }
          const stat = fs.statSync(srcPath);
          if (!stat.isFile()) {
            continue;
          }
          const destPath = path.join(tmpScanRoot, relPath);
          fs.mkdirSync(path.dirname(destPath), { recursive: true });
          fs.copyFileSync(srcPath, destPath);
        }
        dirRes = runGitleaksSync(
          binaryPath,
          [
            'dir',
            '.',
            '--config',
            configPath,
            '--redact',
            '--no-banner',
            '-v',
            '--exit-code',
            '1',
          ],
          { cwd: tmpScanRoot, stdio: 'inherit' },
        );
      } finally {
        fs.rmSync(tmpScanRoot, { recursive: true, force: true });
      }
    } else {
      dirRes = runGitleaksSync(
        binaryPath,
        [
          'dir',
          '.',
          '--config',
          configPath,
          '--redact',
          '--no-banner',
          '-v',
          '--exit-code',
          '1',
        ],
        { stdio: 'inherit' },
      );
    }
    if (dirRes.status !== 0) {
      process.exit(dirRes.status ?? 1);
    }
  }

  console.log('=== Gitleaks Verification PASSED ===');
}

if (path.resolve(process.argv[1] ?? '') === __filename) {
  main().catch((err) => {
    console.error(err instanceof Error ? err.message : String(err));
    process.exit(1);
  });
}
