/**
 * SecureFlow Phase 5A — Reproducible Real-Browser Authentication E2E Smoke Verification
 *
 * Drives a real Chromium browser via Chrome DevTools Protocol against:
 *   - Vite dev server (http://127.0.0.1:5173, same-origin /api proxy to Express BFF)
 *   - Express BFF (http://127.0.0.1:3000)
 *   - Keycloak 26.8.2 (OIDC_ISSUER from environment)
 *   - PostgreSQL 17.11 (TEST_DATABASE_URL, verified strictly as secureflow_test)
 *
 * Usage:
 *   pnpm run test:web:browser
 *
 * Optional environment overrides:
 *   SECUREFLOW_WEB_URL=http://127.0.0.1:5173
 *   SECUREFLOW_API_URL=http://127.0.0.1:3000
 *   KEYCLOAK_DEV_USERNAME=dev@secureflow.example
 *   CHROME_BIN=/path/to/chrome
 */

import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import { createRequire } from 'node:module';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import type { TestDatabaseClient } from '../../packages/domain/src/testing/index.js';

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(SCRIPT_DIR, '../..');

const requireApi = createRequire(path.join(REPO_ROOT, 'apps/api/package.json'));
const requireWeb = createRequire(path.join(REPO_ROOT, 'apps/web/package.json'));
const dotenv = requireApi('dotenv') as { config: (options: { path: string }) => void };
dotenv.config({ path: path.join(REPO_ROOT, '.env') });

// Local E2E smoke runs against HTTP loopback Keycloak; ensure env module boot permits it in development/test.
if ((process.env['NODE_ENV'] ?? 'development') !== 'production' && !process.env['OIDC_ALLOW_INSECURE_HTTP']) {
  process.env['OIDC_ALLOW_INSECURE_HTTP'] = 'true';
}

const { createDomainServices } = await import('../../packages/domain/src/index.js');
const { createTestDatabaseClient, validateTestDatabaseUrl } = await import(
  '../../packages/domain/src/testing/index.js'
);
const { createApp } = await import('../../apps/api/src/app.js');
const { loadAuthConfig } = await import('../../apps/api/src/config/auth.js');

interface ViteDevServer {
  listen(): Promise<unknown>;
  close(): Promise<void>;
}

const viteModule = (await import(pathToFileURL(requireWeb.resolve('vite')).href)) as {
  createServer: (inlineConfig: Record<string, unknown>) => Promise<ViteDevServer>;
};

interface TableCounts {
  readonly users: number;
  readonly projects: number;
  readonly project_members: number;
  readonly findings: number;
  readonly remediation_tasks: number;
  readonly finding_events: number;
  readonly audit_events: number;
  readonly user_sessions: number;
  readonly oidc_transactions: number;
}

class CdpClient {
  private readonly ws: WebSocket;
  private nextId = 1;
  private readonly pending = new Map<
    number,
    { resolve: (val: unknown) => void; reject: (err: Error) => void }
  >();
  public readonly requests: Array<{ url: string; method: string; headers: Record<string, string> }> = [];
  public readonly responses: Array<{ url: string; status: number }> = [];

  private constructor(ws: WebSocket) {
    this.ws = ws;
    ws.addEventListener('message', (event) => {
      const msg = JSON.parse(String(event.data)) as {
        id?: number;
        result?: unknown;
        error?: { message: string };
        method?: string;
        params?: Record<string, unknown>;
      };
      if (msg.id !== undefined) {
        const entry = this.pending.get(msg.id);
        if (entry) {
          this.pending.delete(msg.id);
          if (msg.error) {
            entry.reject(new Error(msg.error.message));
          } else {
            entry.resolve(msg.result);
          }
        }
        return;
      }
      if (msg.method === 'Network.requestWillBeSent' && msg.params) {
        const req = msg.params['request'] as {
          url: string;
          method: string;
          headers: Record<string, string>;
        };
        this.requests.push({ url: req.url, method: req.method, headers: req.headers });
      }
      if (msg.method === 'Network.responseReceived' && msg.params) {
        const resp = msg.params['response'] as { url: string; status: number };
        this.responses.push({ url: resp.url, status: resp.status });
      }
    });
  }

  public static async connect(wsUrl: string): Promise<CdpClient> {
    const ws = new WebSocket(wsUrl);
    await new Promise<void>((resolve, reject) => {
      ws.addEventListener('open', () => resolve(), { once: true });
      ws.addEventListener('error', () => reject(new Error('CDP WebSocket connection error')), {
        once: true,
      });
    });
    const client = new CdpClient(ws);
    await client.send('Page.enable');
    await client.send('Runtime.enable');
    await client.send('Network.enable');
    return client;
  }

  public send<T = Record<string, unknown>>(
    method: string,
    params?: Record<string, unknown>,
  ): Promise<T> {
    const id = this.nextId++;
    return new Promise<T>((resolve, reject) => {
      this.pending.set(id, {
        resolve: resolve as (v: unknown) => void,
        reject,
      });
      this.ws.send(JSON.stringify({ id, method, ...(params ? { params } : {}) }));
    });
  }

  public async evaluate<T = unknown>(expression: string): Promise<T> {
    const res = await this.send<{
      result?: { value?: T };
      exceptionDetails?: { text: string };
    }>('Runtime.evaluate', {
      expression,
      awaitPromise: true,
      returnByValue: true,
    });
    if (res.exceptionDetails) {
      throw new Error(`Browser evaluate error: ${res.exceptionDetails.text}`);
    }
    return res.result?.value as T;
  }

  public close(): void {
    this.ws.close();
  }
}

function resolveChromeBinary(): string {
  const configured = process.env['CHROME_BIN']?.trim();
  if (configured) {
    if (!fs.existsSync(configured)) {
      throw new Error(`CHROME_BIN does not exist at '${configured}'.`);
    }
    return configured;
  }

  const localAppData = process.env['LOCALAPPDATA'] ?? '';
  const candidates = [
    'C:/Program Files/Google/Chrome/Application/chrome.exe',
    'C:/Program Files (x86)/Google/Chrome/Application/chrome.exe',
    ...(localAppData ? [path.join(localAppData, 'Google/Chrome/Application/chrome.exe')] : []),
    '/usr/bin/google-chrome',
    '/usr/bin/chromium',
    '/usr/bin/chromium-browser',
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  ];

  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }

  for (const commandName of ['google-chrome', 'chromium', 'chromium-browser']) {
    const probe = spawnSync(commandName, ['--version'], { stdio: 'ignore' });
    if (probe.status === 0) {
      return commandName;
    }
  }

  throw new Error(
    'Unable to locate Chrome or Chromium binary. Set CHROME_BIN to your browser executable path.',
  );
}

async function waitFor<T>(
  fn: () => Promise<T | null | false>,
  label: string,
  timeoutMs = 15000,
): Promise<T> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const val = await fn();
    if (val) return val;
    await new Promise((r) => setTimeout(r, 150));
  }
  throw new Error(`Timed out waiting for: ${label}`);
}

async function readTableCounts(db: TestDatabaseClient): Promise<TableCounts> {
  const [
    users,
    projects,
    projectMembers,
    findings,
    tasks,
    findingEvents,
    auditEvents,
    sessions,
    txns,
  ] = await Promise.all([
    db.query<{ count: string }>('SELECT COUNT(*) FROM public.users;'),
    db.query<{ count: string }>('SELECT COUNT(*) FROM public.projects;'),
    db.query<{ count: string }>('SELECT COUNT(*) FROM public.project_members;'),
    db.query<{ count: string }>('SELECT COUNT(*) FROM public.findings;'),
    db.query<{ count: string }>('SELECT COUNT(*) FROM public.remediation_tasks;'),
    db.query<{ count: string }>('SELECT COUNT(*) FROM public.finding_events;'),
    db.query<{ count: string }>('SELECT COUNT(*) FROM public.audit_events;'),
    db.query<{ count: string }>('SELECT COUNT(*) FROM public.user_sessions;'),
    db.query<{ count: string }>('SELECT COUNT(*) FROM public.oidc_transactions;'),
  ]);

  return {
    users: parseInt(users.rows[0]?.count ?? '0', 10),
    projects: parseInt(projects.rows[0]?.count ?? '0', 10),
    project_members: parseInt(projectMembers.rows[0]?.count ?? '0', 10),
    findings: parseInt(findings.rows[0]?.count ?? '0', 10),
    remediation_tasks: parseInt(tasks.rows[0]?.count ?? '0', 10),
    finding_events: parseInt(findingEvents.rows[0]?.count ?? '0', 10),
    audit_events: parseInt(auditEvents.rows[0]?.count ?? '0', 10),
    user_sessions: parseInt(sessions.rows[0]?.count ?? '0', 10),
    oidc_transactions: parseInt(txns.rows[0]?.count ?? '0', 10),
  };
}

async function main(): Promise<void> {
  const testDbUrl = process.env['TEST_DATABASE_URL']?.trim();
  const devUsername = process.env['KEYCLOAK_DEV_USERNAME']?.trim() || 'dev@secureflow.example';
  const devPassword = process.env['KEYCLOAK_DEV_DEVELOPER_PASSWORD']?.trim();
  if (!testDbUrl || !devPassword) {
    throw new Error(
      'TEST_DATABASE_URL and KEYCLOAK_DEV_DEVELOPER_PASSWORD must be configured in the environment or .env.',
    );
  }
  validateTestDatabaseUrl(testDbUrl);

  const webUrl = new URL(process.env['SECUREFLOW_WEB_URL']?.trim() || 'http://127.0.0.1:5173');
  const apiUrl = new URL(process.env['SECUREFLOW_API_URL']?.trim() || 'http://127.0.0.1:3000');
  const webOrigin = webUrl.origin;
  const apiOrigin = apiUrl.origin;
  const apiPort = parseInt(apiUrl.port || '3000', 10);
  const webPort = parseInt(webUrl.port || '5173', 10);
  const chromeBinary = resolveChromeBinary();

  const db = await createTestDatabaseClient(testDbUrl);

  const existingCollision = await db.query<{ id: string }>(
    'SELECT id FROM public.users WHERE lower(email) = lower($1);',
    [devUsername],
  );
  if (existingCollision.rows.length > 0) {
    await db.close();
    throw new Error(
      `Refusing smoke run because test user '${devUsername}' already exists in baseline public.users.`,
    );
  }

  const initialCounts = await readTableCounts(db);
  const initialUserIds = (await db.query<{ id: string }>('SELECT id FROM public.users;')).rows.map(
    (r) => r.id,
  );
  const initialSessionIds = (
    await db.query<{ id: string }>('SELECT id FROM public.user_sessions;')
  ).rows.map((r) => r.id);
  const initialTxnIds = (
    await db.query<{ id: string }>('SELECT id FROM public.oidc_transactions;')
  ).rows.map((r) => r.id);
  const initialAuditIds = (
    await db.query<{ id: string }>('SELECT id FROM public.audit_events;')
  ).rows.map((r) => r.id);

  const authConfig = loadAuthConfig({
    ...process.env,
    NODE_ENV: 'development',
    AUTH_ENABLED: 'true',
    CORS_ORIGIN: webOrigin,
    OIDC_REDIRECT_URI: `${apiOrigin}/api/v1/auth/callback`,
    OIDC_POST_LOGOUT_REDIRECT_URI: `${webOrigin}/login`,
    OIDC_ALLOW_INSECURE_HTTP: 'true',
  });
  const oidcIssuerOrigin = new URL(authConfig.oidc.issuerUrl).origin;

  const domainServices = createDomainServices({ connectionString: testDbUrl });
  const app = createApp(domainServices, { authConfig });
  const apiServer = await new Promise<ReturnType<typeof app.listen>>((resolve) => {
    const srv = app.listen(apiPort, apiUrl.hostname, () => resolve(srv));
  });

  const viteServer = await viteModule.createServer({
    configFile: path.join(REPO_ROOT, 'apps/web/vite.config.ts'),
    root: path.join(REPO_ROOT, 'apps/web'),
    server: {
      host: webUrl.hostname,
      port: webPort,
      strictPort: true,
    },
  });
  await viteServer.listen();

  const tempProfileDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sf-chrome-smoke-'));
  let chromeProc: ChildProcess | null = null;
  let cdp: CdpClient | null = null;
  let disposableProjectId: string | null = null;

  try {
    const debugPort = 9229;
    chromeProc = spawn(
      chromeBinary,
      [
        '--headless=new',
        '--disable-gpu',
        '--no-first-run',
        '--no-default-browser-check',
        `--user-data-dir=${tempProfileDir}`,
        `--remote-debugging-port=${debugPort}`,
        `${webOrigin}/workspace`,
      ],
      { stdio: 'ignore' },
    );

    const target = await waitFor(async () => {
      try {
        const res = await fetch(`http://127.0.0.1:${debugPort}/json/list`);
        if (!res.ok) return null;
        const list = (await res.json()) as Array<{ type: string; webSocketDebuggerUrl?: string }>;
        return list.find((t) => t.type === 'page' && t.webSocketDebuggerUrl) ?? null;
      } catch {
        return null;
      }
    }, 'Chrome CDP page target');

    if (!target.webSocketDebuggerUrl) {
      throw new Error('Chrome CDP target did not expose webSocketDebuggerUrl');
    }

    cdp = await CdpClient.connect(target.webSocketDebuggerUrl);

    // 1. Anonymous initial load -> redirects to /login
    await waitFor(
      async () =>
        cdp !== null &&
        cdp.evaluate<boolean>(
          `window.location.href.startsWith(${JSON.stringify(`${webOrigin}/login`)}) && document.body?.innerText?.includes('Sign in to SecureFlow')`,
        ),
      'Anonymous redirect to /login',
    );
    const anonStorage = await cdp.evaluate<{ local: number; session: number; cookie: string }>(
      `({ local: localStorage.length, session: sessionStorage.length, cookie: document.cookie })`,
    );
    if (anonStorage.local !== 0 || anonStorage.session !== 0 || anonStorage.cookie !== '') {
      throw new Error(`Unexpected browser storage while anonymous: ${JSON.stringify(anonStorage)}`);
    }
    console.log('PASS 1: Anonymous /workspace -> redirected to /login with zero storage/cookies');

    // 2. Click "Sign in with Keycloak SSO" -> Vite proxy /api/v1/auth/login -> Keycloak login page
    await cdp.evaluate(`document.querySelector('button.sf-button-primary')?.click()`);
    await waitFor(
      async () =>
        cdp !== null &&
        cdp.evaluate<boolean>(
          `window.location.href.startsWith(${JSON.stringify(authConfig.oidc.issuerUrl)}) && !!document.querySelector('input[name="username"]')`,
        ),
      'Keycloak login form',
    );
    const kcCookiesBefore = await cdp.send<{
      cookies: Array<{ name: string; domain: string; httpOnly: boolean }>;
    }>('Network.getCookies', { urls: [apiOrigin, webOrigin] });
    const txnCookie = kcCookiesBefore.cookies.find((c) => c.name === 'sf_oidc_txn');
    if (!txnCookie || !txnCookie.httpOnly || txnCookie.domain !== webUrl.hostname) {
      throw new Error(
        `Expected HttpOnly sf_oidc_txn on ${webUrl.hostname}, got: ${JSON.stringify(kcCookiesBefore.cookies)}`,
      );
    }
    console.log(
      `PASS 2: Top-level login navigated via Vite proxy to Keycloak with HttpOnly sf_oidc_txn on ${webUrl.hostname}`,
    );

    // 3. Submit Keycloak credentials -> BFF callback -> redirect back to /workspace
    await cdp.evaluate(`(() => {
      const u = document.querySelector('input[name="username"]');
      const p = document.querySelector('input[name="password"]');
      u.value = ${JSON.stringify(devUsername)};
      p.value = ${JSON.stringify(devPassword)};
      document.querySelector('form')?.submit();
    })()`);

    await waitFor(
      async () =>
        cdp !== null &&
        cdp.evaluate<boolean>(
          `window.location.href === ${JSON.stringify(`${webOrigin}/workspace`)} && document.body?.innerText?.includes('SecureFlow Authenticated Shell') && document.body?.innerText?.includes('DEVELOPER')`,
        ),
      `Authenticated workspace on ${webOrigin}/workspace`,
      20000,
    );

    const postLoginCookies = await cdp.send<{
      cookies: Array<{ name: string; httpOnly: boolean; sameSite?: string; path: string }>;
    }>('Network.getCookies', { urls: [webOrigin, apiOrigin] });
    const sessionCookie = postLoginCookies.cookies.find((c) => c.name === 'sf_session');
    const leftoverTxn = postLoginCookies.cookies.find((c) => c.name === 'sf_oidc_txn');
    if (
      !sessionCookie ||
      !sessionCookie.httpOnly ||
      sessionCookie.sameSite !== 'Lax' ||
      sessionCookie.path !== '/' ||
      leftoverTxn
    ) {
      throw new Error(
        `Invalid post-login cookie state: ${JSON.stringify(postLoginCookies.cookies)}`,
      );
    }
    const postLoginStorage = await cdp.evaluate<{
      local: number;
      session: number;
      cookie: string;
      csrfText: string;
      actorId: string;
    }>(
      `({ local: localStorage.length, session: sessionStorage.length, cookie: document.cookie, csrfText: document.querySelector('[data-testid="csrf-status"]')?.textContent ?? '', actorId: document.querySelector('[data-testid="actor-id"]')?.textContent ?? '' })`,
    );
    if (
      postLoginStorage.local !== 0 ||
      postLoginStorage.session !== 0 ||
      postLoginStorage.cookie !== '' ||
      postLoginStorage.csrfText !== 'Loaded in memory' ||
      !postLoginStorage.actorId
    ) {
      throw new Error(
        `Invalid post-login browser storage/CSRF state: ${JSON.stringify(postLoginStorage)}`,
      );
    }
    console.log(
      `PASS 3: Keycloak -> BFF callback -> ${webOrigin}/workspace authenticated, HttpOnly sf_session, CSRF in memory, zero storage leaks`,
    );

    // 4. Protected API GET via Vite proxy (GET /api/v1/projects?limit=1)
    await cdp.evaluate(
      `Array.from(document.querySelectorAll('button')).find(b => b.textContent?.includes('Verify Protected API'))?.click()`,
    );
    await waitFor(
      async () =>
        cdp !== null &&
        cdp.evaluate<boolean>(
          `document.body?.innerText?.includes('Protected API request succeeded with active BFF session cookie (HTTP 200)')`,
        ),
      'Protected API verification HTTP 200',
    );
    console.log('PASS 4: Protected GET API probe via Vite proxy returned HTTP 200');

    // 5. Ordinary authenticated API mutation in browser against a disposable authorized fixture
    disposableProjectId = randomUUID();
    db.registerSyntheticProject(disposableProjectId);
    const disposableFindingId = randomUUID();
    const disposableTaskId = randomUUID();
    const updatedNote = 'Phase 5A browser E2E verified PATCH with in-memory CSRF token';

    await db.query(
      `INSERT INTO public.projects (id, name, slug, description, created_by_id, updated_at)
       VALUES ($1, $2, $3, $4, $5, NOW());`,
      [
        disposableProjectId,
        'Phase 5A Disposable Smoke Project',
        `phase5a-smoke-${disposableProjectId.slice(0, 8)}`,
        'Disposable project created for browser CSRF mutation smoke verification',
        postLoginStorage.actorId,
      ],
    );
    await db.query(
      `INSERT INTO public.project_members (project_id, user_id, role, added_by_id, updated_at)
       VALUES ($1, $2, 'DEVELOPER', $2, NOW());`,
      [disposableProjectId, postLoginStorage.actorId],
    );
    await db.query(
      `INSERT INTO public.findings (id, project_id, title, description, severity, category, status, created_by_id, assigned_to_id, updated_at)
       VALUES ($1, $2, $3, $4, 'LOW', 'OTHER', 'IN_PROGRESS', $5, $5, NOW());`,
      [
        disposableFindingId,
        disposableProjectId,
        'Phase 5A Disposable Smoke Finding',
        'Disposable finding for browser CSRF mutation smoke verification',
        postLoginStorage.actorId,
      ],
    );
    await db.query(
      `INSERT INTO public.remediation_tasks (id, finding_id, assigned_to_id, assigned_by_id, description, status, updated_at)
       VALUES ($1, $2, $3, $3, $4, 'IN_PROGRESS', NOW());`,
      [
        disposableTaskId,
        disposableFindingId,
        postLoginStorage.actorId,
        'Disposable remediation task for Phase 5A browser mutation test',
      ],
    );

    const mutationCheck = await cdp.evaluate<{
      missingCsrfStatus: number;
      validCsrfStatus: number;
      persistedNotes: string | null;
    }>(`(async () => {
      const targetUrl = ${JSON.stringify(`/api/v1/tasks/${disposableTaskId}/notes`)};
      const noCsrfRes = await fetch(targetUrl, {
        method: 'PATCH',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ notes: 'blocked without csrf' }),
      });

      const meRes = await fetch('/api/v1/auth/me', {
        method: 'GET',
        credentials: 'same-origin',
        headers: { Accept: 'application/json' },
      });
      const meJson = await meRes.json();
      const csrfToken = meJson?.data?.csrfToken;

      const validRes = await fetch(targetUrl, {
        method: 'PATCH',
        credentials: 'same-origin',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
          'X-CSRF-Token': csrfToken,
        },
        body: JSON.stringify({ notes: ${JSON.stringify(updatedNote)} }),
      });
      const validJson = await validRes.json();
      return {
        missingCsrfStatus: noCsrfRes.status,
        validCsrfStatus: validRes.status,
        persistedNotes: validJson?.data?.notes ?? null,
      };
    })()`);

    if (
      mutationCheck.missingCsrfStatus !== 403 ||
      mutationCheck.validCsrfStatus !== 200 ||
      mutationCheck.persistedNotes !== updatedNote
    ) {
      throw new Error(
        `Unexpected browser mutation verification result: ${JSON.stringify(mutationCheck)}`,
      );
    }
    console.log(
      'PASS 5: Browser PATCH /api/v1/tasks/:id/notes rejected missing X-CSRF-Token (403) and succeeded with X-CSRF-Token (200)',
    );

    // 6. Real browser Page Reload -> session restoration via GET /api/v1/auth/me
    await cdp.send('Page.reload', { ignoreCache: false });
    await waitFor(
      async () =>
        cdp !== null &&
        cdp.evaluate<boolean>(
          `window.location.href === ${JSON.stringify(`${webOrigin}/workspace`)} && document.body?.innerText?.includes('SecureFlow Authenticated Shell') && document.querySelector('[data-testid="csrf-status"]')?.textContent === 'Loaded in memory'`,
        ),
      'Session restored after browser reload',
    );
    console.log('PASS 6: Browser reload restored session via /api/v1/auth/me and rehydrated CSRF');

    // 7. Logout -> X-CSRF-Token sent on POST /api/v1/auth/logout -> Keycloak SSO logout -> /login
    await cdp.evaluate(
      `Array.from(document.querySelectorAll('button')).find(b => b.textContent?.includes('Sign out'))?.click()`,
    );
    const logoutStage = await waitFor<'confirm' | 'landed'>(
      async () =>
        cdp === null
          ? null
          : cdp.evaluate<'confirm' | 'landed' | null>(`(() => {
              if (window.location.href.startsWith(${JSON.stringify(`${webOrigin}/login`)}) && document.body?.innerText?.includes('Sign in to SecureFlow')) {
                return 'landed';
              }
              if (window.location.href.startsWith(${JSON.stringify(authConfig.oidc.issuerUrl)}) && document.querySelector('#kc-logout, input[type="submit"], button[type="submit"]')) {
                return 'confirm';
              }
              return null;
            })()`),
      'Keycloak RP-initiated logout confirmation or direct return to /login',
    );

    const logoutReq = cdp.requests.find(
      (r) => r.url === `${webOrigin}/api/v1/auth/logout` && r.method === 'POST',
    );
    const csrfHeader = logoutReq
      ? (logoutReq.headers['X-CSRF-Token'] ?? logoutReq.headers['x-csrf-token'])
      : undefined;
    if (!logoutReq || !csrfHeader) {
      throw new Error(
        `Expected POST /api/v1/auth/logout with X-CSRF-Token, got: ${JSON.stringify(logoutReq)}`,
      );
    }

    if (logoutStage === 'confirm') {
      await cdp.evaluate(
        `document.querySelector('#kc-logout, input[type="submit"], button[type="submit"]')?.click()`,
      );
      await waitFor(
        async () =>
          cdp !== null &&
          cdp.evaluate<boolean>(
            `window.location.href.startsWith(${JSON.stringify(`${webOrigin}/login`)}) && document.body?.innerText?.includes('Sign in to SecureFlow')`,
          ),
        `Post-logout redirect back to ${webOrigin}/login`,
      );
    }

    const postLogoutCookies = await cdp.send<{ cookies: Array<{ name: string }> }>(
      'Network.getCookies',
      { urls: [webOrigin, apiOrigin, oidcIssuerOrigin] },
    );
    const activeSfSession = postLogoutCookies.cookies.find((c) => c.name === 'sf_session');
    const activeKcIdentity = postLogoutCookies.cookies.find((c) => c.name === 'KEYCLOAK_IDENTITY');
    if (activeSfSession || activeKcIdentity) {
      throw new Error(
        `Expected both sf_session and KEYCLOAK_IDENTITY cleared, got: ${JSON.stringify(postLogoutCookies.cookies)}`,
      );
    }
    console.log(
      `PASS 7: Logout sent X-CSRF-Token, cleared sf_session and KEYCLOAK_IDENTITY, and landed on ${webOrigin}/login`,
    );
  } finally {
    if (cdp) cdp.close();
    if (chromeProc && !chromeProc.killed) chromeProc.kill();
    await viteServer.close();
    await new Promise<void>((resolve) => apiServer.close(() => resolve()));
    await domainServices.close();

    if (disposableProjectId) {
      await db.cleanupProjectHierarchy(disposableProjectId);
    }
    await db.query('DELETE FROM public.audit_events WHERE id <> ALL($1::uuid[]);', [
      initialAuditIds,
    ]);
    await db.query('DELETE FROM public.user_sessions WHERE id <> ALL($1::uuid[]);', [
      initialSessionIds,
    ]);
    await db.query('DELETE FROM public.oidc_transactions WHERE id <> ALL($1::uuid[]);', [
      initialTxnIds,
    ]);
    await db.query('DELETE FROM public.users WHERE id <> ALL($1::uuid[]);', [initialUserIds]);

    const finalCounts = await readTableCounts(db);
    await db.close();
    fs.rmSync(tempProfileDir, { recursive: true, force: true });

    if (JSON.stringify(finalCounts) !== JSON.stringify(initialCounts)) {
      throw new Error(
        `PostgreSQL baseline counts changed! Initial=${JSON.stringify(initialCounts)}, Final=${JSON.stringify(finalCounts)}`,
      );
    }
    console.log('PASS 8: Exact PostgreSQL baseline fixture preservation verified after cleanup');
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
