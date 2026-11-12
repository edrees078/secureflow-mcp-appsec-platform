import express from 'express';
import request from 'supertest';
import { describe, it, expect } from 'vitest';
import { createCsrfMiddleware } from '../../src/middleware/csrf.js';
import { errorHandlerMiddleware } from '../../src/middleware/error-handler.js';

const ALLOWED_ORIGIN = 'https://app.secureflow.example';
const EXPECTED_CSRF_TOKEN = 'synth_csrf_bound_token_0123456789abcdef';

function createCsrfTestApp(sessionToken: string | null = EXPECTED_CSRF_TOKEN) {
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => {
    if (sessionToken !== null) {
      req.sessionCsrfToken = sessionToken;
    }
    next();
  });
  app.use(
    createCsrfMiddleware({
      allowedOrigins: [ALLOWED_ORIGIN],
    }),
  );

  app.get('/api/v1/resource', (_req, res) => {
    res.status(200).json({ ok: true });
  });
  app.post('/api/v1/resource', (_req, res) => {
    res.status(200).json({ mutated: true });
  });
  app.patch('/api/v1/resource', (_req, res) => {
    res.status(200).json({ patched: true });
  });
  app.delete('/api/v1/resource', (_req, res) => {
    res.status(200).json({ deleted: true });
  });

  app.use(errorHandlerMiddleware);
  return app;
}

describe('Gate 4B.2 CSRF Protection Middleware', () => {
  it('allows safe GET/HEAD methods and trusted OPTIONS preflight without CSRF token', async () => {
    const app = createCsrfTestApp();

    const getRes = await request(app).get('/api/v1/resource');
    expect(getRes.status).toBe(200);

    const headRes = await request(app).head('/api/v1/resource');
    expect(headRes.status).toBe(200);

    const optionsRes = await request(app)
      .options('/api/v1/resource')
      .set('Origin', ALLOWED_ORIGIN);
    expect(optionsRes.status).toBe(200);
  });

  it('rejects OPTIONS preflight from untrusted origins with HTTP 403', async () => {
    const app = createCsrfTestApp();

    const res = await request(app)
      .options('/api/v1/resource')
      .set('Origin', 'https://attacker.example');

    expect(res.status).toBe(403);
    expect(res.body.error.code).toBe('FORBIDDEN');
  });

  it('allows state-changing POST/PATCH/DELETE with trusted Origin, safe Sec-Fetch-Site, and valid CSRF token', async () => {
    const app = createCsrfTestApp();

    for (const method of ['post', 'patch', 'delete'] as const) {
      const res = await request(app)
        [method]('/api/v1/resource')
        .set('Origin', ALLOWED_ORIGIN)
        .set('Sec-Fetch-Site', 'same-origin')
        .set('X-CSRF-Token', EXPECTED_CSRF_TOKEN)
        .send({ action: 'test' });

      expect(res.status).toBe(200);
    }
  });

  it('supports safe Referer fallback when Origin is absent and rejects untrusted or absent Origin+Referer', async () => {
    const app = createCsrfTestApp();

    const validReferer = await request(app)
      .post('/api/v1/resource')
      .set('Referer', `${ALLOWED_ORIGIN}/findings/123`)
      .set('X-CSRF-Token', EXPECTED_CSRF_TOKEN);
    expect(validReferer.status).toBe(200);

    const untrustedReferer = await request(app)
      .post('/api/v1/resource')
      .set('Referer', 'https://attacker.example/exploit.html')
      .set('X-CSRF-Token', EXPECTED_CSRF_TOKEN);
    expect(untrustedReferer.status).toBe(403);
    expect(untrustedReferer.body.error.code).toBe('FORBIDDEN');

    const missingBoth = await request(app)
      .post('/api/v1/resource')
      .set('X-CSRF-Token', EXPECTED_CSRF_TOKEN);
    expect(missingBoth.status).toBe(403);
    expect(missingBoth.body.error.code).toBe('FORBIDDEN');
  });

  it('rejects missing, invalid, mismatched-length, or unbound anti-CSRF tokens with HTTP 403 (never relying on CORS/SameSite alone)', async () => {
    const app = createCsrfTestApp();

    // 1. Missing CSRF token despite valid Same-Origin header
    const missingToken = await request(app)
      .post('/api/v1/resource')
      .set('Origin', ALLOWED_ORIGIN)
      .set('Sec-Fetch-Site', 'same-origin');
    expect(missingToken.status).toBe(403);
    expect(missingToken.body.error.code).toBe('FORBIDDEN');

    // 2. Same-length mismatched token
    const tamperedSameLength = EXPECTED_CSRF_TOKEN.slice(0, -1) + '0';
    const wrongToken = await request(app)
      .post('/api/v1/resource')
      .set('Origin', ALLOWED_ORIGIN)
      .set('X-CSRF-Token', tamperedSameLength);
    expect(wrongToken.status).toBe(403);
    expect(JSON.stringify(wrongToken.body)).not.toContain(EXPECTED_CSRF_TOKEN);

    // 3. Different length token
    const shortToken = await request(app)
      .post('/api/v1/resource')
      .set('Origin', ALLOWED_ORIGIN)
      .set('X-CSRF-Token', 'short-token');
    expect(shortToken.status).toBe(403);

    // 4. Unbound session (missing req.sessionCsrfToken)
    const unboundApp = createCsrfTestApp(null);
    const unboundRes = await request(unboundApp)
      .post('/api/v1/resource')
      .set('Origin', ALLOWED_ORIGIN)
      .set('X-CSRF-Token', EXPECTED_CSRF_TOKEN);
    expect(unboundRes.status).toBe(403);
    expect(unboundRes.body.error.code).toBe('FORBIDDEN');
  });

  it('rejects cross-origin Origin, null Origin, and cross-site Fetch Metadata even when CSRF token matches', async () => {
    const app = createCsrfTestApp();

    const crossOrigin = await request(app)
      .post('/api/v1/resource')
      .set('Origin', 'https://evil-subdomain.secureflow.example')
      .set('X-CSRF-Token', EXPECTED_CSRF_TOKEN);
    expect(crossOrigin.status).toBe(403);

    const nullOrigin = await request(app)
      .post('/api/v1/resource')
      .set('Origin', 'null')
      .set('X-CSRF-Token', EXPECTED_CSRF_TOKEN);
    expect(nullOrigin.status).toBe(403);

    const crossSiteFetchMeta = await request(app)
      .post('/api/v1/resource')
      .set('Origin', ALLOWED_ORIGIN)
      .set('Sec-Fetch-Site', 'cross-site')
      .set('X-CSRF-Token', EXPECTED_CSRF_TOKEN);
    expect(crossSiteFetchMeta.status).toBe(403);
    expect(crossSiteFetchMeta.body.error.code).toBe('FORBIDDEN');

    const unexpectedFetchMeta = await request(app)
      .post('/api/v1/resource')
      .set('Origin', ALLOWED_ORIGIN)
      .set('Sec-Fetch-Site', 'none')
      .set('X-CSRF-Token', EXPECTED_CSRF_TOKEN);
    expect(unexpectedFetchMeta.status).toBe(403);
  });

  it('rejects contradictory Origin, Referer, and Sec-Fetch-Site security headers', async () => {
    const app = createCsrfTestApp();

    // 1. Untrusted attacker Origin pretending to be same-origin via Sec-Fetch-Site
    const spoofedFetchSite = await request(app)
      .post('/api/v1/resource')
      .set('Origin', 'https://attacker.example')
      .set('Sec-Fetch-Site', 'same-origin')
      .set('X-CSRF-Token', EXPECTED_CSRF_TOKEN);
    expect(spoofedFetchSite.status).toBe(403);
    expect(spoofedFetchSite.body.error.code).toBe('FORBIDDEN');

    // 2. Allowed Referer but cross-site Sec-Fetch-Site metadata
    const crossSiteReferer = await request(app)
      .post('/api/v1/resource')
      .set('Referer', `${ALLOWED_ORIGIN}/findings`)
      .set('Sec-Fetch-Site', 'cross-site')
      .set('X-CSRF-Token', EXPECTED_CSRF_TOKEN);
    expect(crossSiteReferer.status).toBe(403);
    expect(crossSiteReferer.body.error.code).toBe('FORBIDDEN');
  });

  it('rejects duplicate browser security and anti-CSRF headers fail-closed', async () => {
    const app = createCsrfTestApp();

    // 1. Duplicate Origin
    const dupOrigin = await request(app)
      .post('/api/v1/resource')
      .set('Origin', [ALLOWED_ORIGIN, 'https://attacker.example'] as unknown as string)
      .set('X-CSRF-Token', EXPECTED_CSRF_TOKEN);
    expect(dupOrigin.status).toBe(403);

    // 2. Duplicate Referer
    const dupReferer = await request(app)
      .post('/api/v1/resource')
      .set('Referer', [`${ALLOWED_ORIGIN}/a`, `${ALLOWED_ORIGIN}/b`] as unknown as string)
      .set('X-CSRF-Token', EXPECTED_CSRF_TOKEN);
    expect(dupReferer.status).toBe(403);

    // 3. Duplicate Sec-Fetch-Site
    const dupFetchSite = await request(app)
      .post('/api/v1/resource')
      .set('Origin', ALLOWED_ORIGIN)
      .set('Sec-Fetch-Site', ['same-origin', 'cross-site'] as unknown as string)
      .set('X-CSRF-Token', EXPECTED_CSRF_TOKEN);
    expect(dupFetchSite.status).toBe(403);

    // 4. Duplicate X-CSRF-Token
    const dupToken = await request(app)
      .post('/api/v1/resource')
      .set('Origin', ALLOWED_ORIGIN)
      .set('X-CSRF-Token', [EXPECTED_CSRF_TOKEN, EXPECTED_CSRF_TOKEN] as unknown as string);
    expect(dupToken.status).toBe(403);
  });
});
