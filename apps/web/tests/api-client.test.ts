import { describe, it, expect, vi } from 'vitest';
import { ApiClientError, createApiClient } from '../src/api/client.js';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

describe('Phase 5A Same-Origin API Client & In-Memory CSRF Management', () => {
  it('enforces credentials=same-origin, omits X-CSRF-Token on safe GET/HEAD, and attaches it on mutations', async () => {
    const fetchMock = vi.fn<typeof fetch>().mockImplementation(async () =>
      jsonResponse({ data: { ok: true } }),
    );
    const client = createApiClient(fetchMock);
    client.setCsrfToken('csrf_in_memory_secret_value_123');

    await client.get('/api/v1/projects');
    await client.request('/api/v1/projects', { method: 'HEAD' });
    await client.post('/api/v1/projects', { name: 'Alpha' });
    await client.patch('/api/v1/projects/1', { name: 'Beta' });
    await client.del('/api/v1/projects/1');

    expect(fetchMock).toHaveBeenCalledTimes(5);

    const getInit = fetchMock.mock.calls[0]?.[1];
    const getHeaders = new Headers(getInit?.headers);
    expect(getInit?.credentials).toBe('same-origin');
    expect(getHeaders.get('X-CSRF-Token')).toBeNull();

    const headInit = fetchMock.mock.calls[1]?.[1];
    const headHeaders = new Headers(headInit?.headers);
    expect(headInit?.credentials).toBe('same-origin');
    expect(headHeaders.get('X-CSRF-Token')).toBeNull();

    for (const idx of [2, 3, 4]) {
      const mutInit = fetchMock.mock.calls[idx]?.[1];
      const mutHeaders = new Headers(mutInit?.headers);
      expect(mutInit?.credentials).toBe('same-origin');
      expect(mutHeaders.get('X-CSRF-Token')).toBe('csrf_in_memory_secret_value_123');
    }

    client.clearCsrfToken();
    expect(client.hasCsrfToken()).toBe(false);
    await client.post('/api/v1/projects', { name: 'Gamma' });
    const postClearHeaders = new Headers(fetchMock.mock.calls[5]?.[1]?.headers);
    expect(postClearHeaders.get('X-CSRF-Token')).toBeNull();
  });

  it('invokes 401 and 403 listeners cleanly and raises typed ApiClientError on HTTP or network failures', async () => {
    const onUnauthorized = vi.fn();
    const onForbidden = vi.fn();
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        jsonResponse(
          { error: { code: 'UNAUTHORIZED', message: 'Session expired' } },
          401,
        ),
      )
      .mockResolvedValueOnce(
        jsonResponse(
          { error: { code: 'FORBIDDEN', message: 'Analyst role required' } },
          403,
        ),
      )
      .mockRejectedValueOnce(new TypeError('Failed to fetch'));

    const client = createApiClient(fetchMock);
    client.setAuthErrorListeners({ onUnauthorized, onForbidden });

    await expect(client.get('/api/v1/projects')).rejects.toMatchObject({
      status: 401,
      code: 'UNAUTHORIZED',
      kind: 'unauthorized',
      message: 'Session expired',
    });
    expect(onUnauthorized).toHaveBeenCalledTimes(1);

    await expect(client.post('/api/v1/projects', { name: 'X' })).rejects.toMatchObject({
      status: 403,
      code: 'FORBIDDEN',
      kind: 'forbidden',
      message: 'Analyst role required',
    });
    expect(onForbidden).toHaveBeenCalledTimes(1);

    await expect(client.get('/api/v1/projects')).rejects.toBeInstanceOf(ApiClientError);
    try {
      const offlineClient = createApiClient(
        vi.fn<typeof fetch>().mockRejectedValueOnce(new TypeError('Network unreachable')),
      );
      await offlineClient.get('/api/v1/auth/me');
    } catch (err) {
      expect(err).toBeInstanceOf(ApiClientError);
      expect((err as ApiClientError).kind).toBe('network');
      expect((err as ApiClientError).status).toBe(0);
      expect((err as ApiClientError).code).toBe('NETWORK_ERROR');
    }
  });
});
