import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { createApiClient, type SessionIdentitySnapshot } from '../src/api/client.js';
import { AuthProvider, useAuth } from '../src/auth/AuthContext.js';
import { ProtectedRoute } from '../src/auth/ProtectedRoute.js';
import { buildBffLoginUrl, sanitizeReturnToPath, type BrowserNavigator } from '../src/auth/navigation.js';
import { AppRoutes } from '../src/App.js';
import { WorkspacePage } from '../src/pages/WorkspacePage.js';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function createSessionFixture(
  overrides?: Partial<SessionIdentitySnapshot>,
): SessionIdentitySnapshot {
  return {
    actor: {
      id: '33333333-3333-4333-8333-333333333333',
      globalRole: 'DEVELOPER',
      isActive: true,
    },
    sessionId: '22222222-2222-4222-8222-222222222222',
    csrfToken: 'csrf_secret_bound_token_9876543210',
    ...overrides,
  };
}

function createNavigatorMock(
  origin = 'http://127.0.0.1:5173',
  pathAndSearch = '/',
): BrowserNavigator & { assign: ReturnType<typeof vi.fn<(url: string) => void>> } {
  return {
    assign: vi.fn<(url: string) => void>(),
    getOrigin: () => origin,
    getPathAndSearch: () => pathAndSearch,
  };
}

describe('Phase 5A React BFF Authentication Integration', () => {
  beforeEach(() => {
    window.localStorage.clear();
    window.sessionStorage.clear();
  });

  it('1. Anonymous initial loading shows checking state and redirects unauthenticated user to /login', async () => {
    let resolveMe: ((value: Response) => void) | undefined;
    const fetchMock = vi.fn<typeof fetch>().mockImplementation(
      () =>
        new Promise<Response>((resolve) => {
          resolveMe = resolve;
        }),
    );
    const apiClient = createApiClient(fetchMock);
    const navigator = createNavigatorMock('http://127.0.0.1:5173', '/workspace');

    render(
      <MemoryRouter initialEntries={['/workspace']}>
        <AuthProvider apiClient={apiClient} navigator={navigator}>
          <AppRoutes />
        </AuthProvider>
      </MemoryRouter>,
    );

    expect(screen.getByRole('status')).toHaveTextContent(/Restoring your server-managed authentication state/i);

    resolveMe?.(
      jsonResponse({ error: { code: 'UNAUTHORIZED', message: 'Authentication required' } }, 401),
    );

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: /Sign in to SecureFlow/i })).toBeInTheDocument();
    });
    expect(screen.getByRole('button', { name: /Sign in with Keycloak SSO/i })).toBeInTheDocument();
    expect(apiClient.hasCsrfToken()).toBe(false);
  });

  it('2. Authenticated session restoration populates user identity, loads in-memory CSRF token, and leaks zero credentials to storage or DOM', async () => {
    const localSetSpy = vi.spyOn(Storage.prototype, 'setItem');
    const sessionFixture = createSessionFixture();
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValueOnce(
      jsonResponse({ data: sessionFixture }, 200),
    );
    const apiClient = createApiClient(fetchMock);
    const navigator = createNavigatorMock();

    const { container } = render(
      <MemoryRouter initialEntries={['/']}>
        <AuthProvider apiClient={apiClient} navigator={navigator}>
          <AppRoutes />
        </AuthProvider>
      </MemoryRouter>,
    );

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: /SecureFlow Authenticated Shell/i })).toBeInTheDocument();
    });

    expect(screen.getByTestId('actor-id')).toHaveTextContent(sessionFixture.actor.id);
    expect(screen.getByTestId('actor-role')).toHaveTextContent('DEVELOPER');
    expect(screen.getByTestId('session-id')).toHaveTextContent(sessionFixture.sessionId);
    expect(screen.getByTestId('csrf-status')).toHaveTextContent('Loaded in memory');
    expect(apiClient.hasCsrfToken()).toBe(true);

    // Credentials never touch localStorage, sessionStorage, cookies, or rendered DOM
    expect(localSetSpy).not.toHaveBeenCalled();
    expect(window.localStorage.length).toBe(0);
    expect(window.sessionStorage.length).toBe(0);
    expect(document.cookie).toBe('');
    expect(container.innerHTML).not.toContain(sessionFixture.csrfToken);

    localSetSpy.mockRestore();
  });

  it('3. Successful login triggers top-level browser navigation to /api/v1/auth/login with safe returnTo and redirects /login when authenticated', async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        jsonResponse({ error: { code: 'UNAUTHORIZED', message: 'Anonymous' } }, 401),
      );
    const apiClient = createApiClient(fetchMock);
    const navigator = createNavigatorMock('http://127.0.0.1:5173', '/workspace?tab=auth');

    const user = userEvent.setup();
    render(
      <MemoryRouter initialEntries={['/workspace?tab=auth']}>
        <AuthProvider apiClient={apiClient} navigator={navigator}>
          <AppRoutes />
        </AuthProvider>
      </MemoryRouter>,
    );

    const signInButton = await screen.findByRole('button', { name: /Sign in with Keycloak SSO/i });
    await user.click(signInButton);

    expect(fetchMock).toHaveBeenCalledTimes(1); // Only GET /api/v1/auth/me used fetch
    expect(navigator.assign).toHaveBeenCalledWith(
      '/api/v1/auth/login?returnTo=%2Fworkspace%3Ftab%3Dauth',
    );

    // Sanitizer rejects open redirects
    expect(sanitizeReturnToPath('https://evil.example/phish')).toBe('/');
    expect(sanitizeReturnToPath('//evil.example')).toBe('/');
    expect(sanitizeReturnToPath('/\\evil.example')).toBe('/');
    expect(sanitizeReturnToPath('/login')).toBe('/');

    // When already authenticated at /login?returnTo=/workspace, router redirects to /workspace
    const authFetch = vi.fn<typeof fetch>().mockResolvedValueOnce(
      jsonResponse({ data: createSessionFixture() }, 200),
    );
    const authClient = createApiClient(authFetch);
    render(
      <MemoryRouter initialEntries={['/login?returnTo=%2Fworkspace']}>
        <AuthProvider apiClient={authClient} navigator={createNavigatorMock()}>
          <AppRoutes />
        </AuthProvider>
      </MemoryRouter>,
    );

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: /SecureFlow Authenticated Shell/i })).toBeInTheDocument();
    });
  });

  it('4. Expired session handling: HTTP 401 from protected endpoint clears CSRF state and returns to /login', async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse({ data: createSessionFixture() }, 200))
      .mockResolvedValueOnce(
        jsonResponse({ error: { code: 'UNAUTHORIZED', message: 'Session expired' } }, 401),
      );
    const apiClient = createApiClient(fetchMock);
    const navigator = createNavigatorMock();
    const user = userEvent.setup();

    render(
      <MemoryRouter initialEntries={['/']}>
        <AuthProvider apiClient={apiClient} navigator={navigator}>
          <AppRoutes />
        </AuthProvider>
      </MemoryRouter>,
    );

    const probeButton = await screen.findByRole('button', { name: /Verify Protected API/i });
    expect(apiClient.hasCsrfToken()).toBe(true);

    await user.click(probeButton);

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: /Sign in to SecureFlow/i })).toBeInTheDocument();
    });
    expect(screen.getByRole('status')).toHaveTextContent(/no longer valid or has expired/i);
    expect(apiClient.hasCsrfToken()).toBe(false);
  });

  it('5. Forbidden (HTTP 403) handling renders clear Access Denied state on deactivated /me, denied API response, and role mismatch', async () => {
    // A. /me returns 403 (deactivated user)
    const deactivatedFetch = vi.fn<typeof fetch>().mockResolvedValueOnce(
      jsonResponse({ error: { code: 'FORBIDDEN', message: 'User account is deactivated' } }, 403),
    );
    const deactivatedClient = createApiClient(deactivatedFetch);

    const { unmount } = render(
      <MemoryRouter initialEntries={['/']}>
        <AuthProvider apiClient={deactivatedClient} navigator={createNavigatorMock()}>
          <AppRoutes />
        </AuthProvider>
      </MemoryRouter>,
    );

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: /Access denied/i })).toBeInTheDocument();
    });
    expect(screen.getByText(/User account is deactivated/i)).toBeInTheDocument();
    expect(deactivatedClient.hasCsrfToken()).toBe(false);
    unmount();

    // B. Protected endpoint returns 403 while session remains active
    const api403Fetch = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse({ data: createSessionFixture() }, 200))
      .mockResolvedValueOnce(
        jsonResponse({ error: { code: 'FORBIDDEN', message: 'Insufficient project permissions' } }, 403),
      );
    const api403Client = createApiClient(api403Fetch);
    const user = userEvent.setup();

    const { unmount: unmountApi403 } = render(
      <MemoryRouter initialEntries={['/']}>
        <AuthProvider apiClient={api403Client} navigator={createNavigatorMock()}>
          <AppRoutes />
        </AuthProvider>
      </MemoryRouter>,
    );

    const probeBtn = await screen.findByRole('button', { name: /Verify Protected API/i });
    await user.click(probeBtn);

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: /Access denied/i })).toBeInTheDocument();
    });
    expect(screen.getByText(/Insufficient project permissions/i)).toBeInTheDocument();
    unmountApi403();

    // C. UI route role guard shows Access Denied without crashing
    const roleFetch = vi.fn<typeof fetch>().mockResolvedValueOnce(
      jsonResponse({ data: createSessionFixture() }, 200),
    );
    render(
      <MemoryRouter initialEntries={['/admin-only']}>
        <AuthProvider apiClient={createApiClient(roleFetch)} navigator={createNavigatorMock()}>
          <Routes>
            <Route element={<ProtectedRoute allowedRoles={['ADMIN']} />}>
              <Route path="/admin-only" element={<WorkspacePage />} />
            </Route>
          </Routes>
        </AuthProvider>
      </MemoryRouter>,
    );

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: /Access denied/i })).toBeInTheDocument();
    });
    expect(screen.getByText(/Role 'DEVELOPER' is not permitted on this view/i)).toBeInTheDocument();
  });

  it('6. Logout attaches X-CSRF-Token, clears in-memory auth state, and navigates to Keycloak endSessionUrl when supplied', async () => {
    const sessionFixture = createSessionFixture();
    const endSessionUrl =
      'http://127.0.0.1:8080/realms/secureflow/protocol/openid-connect/logout?client_id=secureflow-bff&post_logout_redirect_uri=http%3A%2F%2F127.0.0.1%3A5173%2Flogin';

    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse({ data: sessionFixture }, 200))
      .mockResolvedValueOnce(
        jsonResponse({ data: { loggedOut: true, endSessionUrl } }, 200),
      );

    const apiClient = createApiClient(fetchMock);
    const navigator = createNavigatorMock('http://127.0.0.1:5173', '/');
    const user = userEvent.setup();

    render(
      <MemoryRouter initialEntries={['/']}>
        <AuthProvider apiClient={apiClient} navigator={navigator}>
          <AppRoutes />
        </AuthProvider>
      </MemoryRouter>,
    );

    const logoutButton = await screen.findByRole('button', { name: /Sign out/i });
    await user.click(logoutButton);

    await waitFor(() => {
      expect(navigator.assign).toHaveBeenCalledWith(endSessionUrl);
    });

    const logoutCall = fetchMock.mock.calls[1];
    expect(logoutCall?.[0]).toBe('/api/v1/auth/logout');
    const logoutInit = logoutCall?.[1];
    expect(logoutInit?.method).toBe('POST');
    expect(logoutInit?.credentials).toBe('same-origin');
    expect(new Headers(logoutInit?.headers).get('X-CSRF-Token')).toBe(sessionFixture.csrfToken);
    expect(logoutInit?.body).toBe(
      JSON.stringify({ postLogoutRedirectUri: 'http://127.0.0.1:5173/login' }),
    );
    expect(apiClient.hasCsrfToken()).toBe(false);
  });

  it('7. Logout when IdP is unavailable (endSessionUrl: null) clears local auth state and stays at /login with clear notice', async () => {
    const sessionFixture = createSessionFixture();
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse({ data: sessionFixture }, 200))
      .mockResolvedValueOnce(
        jsonResponse({ data: { loggedOut: true, endSessionUrl: null } }, 200),
      );

    const apiClient = createApiClient(fetchMock);
    const navigator = createNavigatorMock('http://127.0.0.1:5173', '/');
    const user = userEvent.setup();

    render(
      <MemoryRouter initialEntries={['/']}>
        <AuthProvider apiClient={apiClient} navigator={navigator}>
          <AppRoutes />
        </AuthProvider>
      </MemoryRouter>,
    );

    const logoutButton = await screen.findByRole('button', { name: /Sign out/i });
    await user.click(logoutButton);

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: /Sign in to SecureFlow/i })).toBeInTheDocument();
    });

    expect(navigator.assign).not.toHaveBeenCalled();
    expect(apiClient.hasCsrfToken()).toBe(false);
    expect(screen.getByRole('status')).toHaveTextContent(
      /Signed out of SecureFlow locally\. The identity provider logout endpoint was unavailable/i,
    );
  });

  it('8. Page refresh & navigation: fresh mount restores session cleanly via /api/v1/auth/me and surfaces Retry UI on network outage', async () => {
    // First "page load" restores session
    const fetchPage1 = vi.fn<typeof fetch>().mockResolvedValueOnce(
      jsonResponse({ data: createSessionFixture() }, 200),
    );
    const clientPage1 = createApiClient(fetchPage1);

    const firstMount = render(
      <MemoryRouter initialEntries={['/workspace']}>
        <AuthProvider apiClient={clientPage1} navigator={createNavigatorMock()}>
          <AppRoutes />
        </AuthProvider>
      </MemoryRouter>,
    );

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: /SecureFlow Authenticated Shell/i })).toBeInTheDocument();
    });
    firstMount.unmount();

    // Simulated full browser page refresh creates brand-new in-memory AuthProvider & ApiClient
    const refreshedFixture = createSessionFixture({ csrfToken: 'fresh_rotated_csrf_token_after_reload' });
    const fetchPage2 = vi
      .fn<typeof fetch>()
      .mockRejectedValueOnce(new TypeError('Temporary connection refused'))
      .mockResolvedValueOnce(jsonResponse({ data: refreshedFixture }, 200));
    const clientPage2 = createApiClient(fetchPage2);
    const user = userEvent.setup();

    render(
      <MemoryRouter initialEntries={['/workspace']}>
        <AuthProvider apiClient={clientPage2} navigator={createNavigatorMock()}>
          <AppRoutes />
        </AuthProvider>
      </MemoryRouter>,
    );

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: /Unable to reach SecureFlow API/i })).toBeInTheDocument();
    });
    expect(clientPage2.hasCsrfToken()).toBe(false);

    await user.click(screen.getByRole('button', { name: /Retry session check/i }));

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: /SecureFlow Authenticated Shell/i })).toBeInTheDocument();
    });
    expect(clientPage2.hasCsrfToken()).toBe(true);
    expect(window.localStorage.length).toBe(0);
    expect(window.sessionStorage.length).toBe(0);
  });

  it('9. Rejects protocol-relative, external, encoded URL, and backslash returnTo redirect bypass attempts', () => {
    const maliciousTargets = [
      'https://evil.example/phish',
      'http://evil.example/login',
      'javascript:alert(1)',
      '//evil.example/path',
      '///evil.example/path',
      '/\\evil.example',
      '\\\\evil.example\\share',
      '/workspace\\evil',
      '/%2f/evil.example',
      '/%2Fevil.example',
      '/%252f/evil.example',
      '/%5cevil.example',
      '/%255cevil.example',
      '%2f%2fevil.example',
      '/%0d%0aSet-Cookie:a=b',
      '/workspace\t?x=1',
      '/%ZZ',
      '/login?next=https://evil.example',
    ];

    for (const target of maliciousTargets) {
      expect(sanitizeReturnToPath(target)).toBe('/');
      expect(buildBffLoginUrl(target)).toBe('/api/v1/auth/login?returnTo=%2F');
    }

    // Legitimate internal routes remain intact
    expect(sanitizeReturnToPath('/workspace?tab=overview')).toBe('/workspace?tab=overview');
    expect(sanitizeReturnToPath('/projects/123/findings')).toBe('/projects/123/findings');
  });

  it('10. Discards delayed /me resolution after logout so stale auth or CSRF state is never resurrected', async () => {
    const sessionFixture = createSessionFixture();
    let resolveDelayedMe: ((res: Response) => void) | undefined;
    const delayedMePromise = new Promise<Response>((resolve) => {
      resolveDelayedMe = resolve;
    });

    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse({ data: sessionFixture }, 200)) // initial restore
      .mockImplementationOnce(() => delayedMePromise) // delayed manual refresh /me
      .mockResolvedValueOnce(jsonResponse({ data: { loggedOut: true, endSessionUrl: null } }, 200)); // POST logout

    const apiClient = createApiClient(fetchMock);
    const navigator = createNavigatorMock('http://127.0.0.1:5173', '/workspace');
    const user = userEvent.setup();

    render(
      <MemoryRouter initialEntries={['/workspace']}>
        <AuthProvider apiClient={apiClient} navigator={navigator}>
          <AppRoutes />
        </AuthProvider>
      </MemoryRouter>,
    );

    const refreshBtn = await screen.findByRole('button', { name: /Revalidate Session/i });
    await user.click(refreshBtn);

    // Trigger logout while delayed /me request is still in-flight
    const signOutBtn = screen.getByRole('button', { name: /Sign out/i });
    await user.click(signOutBtn);

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: /Sign in to SecureFlow/i })).toBeInTheDocument();
    });
    expect(apiClient.hasCsrfToken()).toBe(false);

    // Delayed /me finally arrives with stale session snapshot -> must be ignored
    resolveDelayedMe?.(jsonResponse({ data: sessionFixture }, 200));
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: /Sign in to SecureFlow/i })).toBeInTheDocument();
    });
    expect(apiClient.hasCsrfToken()).toBe(false);
    expect(screen.queryByRole('heading', { name: /SecureFlow Authenticated Shell/i })).not.toBeInTheDocument();
  });

  it('11. Handles HTTP 500 and invalid JSON /me restoration failures without leaking auth or CSRF state', async () => {
    const http500Fetch = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse({ error: { code: 'INTERNAL_ERROR', message: 'BFF unavailable' } }, 500))
      .mockResolvedValueOnce(new Response('not-json-gateway-error', { status: 502 }))
      .mockResolvedValueOnce(jsonResponse({ data: { actor: null } }, 200));

    const apiClient = createApiClient(http500Fetch);
    const user = userEvent.setup();

    render(
      <MemoryRouter initialEntries={['/workspace']}>
        <AuthProvider apiClient={apiClient} navigator={createNavigatorMock()}>
          <AppRoutes />
        </AuthProvider>
      </MemoryRouter>,
    );

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: /Unable to reach SecureFlow API/i })).toBeInTheDocument();
    });
    expect(screen.getByText(/BFF unavailable/i)).toBeInTheDocument();
    expect(apiClient.hasCsrfToken()).toBe(false);

    // Second failure: non-JSON 502
    await user.click(screen.getByRole('button', { name: /Retry session check/i }));
    await waitFor(() => {
      expect(screen.getByText(/Request failed with HTTP 502/i)).toBeInTheDocument();
    });
    expect(apiClient.hasCsrfToken()).toBe(false);

    // Third failure: malformed 200 /me schema
    await user.click(screen.getByRole('button', { name: /Retry session check/i }));
    await waitFor(() => {
      expect(screen.getByText(/Unexpected \/api\/v1\/auth\/me payload structure/i)).toBeInTheDocument();
    });
    expect(apiClient.hasCsrfToken()).toBe(false);
  });

  it('12. Attaches X-CSRF-Token to ordinary authenticated API mutations and clears stale CSRF token after 401 expiry', async () => {
    const sessionFixture = createSessionFixture();
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse({ data: sessionFixture }, 200))
      .mockResolvedValueOnce(jsonResponse({ data: { id: 'task-1', notes: 'Patched dependency' } }, 200))
      .mockResolvedValueOnce(jsonResponse({ error: { code: 'UNAUTHORIZED', message: 'Session revoked' } }, 401))
      .mockResolvedValueOnce(jsonResponse({ error: { code: 'FORBIDDEN', message: 'Missing CSRF' } }, 403));

    const client = createApiClient(fetchMock);
    const user = userEvent.setup();

    function MutationHarness() {
      const { apiClient: ctxClient } = useAuth();
      return (
        <button
          type="button"
          onClick={() => {
            void ctxClient.patch('/api/v1/tasks/task-1/notes', { notes: 'Patched dependency' }).catch(() => undefined);
          }}
        >
          Submit Task Note
        </button>
      );
    }

    render(
      <MemoryRouter initialEntries={['/']}>
        <AuthProvider apiClient={client} navigator={createNavigatorMock()}>
          <Routes>
            <Route path="/login" element={<div>Login View</div>} />
            <Route element={<ProtectedRoute />}>
              <Route path="/" element={<MutationHarness />} />
            </Route>
          </Routes>
        </AuthProvider>
      </MemoryRouter>,
    );

    const mutateBtn = await screen.findByRole('button', { name: /Submit Task Note/i });
    await waitFor(() => expect(client.hasCsrfToken()).toBe(true));

    // Ordinary authenticated PATCH mutation sends same-origin cookie + X-CSRF-Token
    await user.click(mutateBtn);
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));
    const patchInit = fetchMock.mock.calls[1]?.[1];
    expect(patchInit?.method).toBe('PATCH');
    expect(patchInit?.credentials).toBe('same-origin');
    expect(new Headers(patchInit?.headers).get('X-CSRF-Token')).toBe(sessionFixture.csrfToken);

    // Next call fails with 401 -> clears stale CSRF state immediately
    await user.click(mutateBtn);
    await waitFor(() => {
      expect(screen.getByText('Login View')).toBeInTheDocument();
    });
    expect(client.hasCsrfToken()).toBe(false);

    // Any subsequent mutation attempt using the client does NOT send stale X-CSRF-Token
    await expect(client.post('/api/v1/projects', { name: 'AfterExpiry' })).rejects.toMatchObject({
      status: 403,
    });
    const postExpiryHeaders = new Headers(fetchMock.mock.calls[3]?.[1]?.headers);
    expect(postExpiryHeaders.get('X-CSRF-Token')).toBeNull();
  });
});
