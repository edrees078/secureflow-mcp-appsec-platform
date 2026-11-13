import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react';
import {
  apiClient as defaultApiClient,
  ApiClientError,
  type ApiClient,
  type AuthActorProfile,
} from '../api/client.js';
import {
  buildBffLoginUrl,
  buildPostLogoutRedirectUri,
  windowBrowserNavigator,
  type BrowserNavigator,
} from './navigation.js';

export type AuthStatus =
  | 'loading'
  | 'authenticated'
  | 'unauthenticated'
  | 'access_denied'
  | 'error';

export type AuthNoticeKind =
  | 'anonymous'
  | 'session_expired'
  | 'logged_out'
  | 'logged_out_idp_unavailable'
  | 'access_denied'
  | 'network_error';

export interface AuthNotice {
  readonly kind: AuthNoticeKind;
  readonly message: string;
}

export interface AuthContextValue {
  readonly status: AuthStatus;
  readonly user: AuthActorProfile | null;
  readonly sessionId: string | null;
  readonly hasCsrfToken: boolean;
  readonly authNotice: AuthNotice | null;
  readonly isLoggingOut: boolean;
  readonly apiClient: ApiClient;
  login(returnTo?: string): void;
  logout(): Promise<void>;
  refreshSession(): Promise<void>;
  clearAuthNotice(): void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export interface AuthProviderProps {
  readonly children: ReactNode;
  readonly apiClient?: ApiClient | undefined;
  readonly navigator?: BrowserNavigator | undefined;
}

/**
 * Provides server-managed BFF session state strictly in React memory.
 *
 * Security invariants:
 * - Never acquires, stores, or parses OAuth access/refresh/ID tokens in browser JS.
 * - Never persists session or CSRF secrets to localStorage/sessionStorage/cookies.
 * - Session identity is always restored and revalidated via `GET /api/v1/auth/me`.
 */
export function AuthProvider({
  children,
  apiClient = defaultApiClient,
  navigator = windowBrowserNavigator,
}: AuthProviderProps) {
  const [status, setStatus] = useState<AuthStatus>('loading');
  const [user, setUser] = useState<AuthActorProfile | null>(null);
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [hasCsrfToken, setHasCsrfToken] = useState(false);
  const [authNotice, setAuthNotice] = useState<AuthNotice | null>(null);
  const [isLoggingOut, setIsLoggingOut] = useState(false);

  const statusRef = useRef<AuthStatus>(status);
  statusRef.current = status;

  const isLoggingOutRef = useRef(isLoggingOut);
  isLoggingOutRef.current = isLoggingOut;

  // Monotonically incremented whenever auth resets or a new /me/logout cycle starts so
  // delayed out-of-order /me responses can never resurrect state after logout or expiry.
  const authEpochRef = useRef(0);

  const clearInMemoryAuth = useCallback(
    (nextStatus: 'unauthenticated' | 'access_denied' | 'error', notice: AuthNotice | null) => {
      authEpochRef.current += 1;
      apiClient.clearCsrfToken();
      setHasCsrfToken(false);
      setUser(null);
      setSessionId(null);
      setAuthNotice(notice);
      setStatus(nextStatus);
    },
    [apiClient],
  );

  const applySessionSnapshot = useCallback(
    (snapshot: { readonly actor: AuthActorProfile; readonly sessionId: string; readonly csrfToken: string }) => {
      apiClient.setCsrfToken(snapshot.csrfToken);
      setHasCsrfToken(apiClient.hasCsrfToken());
      setUser(snapshot.actor);
      setSessionId(snapshot.sessionId);
      setAuthNotice(null);
      setStatus('authenticated');
    },
    [apiClient],
  );

  const applyAuthFailure = useCallback(
    (err: unknown, mode: 'initial' | 'refresh') => {
      if (err instanceof ApiClientError) {
        if (err.status === 401) {
          const wasAuthenticated = mode === 'refresh' && statusRef.current === 'authenticated';
          clearInMemoryAuth(
            'unauthenticated',
            wasAuthenticated
              ? {
                  kind: 'session_expired',
                  message: 'Your session has expired. Please sign in again.',
                }
              : {
                  kind: 'anonymous',
                  message: 'Sign in with your Keycloak account to access SecureFlow.',
                },
          );
          return;
        }
        if (err.status === 403) {
          clearInMemoryAuth('access_denied', {
            kind: 'access_denied',
            message: err.message || 'Access denied for this account.',
          });
          return;
        }
        clearInMemoryAuth('error', {
          kind: 'network_error',
          message:
            err.message ||
            (mode === 'initial'
              ? 'Unable to reach SecureFlow API to verify session.'
              : 'Unable to verify session with the SecureFlow server.'),
        });
        return;
      }

      clearInMemoryAuth('error', {
        kind: 'network_error',
        message:
          mode === 'initial'
            ? 'Unexpected error while restoring session.'
            : 'Unexpected error while checking authentication status.',
      });
    },
    [clearInMemoryAuth],
  );

  const refreshSession = useCallback(async (): Promise<void> => {
    if (isLoggingOutRef.current) {
      return;
    }

    const requestEpoch = ++authEpochRef.current;
    setStatus((prev) => (prev === 'authenticated' ? prev : 'loading'));
    try {
      const snapshot = await apiClient.getMe({ suppressAuthErrorEvents: true });
      if (requestEpoch !== authEpochRef.current || isLoggingOutRef.current) {
        return;
      }
      applySessionSnapshot(snapshot);
    } catch (err) {
      if (requestEpoch !== authEpochRef.current || isLoggingOutRef.current) {
        return;
      }
      applyAuthFailure(err, 'refresh');
    }
  }, [apiClient, applyAuthFailure, applySessionSnapshot]);

  useEffect(() => {
    apiClient.setAuthErrorListeners({
      onUnauthorized: () => {
        if (isLoggingOutRef.current) {
          return;
        }
        clearInMemoryAuth('unauthenticated', {
          kind: 'session_expired',
          message: 'Your session is no longer valid or has expired. Please sign in again.',
        });
      },
      onForbidden: (error) => {
        if (statusRef.current !== 'authenticated') {
          return;
        }
        setAuthNotice({
          kind: 'access_denied',
          message: error.message || 'You do not have permission to perform that operation.',
        });
      },
    });

    return () => {
      apiClient.setAuthErrorListeners({});
    };
  }, [apiClient, clearInMemoryAuth]);

  useEffect(() => {
    let cancelled = false;
    const requestEpoch = ++authEpochRef.current;

    const restore = async (): Promise<void> => {
      try {
        const snapshot = await apiClient.getMe({ suppressAuthErrorEvents: true });
        if (cancelled || requestEpoch !== authEpochRef.current || isLoggingOutRef.current) {
          return;
        }
        applySessionSnapshot(snapshot);
      } catch (err) {
        if (cancelled || requestEpoch !== authEpochRef.current || isLoggingOutRef.current) {
          return;
        }
        applyAuthFailure(err, 'initial');
      }
    };

    void restore();

    return () => {
      cancelled = true;
    };
  }, [apiClient, applyAuthFailure, applySessionSnapshot]);

  const login = useCallback(
    (returnTo?: string): void => {
      const targetReturnTo = returnTo ?? navigator.getPathAndSearch();
      navigator.assign(buildBffLoginUrl(targetReturnTo));
    },
    [navigator],
  );

  const logout = useCallback(async (): Promise<void> => {
    if (isLoggingOutRef.current) {
      return;
    }

    isLoggingOutRef.current = true;
    authEpochRef.current += 1;
    setIsLoggingOut(true);
    try {
      const result = await apiClient.logout(buildPostLogoutRedirectUri(navigator.getOrigin()));

      if (result.endSessionUrl) {
        clearInMemoryAuth('unauthenticated', {
          kind: 'logged_out',
          message: 'Signed out of SecureFlow. Redirecting to identity provider logout...',
        });
        navigator.assign(result.endSessionUrl);
        return;
      }

      clearInMemoryAuth('unauthenticated', {
        kind: 'logged_out_idp_unavailable',
        message:
          'Signed out of SecureFlow locally. The identity provider logout endpoint was unavailable.',
      });
    } catch (err) {
      if (err instanceof ApiClientError && err.status === 401) {
        clearInMemoryAuth('unauthenticated', {
          kind: 'session_expired',
          message: 'Your session had already expired and has been cleared.',
        });
        return;
      }

      if (err instanceof ApiClientError && err.status === 403) {
        setAuthNotice({
          kind: 'access_denied',
          message: err.message || 'Logout was rejected by CSRF or origin protection.',
        });
        return;
      }

      setAuthNotice({
        kind: 'network_error',
        message:
          err instanceof Error && err.message
            ? `Logout request failed: ${err.message}`
            : 'Logout request failed due to a network error.',
      });
    } finally {
      isLoggingOutRef.current = false;
      setIsLoggingOut(false);
    }
  }, [apiClient, clearInMemoryAuth, navigator]);

  const clearAuthNotice = useCallback((): void => {
    setAuthNotice(null);
  }, []);

  const value = useMemo<AuthContextValue>(
    () => ({
      status,
      user,
      sessionId,
      hasCsrfToken,
      authNotice,
      isLoggingOut,
      apiClient,
      login,
      logout,
      refreshSession,
      clearAuthNotice,
    }),
    [
      status,
      user,
      sessionId,
      hasCsrfToken,
      authNotice,
      isLoggingOut,
      apiClient,
      login,
      logout,
      refreshSession,
      clearAuthNotice,
    ],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error('useAuth must be used inside an AuthProvider');
  }
  return ctx;
}
