import { useState } from 'react';
import { ApiClientError } from '../api/client.js';
import { useAuth } from '../auth/AuthContext.js';
import { AccessDeniedView } from '../components/AuthViews.js';

interface ProbeStatus {
  readonly state: 'idle' | 'pending' | 'ok' | 'forbidden' | 'error';
  readonly message?: string | undefined;
}

export function WorkspacePage() {
  const {
    user,
    sessionId,
    hasCsrfToken,
    authNotice,
    isLoggingOut,
    apiClient,
    logout,
    refreshSession,
  } = useAuth();
  const [probe, setProbe] = useState<ProbeStatus>({ state: 'idle' });
  const [isRefreshing, setIsRefreshing] = useState(false);

  if (!user) {
    return null;
  }

  const handleRefresh = async (): Promise<void> => {
    setIsRefreshing(true);
    try {
      await refreshSession();
    } finally {
      setIsRefreshing(false);
    }
  };

  const handleProtectedProbe = async (): Promise<void> => {
    setProbe({ state: 'pending' });
    try {
      await apiClient.get<{ readonly items?: unknown[] }>('/api/v1/projects?limit=1');
      setProbe({
        state: 'ok',
        message: 'Protected API request succeeded with active BFF session cookie (HTTP 200).',
      });
    } catch (err) {
      if (err instanceof ApiClientError) {
        if (err.status === 403) {
          setProbe({
            state: 'forbidden',
            message: err.message || 'Protected endpoint returned HTTP 403 Forbidden.',
          });
          return;
        }
        if (err.status === 401) {
          return;
        }
        setProbe({
          state: 'error',
          message: err.message || 'Protected API request failed.',
        });
        return;
      }
      setProbe({
        state: 'error',
        message: 'Unexpected error invoking protected endpoint.',
      });
    }
  };

  if (probe.state === 'forbidden') {
    return (
      <AccessDeniedView
        message={probe.message ?? 'Access denied by SecureFlow API (HTTP 403).'}
        onRetry={() => setProbe({ state: 'idle' })}
      />
    );
  }

  return (
    <main className="sf-shell">
      <section className="sf-card" aria-labelledby="workspace-heading">
        <header className="sf-topbar">
          <div>
            <span className="sf-badge sf-badge-success">Authenticated Session</span>
            <h1 id="workspace-heading">SecureFlow Authenticated Shell</h1>
          </div>
          <button
            type="button"
            className="sf-button sf-button-danger"
            onClick={() => void logout()}
            disabled={isLoggingOut}
          >
            {isLoggingOut ? 'Signing out...' : 'Sign out'}
          </button>
        </header>

        {authNotice ? (
          <div className="sf-alert sf-alert-warning" role="status">
            {authNotice.message}
          </div>
        ) : null}

        <dl className="sf-meta-grid">
          <div className="sf-meta-item">
            <dt>Principal ID</dt>
            <dd data-testid="actor-id">{user.id}</dd>
          </div>
          <div className="sf-meta-item">
            <dt>Authoritative Role</dt>
            <dd data-testid="actor-role">{user.globalRole}</dd>
          </div>
          <div className="sf-meta-item">
            <dt>Account Active</dt>
            <dd>{user.isActive ? 'Yes' : 'No'}</dd>
          </div>
          <div className="sf-meta-item">
            <dt>Session ID</dt>
            <dd data-testid="session-id">{sessionId ?? 'unknown'}</dd>
          </div>
          <div className="sf-meta-item">
            <dt>CSRF Token State</dt>
            <dd data-testid="csrf-status">
              {hasCsrfToken ? 'Loaded in memory' : 'Not loaded'}
            </dd>
          </div>
        </dl>

        <p className="sf-muted">
          Phase 5A session verification view. Full AppSec dashboards are deferred to subsequent
          Phase 5 milestones. Authorization is always enforced by Express and PostgreSQL.
        </p>

        {probe.state !== 'idle' && probe.message ? (
          <div
            className={
              probe.state === 'ok' ? 'sf-alert sf-alert-success' : 'sf-alert sf-alert-warning'
            }
            role="status"
          >
            {probe.message}
          </div>
        ) : null}

        <div className="sf-actions">
          <button
            type="button"
            className="sf-button sf-button-secondary"
            onClick={() => void handleRefresh()}
            disabled={isRefreshing || isLoggingOut}
          >
            {isRefreshing ? 'Refreshing...' : 'Revalidate Session'}
          </button>
          <button
            type="button"
            className="sf-button sf-button-secondary"
            onClick={() => void handleProtectedProbe()}
            disabled={probe.state === 'pending' || isLoggingOut}
          >
            {probe.state === 'pending' ? 'Checking...' : 'Verify Protected API'}
          </button>
        </div>
      </section>
    </main>
  );
}
