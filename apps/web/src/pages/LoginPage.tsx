import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from '../auth/AuthContext.js';
import { sanitizeReturnToPath } from '../auth/navigation.js';
import { SessionLoadingView } from '../components/AuthViews.js';

interface LocationLoginState {
  readonly returnTo?: string;
}

export function LoginPage() {
  const { status, authNotice, login, refreshSession } = useAuth();
  const location = useLocation();

  const searchParams = new URLSearchParams(location.search);
  const queryReturnTo = searchParams.get('returnTo');
  const stateReturnTo = (location.state as LocationLoginState | null)?.returnTo;
  const safeReturnTo = sanitizeReturnToPath(queryReturnTo ?? stateReturnTo ?? '/');

  if (status === 'loading') {
    return <SessionLoadingView />;
  }

  if (status === 'authenticated') {
    return <Navigate to={safeReturnTo} replace />;
  }

  const noticeClass =
    authNotice?.kind === 'access_denied'
      ? 'sf-alert sf-alert-danger'
      : authNotice?.kind === 'network_error' || authNotice?.kind === 'session_expired'
        ? 'sf-alert sf-alert-warning'
        : 'sf-alert sf-alert-info';

  return (
    <main className="sf-shell">
      <section className="sf-card" aria-labelledby="login-heading">
        <div className="sf-header">
          <span className="sf-badge sf-badge-neutral">Integrated BFF SSO</span>
          <h1 id="login-heading">Sign in to SecureFlow</h1>
        </div>

        <p className="sf-body">
          Authentication is handled exclusively by the SecureFlow Backend-for-Frontend using
          server-managed HttpOnly session cookies and Keycloak OIDC.
        </p>

        {authNotice ? (
          <div className={noticeClass} role="status">
            {authNotice.message}
          </div>
        ) : null}

        <div className="sf-actions">
          <button
            type="button"
            className="sf-button sf-button-primary"
            onClick={() => login(safeReturnTo)}
          >
            Sign in with Keycloak SSO
          </button>
          {status === 'error' || status === 'access_denied' ? (
            <button
              type="button"
              className="sf-button sf-button-secondary"
              onClick={() => void refreshSession()}
            >
              Retry session check
            </button>
          ) : null}
        </div>
      </section>
    </main>
  );
}
