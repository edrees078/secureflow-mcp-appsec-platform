export interface AccessDeniedViewProps {
  readonly message: string;
  readonly onRetry?: (() => void) | undefined;
  readonly onSignIn?: (() => void) | undefined;
}

export function SessionLoadingView() {
  return (
    <main className="sf-shell">
      <section className="sf-card" role="status" aria-live="polite" aria-label="Checking authentication">
        <div className="sf-header">
          <span className="sf-badge sf-badge-neutral">SecureFlow BFF</span>
          <h1>Verifying session</h1>
        </div>
        <p className="sf-muted">
          Restoring your server-managed authentication state...
        </p>
      </section>
    </main>
  );
}

export function AccessDeniedView({ message, onRetry, onSignIn }: AccessDeniedViewProps) {
  return (
    <main className="sf-shell">
      <section className="sf-card sf-card-danger" role="alert" aria-labelledby="access-denied-title">
        <div className="sf-header">
          <span className="sf-badge sf-badge-danger">HTTP 403</span>
          <h1 id="access-denied-title">Access denied</h1>
        </div>
        <p className="sf-body">{message}</p>
        <p className="sf-muted">
          Authorization decisions are enforced server-side from authoritative PostgreSQL records.
        </p>
        <div className="sf-actions">
          {onRetry ? (
            <button type="button" className="sf-button sf-button-secondary" onClick={onRetry}>
              Retry session check
            </button>
          ) : null}
          {onSignIn ? (
            <button type="button" className="sf-button sf-button-primary" onClick={onSignIn}>
              Sign in with Keycloak
            </button>
          ) : null}
        </div>
      </section>
    </main>
  );
}

export interface SessionErrorViewProps {
  readonly message: string;
  readonly onRetry: () => void;
}

export function SessionErrorView({ message, onRetry }: SessionErrorViewProps) {
  return (
    <main className="sf-shell">
      <section className="sf-card sf-card-warning" role="alert" aria-labelledby="session-error-title">
        <div className="sf-header">
          <span className="sf-badge sf-badge-warning">Connection Error</span>
          <h1 id="session-error-title">Unable to reach SecureFlow API</h1>
        </div>
        <p className="sf-body">{message}</p>
        <div className="sf-actions">
          <button type="button" className="sf-button sf-button-primary" onClick={onRetry}>
            Retry session check
          </button>
        </div>
      </section>
    </main>
  );
}
