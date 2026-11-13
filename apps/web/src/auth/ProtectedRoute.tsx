import { Navigate, Outlet, useLocation } from 'react-router-dom';
import type { ReactNode } from 'react';
import { useAuth } from './AuthContext.js';
import { sanitizeReturnToPath } from './navigation.js';
import type { AuthenticatedRole } from '../api/client.js';
import {
  AccessDeniedView,
  SessionErrorView,
  SessionLoadingView,
} from '../components/AuthViews.js';

export interface ProtectedRouteProps {
  /**
   * Optional UI-level role hint. Never replaces authoritative BFF + PostgreSQL authorization.
   */
  readonly allowedRoles?: readonly AuthenticatedRole[] | undefined;
  readonly children?: ReactNode | undefined;
}

export function ProtectedRoute({ allowedRoles, children }: ProtectedRouteProps) {
  const { status, user, authNotice, refreshSession, login } = useAuth();
  const location = useLocation();

  if (status === 'loading') {
    return <SessionLoadingView />;
  }

  if (status === 'unauthenticated') {
    const requestedPath = sanitizeReturnToPath(`${location.pathname}${location.search}`);
    const loginPath =
      requestedPath === '/'
        ? '/login'
        : `/login?returnTo=${encodeURIComponent(requestedPath)}`;
    return <Navigate to={loginPath} replace state={{ returnTo: requestedPath }} />;
  }

  if (status === 'access_denied') {
    return (
      <AccessDeniedView
        message={authNotice?.message ?? 'Your account does not have permission to access SecureFlow.'}
        onRetry={() => void refreshSession()}
        onSignIn={() => login('/')}
      />
    );
  }

  if (status === 'error') {
    return (
      <SessionErrorView
        message={authNotice?.message ?? 'Unable to verify your session with the server.'}
        onRetry={() => void refreshSession()}
      />
    );
  }

  if (allowedRoles && user && !allowedRoles.includes(user.globalRole)) {
    return (
      <AccessDeniedView
        message={`Role '${user.globalRole}' is not permitted on this view. Authoritative access control is enforced by the API.`}
        onRetry={() => void refreshSession()}
      />
    );
  }

  return children ? <>{children}</> : <Outlet />;
}
