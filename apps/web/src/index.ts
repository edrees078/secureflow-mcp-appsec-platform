import type { FindingRecord } from '@secureflow/schemas';
import { formatDateIso } from '@secureflow/shared';

export {
  ApiClientError,
  apiClient,
  createApiClient,
  type ApiClient,
  type ApiErrorKind,
  type ApiRequestOptions,
  type AuthActorProfile,
  type AuthenticatedRole,
  type LogoutResult,
  type SessionIdentitySnapshot,
} from './api/client.js';
export {
  AuthProvider,
  useAuth,
  type AuthContextValue,
  type AuthNotice,
  type AuthNoticeKind,
  type AuthStatus,
} from './auth/AuthContext.js';
export { ProtectedRoute, type ProtectedRouteProps } from './auth/ProtectedRoute.js';
export {
  buildBffLoginUrl,
  buildPostLogoutRedirectUri,
  sanitizeReturnToPath,
  windowBrowserNavigator,
  type BrowserNavigator,
} from './auth/navigation.js';
export { App, AppRoutes } from './App.js';

export function renderFindingBadge(finding: FindingRecord): string {
  return `[${finding.severity}] ${finding.title} (created: ${formatDateIso(new Date(finding.createdAt))})`;
}
