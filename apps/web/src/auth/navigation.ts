/**
 * Safe relative navigation and top-level browser redirect helpers for BFF OIDC flows.
 */

export interface BrowserNavigator {
  assign(url: string): void;
  getOrigin(): string;
  getPathAndSearch(): string;
}

export const windowBrowserNavigator: BrowserNavigator = {
  assign(url: string): void {
    window.location.assign(url);
  },
  getOrigin(): string {
    return window.location.origin;
  },
  getPathAndSearch(): string {
    return `${window.location.pathname}${window.location.search}`;
  },
};

function hasControlCharacters(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code <= 0x1f || code === 0x7f) {
      return true;
    }
  }
  return false;
}

/**
 * Validates that a candidate post-login returnTo destination is a safe internal
 * relative path starting with a single `/` (rejecting protocol-relative `//`,
 * encoded slash/backslash bypasses such as `%2f`/`%5c`/`%252f`, backslashes,
 * absolute URLs, and control characters). Redirects targeting `/login`
 * collapse to `/` so login does not loop.
 */
export function sanitizeReturnToPath(rawPath?: string | null): string {
  if (!rawPath) {
    return '/';
  }

  const trimmed = rawPath.trim();
  if (
    trimmed.length === 0 ||
    trimmed.length > 500 ||
    !trimmed.startsWith('/') ||
    trimmed.startsWith('//') ||
    trimmed.includes('\\') ||
    hasControlCharacters(trimmed) ||
    /%(?:0[0-9a-f]|1[0-9a-f]|7f|5c|255c)/i.test(trimmed)
  ) {
    return '/';
  }

  const queryOrHashIndex = trimmed.search(/[?#]/);
  const pathPart = queryOrHashIndex === -1 ? trimmed : trimmed.slice(0, queryOrHashIndex);
  if (/%(?:2f|5c|252f|255c)/i.test(pathPart)) {
    return '/';
  }

  let decodedPath = pathPart;
  for (let pass = 0; pass < 2; pass++) {
    try {
      const nextDecoded = decodeURIComponent(decodedPath);
      if (
        !nextDecoded.startsWith('/') ||
        nextDecoded.startsWith('//') ||
        nextDecoded.includes('\\') ||
        hasControlCharacters(nextDecoded)
      ) {
        return '/';
      }
      if (nextDecoded === decodedPath) {
        break;
      }
      decodedPath = nextDecoded;
    } catch {
      return '/';
    }
  }

  try {
    const parsed = new URL(trimmed, 'https://secureflow.invalid');
    if (
      parsed.origin !== 'https://secureflow.invalid' ||
      parsed.username !== '' ||
      parsed.password !== '' ||
      !parsed.pathname.startsWith('/') ||
      parsed.pathname.startsWith('//') ||
      parsed.pathname.includes('\\')
    ) {
      return '/';
    }
    if (parsed.pathname === '/login') {
      return '/';
    }
  } catch {
    return '/';
  }

  return trimmed;
}

/**
 * Builds the BFF top-level navigation URL to initiate OIDC login.
 * Never call this endpoint with fetch/XHR — browsers must perform a top-level
 * navigation so Keycloak SSO redirects and SameSite=Lax cookies function properly.
 */
export function buildBffLoginUrl(returnTo?: string | null): string {
  const safeReturnTo = sanitizeReturnToPath(returnTo);
  return `/api/v1/auth/login?returnTo=${encodeURIComponent(safeReturnTo)}`;
}

/**
 * Computes the expected post-logout redirect URL on the current frontend origin.
 */
export function buildPostLogoutRedirectUri(origin: string): string {
  return `${origin.replace(/\/+$/, '')}/login`;
}
