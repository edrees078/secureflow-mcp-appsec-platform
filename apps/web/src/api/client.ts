import type { GlobalRole } from '@secureflow/schemas';

export type AuthenticatedRole = GlobalRole | 'USER';

export interface AuthActorProfile {
  readonly id: string;
  readonly globalRole: AuthenticatedRole;
  readonly isActive: boolean;
}

export interface SessionIdentitySnapshot {
  readonly actor: AuthActorProfile;
  readonly sessionId: string;
  readonly csrfToken: string;
}

export interface LogoutResult {
  readonly loggedOut: boolean;
  readonly endSessionUrl: string | null;
}

export interface ApiErrorPayload {
  readonly error?: {
    readonly code?: string;
    readonly message?: string;
    readonly details?: unknown;
  };
}

export type ApiErrorKind = 'unauthorized' | 'forbidden' | 'network' | 'http' | 'invalid_response';

export class ApiClientError extends Error {
  public readonly status: number;
  public readonly code: string;
  public readonly kind: ApiErrorKind;
  public readonly details?: unknown;

  constructor(options: {
    readonly status: number;
    readonly code: string;
    readonly kind: ApiErrorKind;
    readonly message: string;
    readonly details?: unknown;
  }) {
    super(options.message);
    this.name = 'ApiClientError';
    this.status = options.status;
    this.code = options.code;
    this.kind = options.kind;
    this.details = options.details;
  }
}

export type HttpMutationMethod = 'POST' | 'PUT' | 'PATCH' | 'DELETE';
export type HttpMethod = 'GET' | 'HEAD' | HttpMutationMethod;

const MUTATION_METHODS = new Set<string>(['POST', 'PUT', 'PATCH', 'DELETE']);

export interface ApiRequestOptions {
  readonly method?: HttpMethod | undefined;
  readonly body?: unknown;
  readonly headers?: Record<string, string> | undefined;
  readonly signal?: AbortSignal | undefined;
  /** Suppresses global auth error listeners (e.g., during initial anonymous /me probe). */
  readonly suppressAuthErrorEvents?: boolean | undefined;
}

export interface ApiClient {
  setCsrfToken(token: string | null): void;
  clearCsrfToken(): void;
  hasCsrfToken(): boolean;
  setAuthErrorListeners(listeners: {
    readonly onUnauthorized?: ((error: ApiClientError) => void) | undefined;
    readonly onForbidden?: ((error: ApiClientError) => void) | undefined;
  }): void;
  request<T>(path: string, options?: ApiRequestOptions): Promise<T>;
  get<T>(path: string, options?: Omit<ApiRequestOptions, 'method' | 'body'>): Promise<T>;
  post<T>(path: string, body?: unknown, options?: Omit<ApiRequestOptions, 'method' | 'body'>): Promise<T>;
  patch<T>(path: string, body?: unknown, options?: Omit<ApiRequestOptions, 'method' | 'body'>): Promise<T>;
  del<T>(path: string, body?: unknown, options?: Omit<ApiRequestOptions, 'method' | 'body'>): Promise<T>;
  getMe(options?: { readonly suppressAuthErrorEvents?: boolean | undefined; readonly signal?: AbortSignal | undefined }): Promise<SessionIdentitySnapshot>;
  logout(postLogoutRedirectUri?: string): Promise<LogoutResult>;
}

function normalizeMethod(method?: HttpMethod): HttpMethod {
  const upper = (method ?? 'GET').toUpperCase();
  switch (upper) {
    case 'GET':
    case 'HEAD':
    case 'POST':
    case 'PUT':
    case 'PATCH':
    case 'DELETE':
      return upper;
    default:
      return 'GET';
  }
}

function isObjectRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isValidSessionSnapshot(data: unknown): data is SessionIdentitySnapshot {
  if (!isObjectRecord(data)) {
    return false;
  }
  const actor = data['actor'];
  if (!isObjectRecord(actor)) {
    return false;
  }
  return (
    typeof actor['id'] === 'string' &&
    typeof actor['globalRole'] === 'string' &&
    typeof actor['isActive'] === 'boolean' &&
    typeof data['sessionId'] === 'string' &&
    typeof data['csrfToken'] === 'string' &&
    data['csrfToken'].length > 0
  );
}

function isValidLogoutResult(data: unknown): data is LogoutResult {
  if (!isObjectRecord(data)) {
    return false;
  }
  const endSessionUrl = data['endSessionUrl'];
  return (
    typeof data['loggedOut'] === 'boolean' &&
    (endSessionUrl === null || typeof endSessionUrl === 'string')
  );
}

/**
 * Creates a cookie-based, same-origin API client that keeps the session anti-CSRF
 * token strictly in memory (never web storage) and attaches `X-CSRF-Token` on all
 * state-changing HTTP operations.
 */
export function createApiClient(
  fetchImpl: typeof fetch = (...args) => globalThis.fetch(...args),
): ApiClient {
  let inMemoryCsrfToken: string | null = null;
  let onUnauthorized: ((error: ApiClientError) => void) | undefined;
  let onForbidden: ((error: ApiClientError) => void) | undefined;

  async function request<T>(path: string, options?: ApiRequestOptions): Promise<T> {
    const method = normalizeMethod(options?.method);
    const headers = new Headers(options?.headers);
    headers.set('Accept', 'application/json');

    let serializedBody: string | undefined;
    if (options?.body !== undefined) {
      if (!headers.has('Content-Type')) {
        headers.set('Content-Type', 'application/json');
      }
      serializedBody = JSON.stringify(options.body);
    }

    if (MUTATION_METHODS.has(method) && inMemoryCsrfToken) {
      headers.set('X-CSRF-Token', inMemoryCsrfToken);
    }

    let response: Response;
    try {
      const init: RequestInit = {
        method,
        credentials: 'same-origin',
        headers,
      };
      if (serializedBody !== undefined) {
        init.body = serializedBody;
      }
      if (options?.signal !== undefined) {
        init.signal = options.signal;
      }
      response = await fetchImpl(path, init);
    } catch (networkErr) {
      throw new ApiClientError({
        status: 0,
        code: 'NETWORK_ERROR',
        kind: 'network',
        message:
          networkErr instanceof Error && networkErr.message
            ? `Unable to reach SecureFlow API: ${networkErr.message}`
            : 'Unable to reach SecureFlow API',
      });
    }

    if (response.status === 204 || method === 'HEAD') {
      if (!response.ok) {
        const headErr = new ApiClientError({
          status: response.status,
          code:
            response.status === 401
              ? 'UNAUTHORIZED'
              : response.status === 403
                ? 'FORBIDDEN'
                : 'HTTP_ERROR',
          kind:
            response.status === 401
              ? 'unauthorized'
              : response.status === 403
                ? 'forbidden'
                : 'http',
          message: `Request failed with HTTP ${response.status}`,
        });
        if (!options?.suppressAuthErrorEvents) {
          if (response.status === 401) onUnauthorized?.(headErr);
          if (response.status === 403) onForbidden?.(headErr);
        }
        throw headErr;
      }
      return undefined as T;
    }

    let parsedBody: unknown;
    try {
      const rawText = await response.text();
      parsedBody = rawText.length > 0 ? JSON.parse(rawText) : {};
    } catch {
      if (!response.ok) {
        const fallbackError = new ApiClientError({
          status: response.status,
          code:
            response.status === 401
              ? 'UNAUTHORIZED'
              : response.status === 403
                ? 'FORBIDDEN'
                : 'HTTP_ERROR',
          kind:
            response.status === 401
              ? 'unauthorized'
              : response.status === 403
                ? 'forbidden'
                : 'http',
          message: `Request failed with HTTP ${response.status}`,
        });
        if (!options?.suppressAuthErrorEvents) {
          if (response.status === 401) onUnauthorized?.(fallbackError);
          if (response.status === 403) onForbidden?.(fallbackError);
        }
        throw fallbackError;
      }

      throw new ApiClientError({
        status: response.status,
        code: 'INVALID_RESPONSE',
        kind: 'invalid_response',
        message: 'API returned malformed JSON response',
      });
    }

    if (!response.ok) {
      const errorEnvelope = isObjectRecord(parsedBody) && isObjectRecord(parsedBody['error'])
        ? parsedBody['error']
        : undefined;
      const code =
        typeof errorEnvelope?.['code'] === 'string'
          ? errorEnvelope['code']
          : response.status === 401
            ? 'UNAUTHORIZED'
            : response.status === 403
              ? 'FORBIDDEN'
              : 'HTTP_ERROR';
      const message =
        typeof errorEnvelope?.['message'] === 'string'
          ? errorEnvelope['message']
          : `Request failed with HTTP ${response.status}`;

      const apiError = new ApiClientError({
        status: response.status,
        code,
        kind:
          response.status === 401
            ? 'unauthorized'
            : response.status === 403
              ? 'forbidden'
              : 'http',
        message,
        ...(errorEnvelope?.['details'] !== undefined ? { details: errorEnvelope['details'] } : {}),
      });

      if (!options?.suppressAuthErrorEvents) {
        if (response.status === 401) {
          onUnauthorized?.(apiError);
        } else if (response.status === 403) {
          onForbidden?.(apiError);
        }
      }

      throw apiError;
    }

    if (isObjectRecord(parsedBody) && 'data' in parsedBody) {
      return parsedBody['data'] as T;
    }

    return parsedBody as T;
  }

  return {
    setCsrfToken(token: string | null): void {
      inMemoryCsrfToken = token && token.trim().length > 0 ? token : null;
    },
    clearCsrfToken(): void {
      inMemoryCsrfToken = null;
    },
    hasCsrfToken(): boolean {
      return inMemoryCsrfToken !== null;
    },
    setAuthErrorListeners(listeners): void {
      onUnauthorized = listeners.onUnauthorized;
      onForbidden = listeners.onForbidden;
    },
    request,
    get<T>(path: string, options?: Omit<ApiRequestOptions, 'method' | 'body'>): Promise<T> {
      return request<T>(path, { ...options, method: 'GET' });
    },
    post<T>(
      path: string,
      body?: unknown,
      options?: Omit<ApiRequestOptions, 'method' | 'body'>,
    ): Promise<T> {
      return request<T>(path, { ...options, method: 'POST', body });
    },
    patch<T>(
      path: string,
      body?: unknown,
      options?: Omit<ApiRequestOptions, 'method' | 'body'>,
    ): Promise<T> {
      return request<T>(path, { ...options, method: 'PATCH', body });
    },
    del<T>(
      path: string,
      body?: unknown,
      options?: Omit<ApiRequestOptions, 'method' | 'body'>,
    ): Promise<T> {
      return request<T>(path, { ...options, method: 'DELETE', body });
    },
    async getMe(options?: {
      readonly suppressAuthErrorEvents?: boolean | undefined;
      readonly signal?: AbortSignal | undefined;
    }): Promise<SessionIdentitySnapshot> {
      const requestOpts: Omit<ApiRequestOptions, 'method' | 'body'> = {
        suppressAuthErrorEvents: options?.suppressAuthErrorEvents ?? true,
        ...(options?.signal !== undefined ? { signal: options.signal } : {}),
      };
      const data = await request<unknown>('/api/v1/auth/me', {
        ...requestOpts,
        method: 'GET',
      });
      if (!isValidSessionSnapshot(data)) {
        throw new ApiClientError({
          status: 500,
          code: 'INVALID_RESPONSE',
          kind: 'invalid_response',
          message: 'Unexpected /api/v1/auth/me payload structure',
        });
      }
      return data;
    },
    async logout(postLogoutRedirectUri?: string): Promise<LogoutResult> {
      const body = postLogoutRedirectUri ? { postLogoutRedirectUri } : {};
      const data = await request<unknown>('/api/v1/auth/logout', {
        method: 'POST',
        body,
      });
      if (!isValidLogoutResult(data)) {
        throw new ApiClientError({
          status: 500,
          code: 'INVALID_RESPONSE',
          kind: 'invalid_response',
          message: 'Unexpected /api/v1/auth/logout payload structure',
        });
      }
      return data;
    },
  };
}

export const apiClient = createApiClient();
