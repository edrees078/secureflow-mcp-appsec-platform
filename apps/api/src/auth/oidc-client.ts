import * as client from 'openid-client';
import { SecureFlowError } from '@secureflow/shared';
import {
  normalizeAndValidateRedirectUri,
  type OidcProtocolConfig,
} from '../config/auth.js';

export type OidcErrorCode =
  | 'OIDC_DISCOVERY_FAILED'
  | 'OIDC_REDIRECT_URI_NOT_ALLOWED'
  | 'OIDC_STATE_MISMATCH'
  | 'OIDC_ISSUER_MISMATCH'
  | 'OIDC_NONCE_MISMATCH'
  | 'OIDC_ID_TOKEN_EXPIRED'
  | 'OIDC_ID_TOKEN_AUDIENCE_MISMATCH'
  | 'OIDC_ID_TOKEN_INVALID_SIGNATURE'
  | 'OIDC_AUTHORIZATION_ERROR'
  | 'OIDC_TOKEN_EXCHANGE_FAILED'
  | 'OIDC_CLAIMS_INVALID';

/**
 * Safe protocol error surfaced across BFF auth boundaries without leaking raw tokens,
 * client secrets, PKCE verifiers, or authorization codes.
 */
export class OidcProtocolError extends SecureFlowError {
  public readonly protocolCode: OidcErrorCode;

  constructor(
    message: string,
    protocolCode: OidcErrorCode,
    statusCode = 401,
  ) {
    super(message, protocolCode, statusCode);
    this.protocolCode = protocolCode;
  }
}

export interface OidcServerMetadataSummary {
  readonly issuer: string;
  readonly authorizationEndpoint: string;
  readonly tokenEndpoint: string;
  readonly jwksUri: string;
  readonly supportsPkceS256: boolean;
}

export interface OidcAuthorizationRequestParams {
  readonly redirectUri: string;
  readonly state: string;
  readonly nonce: string;
  readonly codeChallenge: string;
  readonly codeChallengeMethod: 'S256';
  readonly scope?: string;
}

export interface OidcAuthorizationCallbackInput {
  readonly callbackUrl: string | URL;
  readonly expectedRedirectUri: string;
  readonly expectedState: string;
  readonly expectedNonce: string;
  readonly pkceCodeVerifier: string;
}

export interface VerifiedOidcTokenIdentity {
  readonly issuer: string;
  readonly sub: string;
  readonly email: string;
  readonly emailVerified: boolean;
  readonly displayName?: string;
  readonly oidcSid: string | null;
  readonly audience: string | readonly string[];
}

/**
 * Narrow protocol interface decoupling Express BFF orchestration from `openid-client`.
 */
export interface IOidcClient {
  discover(): Promise<OidcServerMetadataSummary>;
  buildAuthorizationUrl(params: OidcAuthorizationRequestParams): Promise<URL>;
  exchangeAuthorizationCode(
    input: OidcAuthorizationCallbackInput,
  ): Promise<VerifiedOidcTokenIdentity>;
  clearCache(): void;
}

export interface OpenIdConnectClientOptions {
  /** Optional custom Fetch API implementation (e.g., proxy instrumentation or test transport). */
  readonly customFetch?: client.CustomFetch;
}

function classifyOidcClientError(
  err: unknown,
  stage: 'discovery' | 'exchange',
): OidcProtocolError {
  if (err instanceof OidcProtocolError) {
    return err;
  }

  if (err instanceof client.AuthorizationResponseError) {
    const safeOAuthError = /^[a-z0-9_.-]{1,64}$/i.test(err.error)
      ? err.error
      : 'authorization_error';
    return new OidcProtocolError(
      `OIDC authorization server returned an error (${safeOAuthError})`,
      'OIDC_AUTHORIZATION_ERROR',
      401,
    );
  }

  if (err instanceof client.ResponseBodyError) {
    return new OidcProtocolError(
      `OIDC token endpoint rejected authorization code exchange (HTTP ${err.status})`,
      'OIDC_TOKEN_EXCHANGE_FAILED',
      401,
    );
  }

  if (err instanceof Error) {
    const causeError = err.cause instanceof Error ? err.cause : undefined;
    const msg = `${err.message} ${causeError ? causeError.message : ''}`.toLowerCase();
    const errorCode =
      'code' in err && typeof err.code === 'string'
        ? err.code.toUpperCase()
        : causeError && 'code' in causeError && typeof causeError.code === 'string'
          ? causeError.code.toUpperCase()
          : '';

    if (msg.includes('"iss"') || msg.includes('issuer')) {
      return new OidcProtocolError(
        'OIDC issuer validation failed',
        'OIDC_ISSUER_MISMATCH',
        401,
      );
    }

    if (msg.includes('"state"') || msg.includes('state')) {
      return new OidcProtocolError(
        'OIDC authorization state validation failed',
        'OIDC_STATE_MISMATCH',
        401,
      );
    }

    if (msg.includes('"nonce"') || msg.includes('nonce')) {
      return new OidcProtocolError(
        'OIDC ID token nonce validation failed',
        'OIDC_NONCE_MISMATCH',
        401,
      );
    }

    if (msg.includes('"aud"') || msg.includes('"azp"') || msg.includes('audience')) {
      return new OidcProtocolError(
        'OIDC ID token audience validation failed',
        'OIDC_ID_TOKEN_AUDIENCE_MISMATCH',
        401,
      );
    }

    if (
      errorCode.includes('TIMESTAMP') ||
      msg.includes('"exp"') ||
      msg.includes('"nbf"') ||
      msg.includes('expired') ||
      msg.includes('future')
    ) {
      return new OidcProtocolError(
        'OIDC ID token timestamp validation failed',
        'OIDC_ID_TOKEN_EXPIRED',
        401,
      );
    }

    if (
      errorCode.includes('KEY_SELECTION') ||
      errorCode.includes('CRYPTO') ||
      errorCode.includes('JWS') ||
      errorCode.includes('JSON_WEB_KEY_SET') ||
      errorCode.includes('UNSUPPORTED_OPERATION') ||
      msg.includes('signature') ||
      msg.includes('jwks') ||
      msg.includes('verification key') ||
      msg.includes('unsupported jws')
    ) {
      return new OidcProtocolError(
        'OIDC ID token signature or JWKS validation failed',
        'OIDC_ID_TOKEN_INVALID_SIGNATURE',
        401,
      );
    }

    if (stage === 'discovery') {
      return new OidcProtocolError(
        'OIDC trusted issuer discovery failed',
        'OIDC_DISCOVERY_FAILED',
        503,
      );
    }
  }

  return new OidcProtocolError(
    stage === 'discovery'
      ? 'OIDC trusted issuer discovery failed'
      : 'OIDC authorization code exchange failed',
    stage === 'discovery' ? 'OIDC_DISCOVERY_FAILED' : 'OIDC_TOKEN_EXCHANGE_FAILED',
    stage === 'discovery' ? 503 : 401,
  );
}

/**
 * Standards-compliant OIDC relying-party integration built on `openid-client` v6.
 */
export class OpenIdConnectClient implements IOidcClient {
  private readonly config: OidcProtocolConfig;
  private readonly customFetch: client.CustomFetch | undefined;
  private discoveredConfig: client.Configuration | null = null;
  private discoveryInFlight: Promise<client.Configuration> | null = null;

  constructor(config: OidcProtocolConfig, options?: OpenIdConnectClientOptions) {
    this.config = config;
    this.customFetch = options?.customFetch;
  }

  public clearCache(): void {
    this.discoveredConfig = null;
    this.discoveryInFlight = null;
  }

  private async getConfiguration(): Promise<client.Configuration> {
    if (this.discoveredConfig) {
      return this.discoveredConfig;
    }
    if (this.discoveryInFlight) {
      return this.discoveryInFlight;
    }

    this.discoveryInFlight = this.performDiscovery();
    try {
      const cfg = await this.discoveryInFlight;
      this.discoveredConfig = cfg;
      return cfg;
    } finally {
      this.discoveryInFlight = null;
    }
  }

  private async performDiscovery(): Promise<client.Configuration> {
    const issuerUrl = new URL(this.config.issuerUrl);
    const clientAuth =
      this.config.clientAuthMethod === 'client_secret_post'
        ? client.ClientSecretPost(this.config.clientSecret)
        : client.ClientSecretBasic(this.config.clientSecret);

    const clientMetadata: Partial<client.ClientMetadata> = {
      client_secret: this.config.clientSecret,
      redirect_uris: [...this.config.allowedRedirectUris],
      [client.clockTolerance]: this.config.clockToleranceSeconds,
    };

    const executeHooks: Array<(cfg: client.Configuration) => void> = [
      client.enableNonRepudiationChecks,
    ];
    if (this.config.allowInsecureHttp) {
      executeHooks.push(client.allowInsecureRequests);
    }

    const discoveryOptions: client.DiscoveryRequestOptions = {
      algorithm: 'oidc',
      timeout: this.config.requestTimeoutSeconds,
      execute: executeHooks,
      ...(this.customFetch ? { [client.customFetch]: this.customFetch } : {}),
    };

    try {
      const resolved = await client.discovery(
        issuerUrl,
        this.config.clientId,
        clientMetadata,
        clientAuth,
        discoveryOptions,
      );

      const serverMetadata = resolved.serverMetadata();
      if (
        !serverMetadata.authorization_endpoint ||
        !serverMetadata.token_endpoint ||
        !serverMetadata.jwks_uri
      ) {
        throw new OidcProtocolError(
          'OIDC discovery metadata is missing required endpoints or jwks_uri',
          'OIDC_DISCOVERY_FAILED',
          503,
        );
      }

      if (
        Array.isArray(serverMetadata.code_challenge_methods_supported) &&
        !serverMetadata.code_challenge_methods_supported.includes('S256')
      ) {
        throw new OidcProtocolError(
          'OIDC provider does not advertise mandatory PKCE S256 support',
          'OIDC_DISCOVERY_FAILED',
          503,
        );
      }

      return resolved;
    } catch (err) {
      throw classifyOidcClientError(err, 'discovery');
    }
  }

  public async discover(): Promise<OidcServerMetadataSummary> {
    const cfg = await this.getConfiguration();
    const meta = cfg.serverMetadata();

    return {
      issuer: meta.issuer,
      authorizationEndpoint: meta.authorization_endpoint!,
      tokenEndpoint: meta.token_endpoint!,
      jwksUri: meta.jwks_uri!,
      supportsPkceS256:
        !Array.isArray(meta.code_challenge_methods_supported) ||
        meta.code_challenge_methods_supported.includes('S256'),
    };
  }

  public async buildAuthorizationUrl(
    params: OidcAuthorizationRequestParams,
  ): Promise<URL> {
    let allowlistedRedirectUri: string;
    try {
      allowlistedRedirectUri = normalizeAndValidateRedirectUri(
        params.redirectUri,
        this.config.allowedRedirectUris,
        !this.config.allowInsecureHttp,
      );
    } catch {
      throw new OidcProtocolError(
        'OIDC redirect URI is not permitted by allowlist',
        'OIDC_REDIRECT_URI_NOT_ALLOWED',
        400,
      );
    }

    if (params.codeChallengeMethod !== 'S256') {
      throw new OidcProtocolError(
        'Only PKCE S256 challenge method is supported',
        'OIDC_CLAIMS_INVALID',
        400,
      );
    }
    if (!params.state.trim() || !params.nonce.trim() || !params.codeChallenge.trim()) {
      throw new OidcProtocolError(
        'State, nonce, and PKCE code_challenge are required for authorization requests',
        'OIDC_CLAIMS_INVALID',
        400,
      );
    }

    const cfg = await this.getConfiguration();
    const authorizationUrl = client.buildAuthorizationUrl(cfg, {
      redirect_uri: allowlistedRedirectUri,
      scope: params.scope ?? this.config.scopes,
      response_type: 'code',
      code_challenge: params.codeChallenge,
      code_challenge_method: 'S256',
      state: params.state,
      nonce: params.nonce,
    });

    return authorizationUrl;
  }

  public async exchangeAuthorizationCode(
    input: OidcAuthorizationCallbackInput,
  ): Promise<VerifiedOidcTokenIdentity> {
    let allowlistedRedirectUri: string;
    try {
      allowlistedRedirectUri = normalizeAndValidateRedirectUri(
        input.expectedRedirectUri,
        this.config.allowedRedirectUris,
        !this.config.allowInsecureHttp,
      );
    } catch {
      throw new OidcProtocolError(
        'OIDC callback redirect URI is not permitted by allowlist',
        'OIDC_REDIRECT_URI_NOT_ALLOWED',
        400,
      );
    }

    let parsedCallbackUrl: URL;
    try {
      parsedCallbackUrl =
        input.callbackUrl instanceof URL
          ? new URL(input.callbackUrl.toString())
          : new URL(input.callbackUrl);
    } catch {
      throw new OidcProtocolError(
        'Malformed OIDC authorization callback URL',
        'OIDC_TOKEN_EXCHANGE_FAILED',
        400,
      );
    }

    const expectedRedirectUrl = new URL(allowlistedRedirectUri);
    if (
      parsedCallbackUrl.origin !== expectedRedirectUrl.origin ||
      parsedCallbackUrl.pathname !== expectedRedirectUrl.pathname
    ) {
      throw new OidcProtocolError(
        'OIDC callback URL does not match allowlisted redirect URI',
        'OIDC_REDIRECT_URI_NOT_ALLOWED',
        400,
      );
    }

    if (
      !input.expectedState.trim() ||
      !input.expectedNonce.trim() ||
      !input.pkceCodeVerifier.trim()
    ) {
      throw new OidcProtocolError(
        'Expected state, nonce, and PKCE code verifier are required',
        'OIDC_CLAIMS_INVALID',
        400,
      );
    }

    const cfg = await this.getConfiguration();

    let tokenResponse: client.TokenEndpointResponse & client.TokenEndpointResponseHelpers;
    try {
      tokenResponse = await client.authorizationCodeGrant(cfg, parsedCallbackUrl, {
        expectedState: input.expectedState,
        expectedNonce: input.expectedNonce,
        pkceCodeVerifier: input.pkceCodeVerifier,
        idTokenExpected: true,
      });
    } catch (err) {
      throw classifyOidcClientError(err, 'exchange');
    }

    const claims = tokenResponse.claims();
    if (!claims) {
      throw new OidcProtocolError(
        'OIDC token response did not contain a validated ID token',
        'OIDC_CLAIMS_INVALID',
        401,
      );
    }

    const sub = typeof claims.sub === 'string' ? claims.sub.trim() : '';
    const iss = typeof claims.iss === 'string' ? claims.iss.trim() : '';
    const email = typeof claims['email'] === 'string' ? claims['email'].trim() : '';
    const rawDisplayName =
      typeof claims['name'] === 'string'
        ? claims['name'].trim()
        : typeof claims['preferred_username'] === 'string'
          ? claims['preferred_username'].trim()
          : undefined;
    const rawSid = typeof claims['sid'] === 'string' ? claims['sid'].trim() : '';

    if (!sub || !iss || !email) {
      throw new OidcProtocolError(
        'OIDC ID token is missing required sub, iss, or email claims',
        'OIDC_CLAIMS_INVALID',
        401,
      );
    }

    return {
      issuer: iss,
      sub,
      email,
      emailVerified: claims['email_verified'] === true,
      ...(rawDisplayName && rawDisplayName.length > 0 ? { displayName: rawDisplayName } : {}),
      oidcSid: rawSid.length > 0 ? rawSid : null,
      audience: claims.aud,
    };
  }
}
