import type {
  ActorContext,
  IAuthService,
  UserProfileEntity,
} from '@secureflow/domain';
import type { AuthFailureReason } from '@secureflow/schemas';
import type { AuthRuntimeConfig } from '../config/auth.js';
import { OidcProtocolError, type IOidcClient } from './oidc-client.js';

export interface StartOidcLoginInput {
  readonly returnTo?: string;
  readonly redirectUri?: string;
}

export interface StartedOidcLoginFlow {
  readonly authorizationUrl: URL;
  readonly rawTxnToken: string;
  readonly expiresAt: Date;
}

export interface CompleteOidcCallbackInput {
  readonly callbackUrl: string | URL;
  readonly rawTxnToken: string;
  readonly redirectUri?: string;
  readonly ipAddress?: string | null;
  readonly userAgent?: string | null;
}

export interface CompletedOidcLoginFlow {
  readonly rawSessionToken: string;
  readonly csrfToken: string;
  readonly sessionId: string;
  readonly expiresAt: Date;
  readonly idleExpiresAt: Date;
  readonly returnTo: string;
  readonly user: UserProfileEntity;
  readonly actor: ActorContext;
  readonly jitProvisioned: boolean;
}

function mapProtocolErrorToAuditReason(err: unknown): AuthFailureReason {
  if (err instanceof OidcProtocolError) {
    if (err.protocolCode === 'OIDC_STATE_MISMATCH') {
      return 'OIDC_STATE_MISMATCH';
    }
    if (err.protocolCode === 'OIDC_NONCE_MISMATCH') {
      return 'OIDC_NONCE_MISMATCH';
    }
  }
  return 'OIDC_TOKEN_EXCHANGE_FAILED';
}

/**
 * Coordinates the OIDC authorization flow between the `IOidcClient` protocol wrapper
 * and the domain `IAuthService` persistence boundary without exposing HTTP endpoints.
 */
export class OidcAuthFlowCoordinator {
  private readonly authService: IAuthService;
  private readonly oidcClient: IOidcClient;
  private readonly config: AuthRuntimeConfig;

  constructor(
    authService: IAuthService,
    oidcClient: IOidcClient,
    config: AuthRuntimeConfig,
  ) {
    this.authService = authService;
    this.oidcClient = oidcClient;
    this.config = config;
  }

  public async startAuthorizationFlow(
    input?: StartOidcLoginInput,
    now?: Date,
  ): Promise<StartedOidcLoginFlow> {
    const txn = await this.authService.createOidcTransaction(
      {
        returnTo: input?.returnTo ?? '/',
        ttlSeconds: this.config.session.oidcTxnTtlSeconds,
      },
      now,
    );

    const authorizationUrl = await this.oidcClient.buildAuthorizationUrl({
      redirectUri: input?.redirectUri ?? this.config.oidc.redirectUri,
      state: txn.state,
      nonce: txn.nonce,
      codeChallenge: txn.codeChallenge,
      codeChallengeMethod: txn.codeChallengeMethod,
      scope: this.config.oidc.scopes,
    });

    return {
      authorizationUrl,
      rawTxnToken: txn.rawTxnToken,
      expiresAt: txn.expiresAt,
    };
  }

  public async completeAuthorizationCallback(
    input: CompleteOidcCallbackInput,
    now?: Date,
  ): Promise<CompletedOidcLoginFlow> {
    let parsedCallbackUrl: URL;
    try {
      parsedCallbackUrl =
        input.callbackUrl instanceof URL
          ? new URL(input.callbackUrl.toString())
          : new URL(input.callbackUrl);
    } catch {
      await this.authService.recordAuthenticationFailure({
        reason: 'OIDC_TOKEN_EXCHANGE_FAILED',
        actorId: null,
        resourceUserId: null,
        ipAddress: input.ipAddress ?? null,
        userAgent: input.userAgent ?? null,
        metadata: { stage: 'callback_url_parse' },
      });
      throw new OidcProtocolError(
        'Malformed OIDC authorization callback URL',
        'OIDC_TOKEN_EXCHANGE_FAILED',
        400,
      );
    }

    const callbackState = parsedCallbackUrl.searchParams.get('state')?.trim() ?? '';
    if (!callbackState) {
      await this.authService.recordAuthenticationFailure({
        reason: 'OIDC_STATE_MISMATCH',
        actorId: null,
        resourceUserId: null,
        ipAddress: input.ipAddress ?? null,
        userAgent: input.userAgent ?? null,
        metadata: { stage: 'callback_state_presence' },
      });
      throw new OidcProtocolError(
        'OIDC authorization callback is missing required state parameter',
        'OIDC_STATE_MISMATCH',
        401,
      );
    }

    const consumedTxn = await this.authService.consumeOidcTransaction(
      {
        rawTxnToken: input.rawTxnToken,
        state: callbackState,
        ipAddress: input.ipAddress ?? null,
        userAgent: input.userAgent ?? null,
      },
      now,
    );

    let verifiedIdentity;
    try {
      verifiedIdentity = await this.oidcClient.exchangeAuthorizationCode({
        callbackUrl: parsedCallbackUrl,
        expectedRedirectUri: input.redirectUri ?? this.config.oidc.redirectUri,
        expectedState: callbackState,
        expectedNonce: consumedTxn.nonce,
        pkceCodeVerifier: consumedTxn.codeVerifier,
      });
    } catch (err) {
      const failureReason = mapProtocolErrorToAuditReason(err);
      const protocolCode =
        err instanceof OidcProtocolError ? err.protocolCode : 'OIDC_TOKEN_EXCHANGE_FAILED';

      await this.authService.recordAuthenticationFailure({
        reason: failureReason,
        actorId: null,
        resourceUserId: null,
        ipAddress: input.ipAddress ?? null,
        userAgent: input.userAgent ?? null,
        metadata: { protocolCode },
      });
      throw err;
    }

    const established = await this.authService.establishAuthenticatedSession(
      {
        sub: verifiedIdentity.sub,
        email: verifiedIdentity.email,
        emailVerified: verifiedIdentity.emailVerified,
        ...(verifiedIdentity.displayName !== undefined
          ? { displayName: verifiedIdentity.displayName }
          : {}),
        oidcSid: verifiedIdentity.oidcSid,
        ipAddress: input.ipAddress ?? null,
        userAgent: input.userAgent ?? null,
        idleTimeoutSeconds: this.config.session.idleTimeoutSeconds,
        absoluteTimeoutSeconds: this.config.session.absoluteTimeoutSeconds,
      },
      now,
    );

    return {
      rawSessionToken: established.rawSessionToken,
      csrfToken: established.session.csrfToken,
      sessionId: established.session.id,
      expiresAt: established.session.expiresAt,
      idleExpiresAt: established.session.idleExpiresAt,
      returnTo: consumedTxn.returnTo,
      user: established.user,
      actor: established.actor,
      jitProvisioned: established.jitProvisioned,
    };
  }
}
