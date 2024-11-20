import type {
  OpenId4VciResolvedCredentialOffer,
  OpenId4VciAuthCodeFlowOptions,
  OpenId4VciTokenRequestOptions as OpenId4VciRequestTokenOptions,
  OpenId4VciCredentialRequestOptions as OpenId4VciRequestCredentialOptions,
  OpenId4VciSendNotificationOptions,
  OpenId4VciRequestTokenResponse,
  OpenId4VciRetrieveAuthorizationCodeUsingPresentationOptions,
} from './OpenId4VciHolderServiceOptions'
import type {
  OpenId4VcSiopAcceptAuthorizationRequestOptions,
  OpenId4VcSiopResolveAuthorizationRequestOptions,
  OpenId4VcSiopResolveTrustChainsOptions,
} from './OpenId4vcSiopHolderServiceOptions'

import { injectable, AgentContext, DifPresentationExchangeService, DifPexCredentialsForRequest } from '@credo-ts/core'

import { OpenId4VciMetadata } from '../shared'

import { OpenId4VciHolderService } from './OpenId4VciHolderService'
import { OpenId4VcSiopHolderService } from './OpenId4vcSiopHolderService'

/**
 * @public
 */
@injectable()
export class OpenId4VcHolderApi {
  public constructor(
    private agentContext: AgentContext,
    private openId4VciHolderService: OpenId4VciHolderService,
    private openId4VcSiopHolderService: OpenId4VcSiopHolderService,
    private difPresentationExchangeService: DifPresentationExchangeService
  ) {}

  /**
   * Resolves the authentication request given as URI or JWT to a unified format, and
   * verifies the validity of the request.
   *
   * The resolved request can be accepted with the @see acceptSiopAuthorizationRequest.
   *
   * If the authorization request uses OpenID4VP and included presentation definitions,
   * a `presentationExchange` property will be defined with credentials that satisfy the
   * incoming request. When `presentationExchange` is present, you MUST supply `presentationExchange`
   * when calling `acceptSiopAuthorizationRequest` as well.
   *
   * @param requestJwtOrUri JWT or an SIOPv2 request URI
   * @returns the resolved and verified authentication request.
   */
  public async resolveSiopAuthorizationRequest(
    requestJwtOrUri: string,
    options: OpenId4VcSiopResolveAuthorizationRequestOptions = {}
  ) {
    return this.openId4VcSiopHolderService.resolveAuthorizationRequest(this.agentContext, requestJwtOrUri, options)
  }

  /**
   * Accepts the authentication request after it has been resolved and verified with {@link resolveSiopAuthorizationRequest}.
   *
   * If the resolved authorization request included a `presentationExchange` property, you MUST supply `presentationExchange`
   * in the `options` parameter.
   *
   * If no `presentationExchange` property is present, you MUST supply `openIdTokenIssuer` in the `options` parameter.
   */
  public async acceptSiopAuthorizationRequest(options: OpenId4VcSiopAcceptAuthorizationRequestOptions) {
    return await this.openId4VcSiopHolderService.acceptAuthorizationRequest(this.agentContext, options)
  }

  /**
   * Automatically select credentials from available credentials for a request. Can be called after calling
   * @see resolveSiopAuthorizationRequest.
   */
  public selectCredentialsForRequest(credentialsForRequest: DifPexCredentialsForRequest) {
    return this.difPresentationExchangeService.selectCredentialsForRequest(credentialsForRequest)
  }

  public async resolveIssuerMetadata(credentialIssuer: string): Promise<OpenId4VciMetadata> {
    return await this.openId4VciHolderService.resolveIssuerMetadata(this.agentContext, credentialIssuer)
  }

  /**
   * Resolves a credential offer given as credential offer URL, or issuance initiation URL,
   * into a unified format with metadata.
   *
   * @param credentialOffer the credential offer to resolve
   * @returns The uniform credential offer payload, the issuer metadata, protocol version, and the offered credentials with metadata.
   */
  public async resolveCredentialOffer(credentialOffer: string) {
    return await this.openId4VciHolderService.resolveCredentialOffer(this.agentContext, credentialOffer)
  }

  /**
   * This function is to be used to receive an credential in OpenID4VCI using the Authorization Code Flow.
   *
   * Not to be confused with the {@link resolveSiopAuthorizationRequest}, which is only used for SIOP requests.
   *
   * It will generate an authorization session based on the provided options.
   *
   * There are two possible flows:
   * - Oauth2Recirect: an authorization request URI is returend which can be used to obtain the authorization code.
   *   This needs to be done manually (e.g. by opening a browser window)
   * - PresentationDuringIssuance: an openid4vp presentation request needs to be handled. A oid4vpRequestUri is returned
   *   which can be parsed using `resolveSiopAuthorizationRequest`. After the presentation session has been completed,
   *   the resulting `presentationDuringIssuanceSession` can be used to obtain an authorization code
   *
   * Authorization to request credentials can be requested via authorization_details or scopes.
   * This function automatically generates the authorization_details for all offered credentials.
   * If scopes are provided, the provided scopes are sent alongside the authorization_details.
   *
   * @param resolvedCredentialOffer Obtained through @see resolveCredentialOffer
   * @param authCodeFlowOptions
   * @returns The authorization request URI alongside the code verifier and original @param authCodeFlowOptions
   */
  public async resolveIssuanceAuthorizationRequest(
    resolvedCredentialOffer: OpenId4VciResolvedCredentialOffer,
    authCodeFlowOptions: OpenId4VciAuthCodeFlowOptions
  ) {
    return await this.openId4VciHolderService.resolveAuthorizationRequest(
      this.agentContext,
      resolvedCredentialOffer,
      authCodeFlowOptions
    )
  }

  /**
   * Retrieve an authorization code using an `presentationDuringIssuanceSession`.
   *
   * The authorization code can be exchanged for an `accessToken` @see requestToken
   */
  public async retrieveAuthorizationCodeUsingPresentation(
    options: OpenId4VciRetrieveAuthorizationCodeUsingPresentationOptions
  ) {
    return await this.openId4VciHolderService.retrieveAuthorizationCodeUsingPresentation(this.agentContext, options)
  }

  /**
   * Requests the token to be used for credential requests.
   */
  public async requestToken(options: OpenId4VciRequestTokenOptions): Promise<OpenId4VciRequestTokenResponse> {
    const { accessTokenResponse, dpop } = await this.openId4VciHolderService.requestAccessToken(
      this.agentContext,
      options
    )

    return { accessToken: accessTokenResponse.access_token, cNonce: accessTokenResponse.c_nonce, dpop }
  }

  /**
   * Request a set of credentials from the credential isser.
   * Can be used with both the pre-authorized code flow and the authorization code flow.
   */
  public async requestCredentials(options: OpenId4VciRequestCredentialOptions) {
    const { resolvedCredentialOffer, cNonce, accessToken, dpop, clientId, ...credentialRequestOptions } = options

    return this.openId4VciHolderService.acceptCredentialOffer(this.agentContext, {
      resolvedCredentialOffer,
      acceptCredentialOfferOptions: credentialRequestOptions,
      accessToken,
      cNonce,
      dpop,
      clientId,
    })
  }

  /**
   * Send a notification event to the credential issuer
   */
  public async sendNotification(options: OpenId4VciSendNotificationOptions) {
    return this.openId4VciHolderService.sendNotification(this.agentContext, options)
  }

  public async resolveOpenIdFederationChains(options: OpenId4VcSiopResolveTrustChainsOptions) {
    return this.openId4VcSiopHolderService.resolveOpenIdFederationChains(this.agentContext, options)
  }
}
