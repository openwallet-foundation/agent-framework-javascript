import type {
  CreateIssueCredentialResponseOptions,
  CreateCredentialOfferAndRequestOptions,
  CredentialOfferAndRequest,
  OfferedCredential,
  CredentialOfferPayloadV1_0_11,
  EndpointConfig,
} from './OpenId4VcIssuerServiceOptions'
import type { Router } from 'express'

import { injectable, AgentContext } from '@aries-framework/core'

import { OpenId4VcIssuerService } from './OpenId4VcIssuerService'

/**
 * @public
 * This class represents the API for interacting with the OpenID4VC Issuer service.
 * It provides methods for creating a credential offer, creating a response to a credential issuance request,
 * and retrieving a credential offer from a URI.
 */
@injectable()
export class OpenId4VcIssuerApi {
  private agentContext: AgentContext
  private openId4VcIssuerService: OpenId4VcIssuerService

  public constructor(agentContext: AgentContext, openId4VcIssuerService: OpenId4VcIssuerService) {
    this.agentContext = agentContext
    this.openId4VcIssuerService = openId4VcIssuerService
  }

  /**
   * Creates a credential offer, and credential offer request.
   * Either the preAuthorizedCodeFlowConfig or the authorizationCodeFlowConfig must be provided.
   *
   * @param  offeredCredentials - The credentials to be offered.
   * @param  options.issuerMetadata - Metadata about the issuer.
   * @param  options.credentialOfferUri - The URI to retrieve the credential offer if the offer is passed by reference.
   * @param  options.scheme - The credential offer request scheme. Default is 'https'.
   * @param  options.baseUri - The base URI of the credential offer request. Default is ''.
   * @param  options.preAuthorizedCodeFlowConfig - The configuration for the pre-authorized code flow. This or the authorizationCodeFlowConfig must be provided.
   * @param  options.authorizationCodeFlowConfig - The configuration for the authorization code flow. This or the preAuthorizedCodeFlowConfig must be provided.
   *
   * @returns Object containing the payload of the credential offer and the credential offer request, which is to be sent to the wallet.
   */
  public async createCredentialOfferAndRequest(
    offeredCredentials: OfferedCredential[],
    options: CreateCredentialOfferAndRequestOptions
  ): Promise<CredentialOfferAndRequest> {
    return await this.openId4VcIssuerService.createCredentialOfferAndRequest(
      this.agentContext,
      offeredCredentials,
      options
    )
  }

  /**
   * This function retrieves a credential offer from a given URI.
   * Retrieving a credential offer from a URI is possible after a credential offer was created with
   * @see createCredentialOfferAndRequest and the credentialOfferUri option.
   *
   * @throws if no credential offer can found for the given URI.
   * @param uri - The URI for which to retrieve the credential offer.
   * @returns The credential offer payload associated with the given URI.
   */
  public async getCredentialOfferFromUri(uri: string): Promise<CredentialOfferPayloadV1_0_11> {
    return await this.openId4VcIssuerService.getCredentialOfferFromUri(uri)
  }

  /**
   * This function creates a response which can be send to the holder after receiving a credential issuance request.
   *
   * @param options.credentialRequest - The credential request, for which to create a response.
   * @param options.credential - The credential to be issued.
   * @param options.issuerMetadata - Metadata about the issuer.
   */
  public async createIssueCredentialResponse(options: CreateIssueCredentialResponseOptions) {
    return await this.openId4VcIssuerService.createIssueCredentialResponse(this.agentContext, options)
  }

  /**
   * Configures the enabled endpoints for the given router, as specified in @link https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html
   *
   * @param router - The router to configure.
   * @param endpointConfig - The endpoint configuration.
   * @returns The configured router.
   */
  public async configureRouter(router: Router, endpointConfig: EndpointConfig) {
    return this.openId4VcIssuerService.configureRouter(this.agentContext, router, endpointConfig)
  }
}