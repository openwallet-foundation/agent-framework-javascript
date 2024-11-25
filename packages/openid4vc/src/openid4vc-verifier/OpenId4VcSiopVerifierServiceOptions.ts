import type { OpenId4VcVerificationSessionRecord, OpenId4VcVerifierRecordProps } from './repository'
import type {
  OpenId4VcIssuerX5c,
  OpenId4VcJwtIssuer,
  OpenId4VcSiopAuthorizationResponsePayload,
  OpenId4VcSiopIdTokenPayload,
} from '../shared'
import type {
  DifPresentationExchangeDefinition,
  DifPresentationExchangeSubmission,
  DifPresentationExchangeDefinitionV2,
  VerifiablePresentation,
  DcqlQuery,
  DcqlPresentation,
  DifPexPresentationWithDescriptor,
  DcqlPresentationResult,
} from '@credo-ts/core'

export type ResponseMode = 'direct_post' | 'direct_post.jwt'

export interface OpenId4VcSiopCreateAuthorizationRequestOptions {
  /**
   * Signing information for the request JWT. This will be used to sign the request JWT
   * and to set the client_id and client_id_scheme for registration of client_metadata.
   *
   * For x5c signer's the issuer value can be omitted as it can be derived from the authorization response endpoint.
   */
  requestSigner:
    | Exclude<OpenId4VcJwtIssuer, OpenId4VcIssuerX5c>
    | (Omit<OpenId4VcIssuerX5c, 'issuer'> & { issuer?: string })

  /**
   * Whether to reuqest an ID Token. Enabled by defualt when `presentationExchange` is not provided,
   * disabled by default when `presentationExchange` is provided.
   */
  idToken?: boolean

  /**
   * A DIF Presentation Definition (v2) can be provided to request a Verifiable Presentation using OpenID4VP.
   */
  presentationExchange?: {
    definition: DifPresentationExchangeDefinitionV2
  }

  /**
   * A Digital Credentials Query Language (DCQL) can be provided to request the presentation of a Verifiable Credentials.
   */
  dcql?: {
    query: DcqlQuery
  }

  /**
   * The response mode to use for the authorization request.
   * @default to `direct_post`.
   *
   * With response_mode `direct_post` the response will be posted directly to the `response_uri` provided in the request.
   * With response_mode `direct_post.jwt` the response will be `signed` `encrypted` or `signed and encrypted` and then posted to the `response_uri` provided in the request.
   */
  responseMode?: ResponseMode
}

export interface OpenId4VcSiopVerifyAuthorizationResponseOptions {
  /**
   * The authorization response received from the OpenID Provider (OP).
   */
  authorizationResponse: OpenId4VcSiopAuthorizationResponsePayload
}

export interface OpenId4VcSiopCreateAuthorizationRequestReturn {
  authorizationRequest: string
  verificationSession: OpenId4VcVerificationSessionRecord
}

export interface OpenId4VcSiopVerifiedAuthorizationResponsePresentationExchange {
  submission: DifPresentationExchangeSubmission
  definition: DifPresentationExchangeDefinition
  presentations: Array<VerifiablePresentation>

  descriptors: DifPexPresentationWithDescriptor[]
}

export interface OpenId4VcSiopVerifiedAuthorizationResponseDcql {
  presentation: DcqlPresentation
  presentationResult: DcqlPresentationResult
}

/**
 * Either `idToken` and/or `presentationExchange` will be present.
 */
export interface OpenId4VcSiopVerifiedAuthorizationResponse {
  idToken?: {
    payload: OpenId4VcSiopIdTokenPayload
  }

  presentationExchange?: OpenId4VcSiopVerifiedAuthorizationResponsePresentationExchange

  dcql?: OpenId4VcSiopVerifiedAuthorizationResponseDcql
}

/**
 * Verifier metadata that will be send when creating a request
 */
export interface OpenId4VcSiopVerifierClientMetadata {
  client_name?: string
  logo_uri?: string
}

export interface OpenId4VcSiopCreateVerifierOptions {
  /**
   * Id of the verifier, not the id of the verifier record. Will be exposed publicly
   */
  verifierId?: string

  /**
   * Optional client metadata that will be included in requests
   */
  clientMetadata?: OpenId4VcSiopVerifierClientMetadata
}

export type OpenId4VcUpdateVerifierRecordOptions = Pick<OpenId4VcVerifierRecordProps, 'verifierId' | 'clientMetadata'>
