import type {
  OpenId4VcCredentialHolderBinding,
  OpenId4VciAccessTokenResponse,
  OpenId4VciCredentialConfigurationsSupportedWithFormats,
} from '../shared'
import type { CredentialOfferObject, IssuerMetadataResult } from '@animo-id/oid4vci'
import type { AgentContext, JwaSignatureAlgorithm, Jwk, KeyType, VerifiableCredential } from '@credo-ts/core'

import { AuthorizationFlow as OpenId4VciAuthorizationFlow } from '@animo-id/oid4vci'

import { OpenId4VciCredentialFormatProfile } from '../shared/models/OpenId4VciCredentialFormatProfile'

export { OpenId4VciAuthorizationFlow }

export type OpenId4VciSupportedCredentialFormats =
  | OpenId4VciCredentialFormatProfile.JwtVcJson
  | OpenId4VciCredentialFormatProfile.JwtVcJsonLd
  | OpenId4VciCredentialFormatProfile.SdJwtVc
  | OpenId4VciCredentialFormatProfile.LdpVc
  | OpenId4VciCredentialFormatProfile.MsoMdoc

export const openId4VciSupportedCredentialFormats: OpenId4VciSupportedCredentialFormats[] = [
  OpenId4VciCredentialFormatProfile.JwtVcJson,
  OpenId4VciCredentialFormatProfile.JwtVcJsonLd,
  OpenId4VciCredentialFormatProfile.SdJwtVc,
  OpenId4VciCredentialFormatProfile.LdpVc,
  OpenId4VciCredentialFormatProfile.MsoMdoc,
]

export interface OpenId4VciDpopRequestOptions {
  jwk: Jwk
  alg: JwaSignatureAlgorithm
  nonce?: string
}

/**
 * 'credential_accepted' The Credential was successfully stored in the Wallet.
 * 'credential_deleted' when the unsuccessful Credential issuance was caused by a user action.
 * 'credential_failure' otherwise.
 */
export type OpenId4VciNotificationEvent = 'credential_accepted' | 'credential_failure' | 'credential_deleted'

export type OpenId4VciRequestTokenResponse = {
  accessToken: string
  cNonce?: string
  dpop?: OpenId4VciDpopRequestOptions

  accessTokenResponse: OpenId4VciAccessTokenResponse
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type UnionToArrayUnion<T> = T extends any ? T[] : never

export interface OpenId4VciCredentialResponse {
  credentialConfigurationId: string
  credentials: UnionToArrayUnion<VerifiableCredential>
  notificationId?: string
}

export interface OpenId4VciResolvedCredentialOffer {
  metadata: IssuerMetadataResult
  credentialOfferPayload: CredentialOfferObject

  /**
   * Offered credential configurations with known formats
   */
  offeredCredentialConfigurations: OpenId4VciCredentialConfigurationsSupportedWithFormats
}

export type OpenId4VciResolvedAuthorizationRequest =
  | {
      oid4vpRequestUrl: string
      authorizationFlow: OpenId4VciAuthorizationFlow.PresentationDuringIssuance
      authSession: string
    }
  | {
      authorizationRequestUrl: string
      authorizationFlow: OpenId4VciAuthorizationFlow.Oauth2Redirect
      codeVerifier?: string
    }

export interface OpenId4VciSendNotificationOptions {
  metadata: IssuerMetadataResult

  notificationId: string

  /**
   * The access token obtained through @see requestToken
   */
  accessToken: string

  /**
   * The notification event
   *
   * 'credential_accepted' The Credential was successfully stored in the Wallet.
   * 'credential_deleted' when the unsuccessful Credential issuance was caused by a user action.
   * 'credential_failure' otherwise.
   */
  notificationEvent: OpenId4VciNotificationEvent

  dpop?: OpenId4VciDpopRequestOptions
}

export interface OpenId4VcAuthorizationCodeTokenRequestOptions {
  resolvedCredentialOffer: OpenId4VciResolvedCredentialOffer
  code: string
  clientId: string
  codeVerifier?: string
  redirectUri?: string

  txCode?: never
}

export interface OpenId4VciPreAuthorizedTokenRequestOptions {
  resolvedCredentialOffer: OpenId4VciResolvedCredentialOffer
  txCode?: string

  code?: undefined
}

export type OpenId4VciTokenRequestOptions =
  | OpenId4VciPreAuthorizedTokenRequestOptions
  | OpenId4VcAuthorizationCodeTokenRequestOptions

export interface OpenId4VciRetrieveAuthorizationCodeUsingPresentationOptions {
  resolvedCredentialOffer: OpenId4VciResolvedCredentialOffer
  dpop?: OpenId4VciDpopRequestOptions

  /**
   * auth session returned at an earlier call to the authorization challenge endpoint
   */
  authSession: string

  /**
   * Presentation during issuance session returned by the verifier after submitting a valid presentation
   */
  presentationDuringIssuanceSession?: string
}

export interface OpenId4VciCredentialRequestOptions extends Omit<OpenId4VciAcceptCredentialOfferOptions, 'userPin'> {
  resolvedCredentialOffer: OpenId4VciResolvedCredentialOffer
  accessToken: string
  cNonce?: string
  dpop?: OpenId4VciDpopRequestOptions

  /**
   * The client id used for authorization. Only required if authorization_code flow was used.
   */
  clientId?: string
}

/**
 * Options that are used to accept a credential offer for both the pre-authorized code flow and authorization code flow.
 * NOTE: Merge with @see OpenId4VciCredentialRequestOptions for 0.6
 */
export interface OpenId4VciAcceptCredentialOfferOptions {
  /**
   * This is the list of credentials configuration ids that will be requested from the issuer.
   * Should be a list of ids of the credentials that are included in the credential offer.
   * If not provided all offered credentials will be requested.
   */
  credentialConfigurationIds?: string[]

  /**
   * Whether to request a batch of credentials if supported by the crednetial issuer.
   *
   * You can also provide a number to indicate the batch size. If `true` is provided
   * the max size from the credential issuer will be used.
   *
   * If a number is passed that is higher than the max batch size of the credential issuer,
   * an error will be thrown.
   *
   * @default false
   */
  requestBatch?: boolean | number

  verifyCredentialStatus?: boolean

  /**
   * A list of allowed proof of possession signature algorithms in order of preference.
   *
   * Note that the signature algorithms must be supported by the wallet implementation.
   * Signature algorithms that are not supported by the wallet will be ignored.
   *
   * The proof of possession (pop) signature algorithm is used in the credential request
   * to bind the credential to a did. In most cases the JWA signature algorithm
   * that is used in the pop will determine the cryptographic suite that is used
   * for signing the credential, but this not a requirement for the spec. E.g. if the
   * pop uses EdDsa, the credential will most commonly also use EdDsa, or Ed25519Signature2018/2020.
   */
  allowedProofOfPossessionSignatureAlgorithms?: JwaSignatureAlgorithm[]

  /**
   * A function that should resolve key material for binding the to-be-issued credential
   * to the holder based on the options passed. This key material will be used for signing
   * the proof of possession included in the credential request.
   *
   * This method will be called once for each of the credentials that are included
   * in the credential offer.
   *
   * Based on the credential format, JWA signature algorithm, verification method types
   * and binding methods (did methods, jwk), the resolver must return an object
   * conformant to the `CredentialHolderBinding` interface, which will be used
   * for the proof of possession signature.
   */
  credentialBindingResolver: OpenId4VciCredentialBindingResolver
}

/**
 * Options that are used for the authorization code flow.
 * Extends the pre-authorized code flow options.
 */
export interface OpenId4VciAuthCodeFlowOptions {
  clientId: string
  redirectUri: string
  scope?: string[]
}

export interface OpenId4VciCredentialBindingOptions {
  agentContext: AgentContext

  /**
   * The credential format that will be requested from the issuer.
   * E.g. `jwt_vc` or `ldp_vc`.
   */
  credentialFormat: OpenId4VciSupportedCredentialFormats

  /**
   * The JWA Signature Algorithm(s) that can be used in the proof of possession.
   * This is based on the `allowedProofOfPossessionSignatureAlgorithms` passed
   * to the request credential method, and the supported signature algorithms.
   */
  signatureAlgorithms: JwaSignatureAlgorithm[]

  /**
   * This is a list of verification methods types that are supported
   * for creating the proof of possession signature. The returned
   * verification method type must be of one of these types.
   */
  supportedVerificationMethods: string[]

  /**
   * The key type that can be used to create the proof of possession signature.
   * This is related to the verification method and the signature algorithm, and
   * is added for convenience.
   */
  keyTypes: KeyType[]

  /**
   * The credential type that will be requested from the issuer. This is
   * based on the credential types that are included the credential offer.
   */
  credentialConfigurationId?: string

  /**
   * Whether the issuer supports the `did` cryptographic binding method,
   * indicating they support all did methods. In most cases, they do not
   * support all did methods, and it means we have to make an assumption
   * about the did methods they support.
   *
   * If this value is `false`, the `supportedDidMethods` property will
   * contain a list of supported did methods.
   */
  supportsAllDidMethods: boolean

  /**
   * A list of supported did methods. This is only used if the `supportsAllDidMethods`
   * property is `false`. When this array is populated, the returned verification method
   * MUST be based on one of these did methods.
   *
   * The did methods are returned in the format `did:<method>`, e.g. `did:web`.
   *
   * The value is undefined in the case the supported did methods could not be extracted.
   * This is the case when an inline credential was used, or when the issuer didn't include
   * the supported did methods in the issuer metadata.
   *
   * NOTE: an empty array (no did methods supported) has a different meaning from the value
   * being undefined (the supported did methods could not be extracted). If `supportsAllDidMethods`
   * is true, the value of this property MUST be ignored.
   */
  supportedDidMethods?: string[]

  /**
   * Whether the issuer supports the `jwk` cryptographic binding method,
   * indicating they support proof of possession signatures bound to a jwk.
   */
  supportsJwk: boolean
}

/**
 * The proof of possession verification method resolver is a function that can be passed by the
 * user of the framework and allows them to determine which verification method should be used
 * for the proof of possession signature.
 */
export type OpenId4VciCredentialBindingResolver = (
  options: OpenId4VciCredentialBindingOptions
) => Promise<OpenId4VcCredentialHolderBinding> | OpenId4VcCredentialHolderBinding

/**
 * @internal
 */
export interface OpenId4VciProofOfPossessionRequirements {
  signatureAlgorithms: JwaSignatureAlgorithm[]
  supportedDidMethods?: string[]
  supportsAllDidMethods: boolean
  supportsJwk: boolean
}
