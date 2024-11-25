import type { OpenId4VcIssuanceSessionRecord, OpenId4VcIssuerRecordProps } from './repository'
import type {
  OpenId4VcSiopCreateAuthorizationRequestReturn,
  OpenId4VcSiopVerifiedAuthorizationResponseDcql,
  OpenId4VcSiopVerifiedAuthorizationResponsePresentationExchange,
  OpenId4VcVerificationSessionRecord,
} from '../openid4vc-verifier'
import type {
  OpenId4VcCredentialHolderBindingWithKey,
  OpenId4VciCredentialConfigurationsSupportedWithFormats,
  OpenId4VciCredentialOfferPayload,
  OpenId4VciCredentialRequest,
  OpenId4VciCredentialRequestFormatSpecific,
  OpenId4VciCredentialIssuerMetadataDisplay,
  OpenId4VciTxCode,
} from '../shared'
import type { OpenId4VciAuthorizationServerConfig } from '../shared/models/OpenId4VciAuthorizationServerConfig'
import type { AccessTokenProfileJwtPayload, TokenIntrospectionResponse } from '@animo-id/oauth2'
import type {
  AgentContext,
  ClaimFormat,
  W3cCredential,
  SdJwtVcSignOptions,
  JwaSignatureAlgorithm,
  MdocSignOptions,
  KeyType,
} from '@credo-ts/core'

export interface OpenId4VciCredentialRequestAuthorization {
  authorizationServer: string
  accessToken: {
    payload: AccessTokenProfileJwtPayload | TokenIntrospectionResponse
    value: string
  }
}

export interface OpenId4VciPreAuthorizedCodeFlowConfig {
  preAuthorizedCode?: string

  /**
   * The user pin required flag indicates whether the user needs to enter a pin to authorize the transaction.
   */
  txCode?: OpenId4VciTxCode

  // OPTIONAL string that the Wallet can use to identify the Authorization Server to use with this grant
  // type when authorization_servers parameter in the Credential Issuer metadata has multiple entries.
  authorizationServerUrl?: string
}

export interface OpenId4VciAuthorizationCodeFlowConfig {
  /**
   * OPTIONAL. String value created by the Credential Issuer and opaque to the Wallet
   * that is used to bind the subsequent Authorization Request with the Credential Issuer
   * to a context set up during previous steps.
   * If not provided, a value will be generated.
   */
  issuerState?: string

  /**
   * OPTIONAL string that the Wallet can use to identify the Authorization Server to use with this grant
   * type when authorization_servers parameter in the Credential Issuer metadata has multiple entries.
   */
  authorizationServerUrl?: string

  /**
   * Whether presentation using OpenID4VP is required as part of the authorization flow. The presentation
   * request will be created dynamically when the wallet initiates the authorization flow using the
   * `getVerificationSessionForIssuanceSessionAuthorization` callback in the issuer module config.
   *
   * You can dynamically create the verification session based on the provided issuace session, or you
   * can have a more generic implementation based on credential configurations and scopes that are being
   * requested.
   *
   * In case this parameter is set to true, `authorizationServerUrl` MUST be undefined or match the
   * `credential_issuer` value, as only Credo can handle this flow.
   *
   * In case this parameter is set to true, and `getVerificationSessionForIssuanceSessionAuthorization` is
   * not configured on the issuer module an error will be thrown.
   *
   * @default false
   */
  requirePresentationDuringIssuance?: boolean
}

interface OpenId4VciCreateCredentialOfferOptionsBase {
  // NOTE: v11 of OID4VCI supports both inline and referenced (to credentials_supported.id) credential offers.
  // In draft 12 the inline credential offers have been removed and to make the migration to v12 easier
  // we only support referenced credentials in an offer
  offeredCredentials: string[]

  /**
   * baseUri for the credential offer uri. By default `openid-credential-offer://` will be used
   * if no value is provided. If a value is provided, make sure it contains the scheme as well as `://`.
   */
  baseUri?: string

  /**
   * @default v1.draft11-13
   */
  version?: 'v1.draft11-13' | 'v1.draft13'
}

export interface OpenId4VciCreateStatelessCredentialOfferOptions extends OpenId4VciCreateCredentialOfferOptionsBase {
  authorizationCodeFlowConfig: Required<Pick<OpenId4VciAuthorizationCodeFlowConfig, 'authorizationServerUrl'>>

  /**
   * For stateless credential offers we need an external authorization server, which also means we need to
   * support `authorization_servers`, therefore only draft 13 offers are supported
   *
   * @default v1.draft13
   */
  version?: 'v1.draft13'
}

export interface OpenId4VciCreateCredentialOfferOptions extends OpenId4VciCreateCredentialOfferOptionsBase {
  preAuthorizedCodeFlowConfig?: OpenId4VciPreAuthorizedCodeFlowConfig
  authorizationCodeFlowConfig?: OpenId4VciAuthorizationCodeFlowConfig

  /**
   * Metadata about the issuance, that will be stored in the issuance session record and
   * passed to the credential request to credential mapper. This can be used to e.g. store an
   * user identifier so user data can be fetched in the credential mapper, or the actual credential
   * data.
   */
  issuanceMetadata?: Record<string, unknown>
}

export interface OpenId4VciCreateCredentialResponseOptions {
  credentialRequest: OpenId4VciCredentialRequest
  authorization: OpenId4VciCredentialRequestAuthorization

  /**
   * You can optionally provide a credential request to credential mapper that will be
   * dynamically invoked to return credential data based on the credential request.
   *
   * If not provided, the `credentialRequestToCredentialMapper` from the agent config
   * will be used.
   */
  credentialRequestToCredentialMapper?: OpenId4VciCredentialRequestToCredentialMapper
}

/**
 * Callback that is called when a verification session needs to be created to complete
 * authorization of credential issuance.
 *
 *
 */
export type OpenId4VciGetVerificationSessionForIssuanceSessionAuthorization = (options: {
  agentContext: AgentContext
  issuanceSession: OpenId4VcIssuanceSessionRecord

  /**
   * The credential configurations for which authorization has been requested based on the **scope**
   * values. It doesn't mean the wallet will request all credentials to be issued.
   */
  requestedCredentialConfigurations: OpenId4VciCredentialConfigurationsSupportedWithFormats

  /**
   * The scopes which were requested and are also present in the credential configurations supported
   * that were offered. It will match with the scope values in the `requestedCredentialConfiguration`
   * parameter
   */
  scopes: string[]
}) => Promise<
  OpenId4VcSiopCreateAuthorizationRequestReturn & {
    /**
     * The scopes which will be granted by successfully completing the verification
     * session.
     *
     * @todo do we need more granular support? I.e. every input descriptor can satisfy a
     * different scope?
     */
    scopes: string[]
  }
>

export interface OpenId4VciCredentialRequestToCredentialMapperOptions {
  agentContext: AgentContext

  /**
   * Authorization associated with the credential request
   */
  authorization: OpenId4VciCredentialRequestAuthorization

  /**
   * If an openid4vp verification was done as part of the authorization flow this parameter will be defined.
   *
   * The contents can be used to populate credential data
   */
  verification?: {
    session: OpenId4VcVerificationSessionRecord
  } & (
    | {
        presentationExchange: OpenId4VcSiopVerifiedAuthorizationResponsePresentationExchange
        dcql?: never
      }
    | {
        dcql: OpenId4VcSiopVerifiedAuthorizationResponseDcql
        presentationExchange?: never
      }
  )

  /**
   * The issuance session associated with the credential request. You can extract the
   * issuance metadata from this record if passed in the offer creation method.
   */
  issuanceSession: OpenId4VcIssuanceSessionRecord

  /**
   * The credential request received from the wallet
   */
  credentialRequest: OpenId4VciCredentialRequest

  /**
   * Contains format specific credential request data. Currently it will
   * always be defined, but may be undefined once `credential_identifier`
   * in the credential request will be supported
   */
  credentialRequestFormat?: OpenId4VciCredentialRequestFormatSpecific

  /**
   * The offer associated with the credential request
   */
  credentialOffer: OpenId4VciCredentialOfferPayload

  /**
   * Verified key binding material entries that should be included in the credential(s)
   * A separate credential should be returned for each holder binding.
   *
   * Can either be bound to did or a JWK (in case of for ex. SD-JWT).
   */
  holderBindings: OpenId4VcCredentialHolderBindingWithKey[]

  /**
   * The credential configurations supported entries from the issuer metadata
   * that were offered and match the incoming request.
   */
  credentialConfigurationsSupported: OpenId4VciCredentialConfigurationsSupportedWithFormats

  /**
   * v13: The ids of the credential configurations that were offered and match the request
   *
   * NOTE: This will probably become a single entry, as it will be matched on id
   */
  credentialConfigurationIds: [string, ...string[]]
}
export type OpenId4VciCredentialRequestToCredentialMapper = (
  options: OpenId4VciCredentialRequestToCredentialMapperOptions
) => Promise<OpenId4VciSignCredentials> | OpenId4VciSignCredentials

export type OpenId4VciSignCredentials =
  | OpenId4VciSignSdJwtCredentials
  | OpenId4VciSignW3cCredentials
  | OpenId4VciSignMdocCredentials

export interface OpenId4VciSignSdJwtCredentials {
  credentialConfigurationId: string
  format: ClaimFormat.SdJwtVc | `${ClaimFormat.SdJwtVc}`
  credentials: SdJwtVcSignOptions[]
}

export interface OpenId4VciSignMdocCredentials {
  credentialConfigurationId: string
  format: ClaimFormat.MsoMdoc | `${ClaimFormat.MsoMdoc}`
  credentials: MdocSignOptions[]
}

export interface OpenId4VciSignW3cCredentials {
  credentialConfigurationId: string
  format: ClaimFormat.JwtVc | `${ClaimFormat.JwtVc}` | ClaimFormat.LdpVc | `${ClaimFormat.LdpVc}`
  credentials: Array<{
    verificationMethod: string
    credential: W3cCredential
  }>
}

export interface OpenId4VciBatchCredentialIssuanceOptions {
  /**
   * The maximum batch size
   */
  batchSize: number
}

export type OpenId4VciCreateIssuerOptions = {
  /**
   * Id of the issuer, not the id of the issuer record. Will be exposed publicly
   */
  issuerId?: string

  /**
   * Key type to use for signing access tokens
   *
   * @default KeyType.Ed25519
   */
  accessTokenSignerKeyType?: KeyType

  display?: OpenId4VciCredentialIssuerMetadataDisplay[]
  authorizationServerConfigs?: OpenId4VciAuthorizationServerConfig[]
  dpopSigningAlgValuesSupported?: [JwaSignatureAlgorithm, ...JwaSignatureAlgorithm[]]
  credentialConfigurationsSupported: OpenId4VciCredentialConfigurationsSupportedWithFormats

  /**
   * Indicate support for batch issuane of credentials
   */
  batchCredentialIssuance?: OpenId4VciBatchCredentialIssuanceOptions
}

export type OpenId4VcUpdateIssuerRecordOptions = Pick<
  OpenId4VcIssuerRecordProps,
  | 'issuerId'
  | 'display'
  | 'dpopSigningAlgValuesSupported'
  | 'credentialConfigurationsSupported'
  | 'batchCredentialIssuance'
>
