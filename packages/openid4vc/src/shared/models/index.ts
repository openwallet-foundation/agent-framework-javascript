import type { AccessTokenResponse } from '@animo-id/oauth2'
import type {
  CredentialConfigurationSupported,
  CredentialConfigurationSupportedWithFormats,
  CredentialIssuerMetadata,
  CredentialIssuerMetadataDisplayEntry,
  CredentialOfferPreAuthorizedCodeGrantTxCode,
  CredentialRequest,
  CredentialRequestFormatSpecific,
  CredentialRequestWithFormats,
  IssuerMetadataResult,
  ParseCredentialRequestReturn,
  CredentialOfferObject,
} from '@animo-id/oid4vci'
import type {
  VerifiedAuthorizationRequest,
  AuthorizationRequestPayload,
  AuthorizationResponsePayload,
  IDTokenPayload,
} from '@sphereon/did-auth-siop'

export { preAuthorizedCodeGrantIdentifier, authorizationCodeGrantIdentifier } from '@animo-id/oauth2'

export type OpenId4VciCredentialConfigurationSupportedWithFormats = CredentialConfigurationSupportedWithFormats
export type OpenId4VciCredentialConfigurationSupported = CredentialConfigurationSupported

export type OpenId4VciCredentialConfigurationsSupported = Record<string, OpenId4VciCredentialConfigurationSupported>
export type OpenId4VciCredentialConfigurationsSupportedWithFormats = Record<
  string,
  OpenId4VciCredentialConfigurationSupportedWithFormats
>

export type OpenId4VciAccessTokenResponse = AccessTokenResponse
export type OpenId4VciMetadata = IssuerMetadataResult

export type OpenId4VciTxCode = CredentialOfferPreAuthorizedCodeGrantTxCode
export type OpenId4VciCredentialIssuerMetadata = CredentialIssuerMetadata

export type OpenId4VciParsedCredentialRequest = ParseCredentialRequestReturn
export type OpenId4VciCredentialRequestFormatSpecific = CredentialRequestFormatSpecific

export type OpenId4VciCredentialIssuerMetadataDisplay = CredentialIssuerMetadataDisplayEntry

export type OpenId4VciCredentialRequest = CredentialRequest
export type OpenId4VciCredentialRequestWithFormats = CredentialRequestWithFormats

export type OpenId4VciCredentialOfferPayload = CredentialOfferObject

export type OpenId4VcSiopVerifiedAuthorizationRequest = VerifiedAuthorizationRequest
export type OpenId4VcSiopAuthorizationRequestPayload = AuthorizationRequestPayload
export type OpenId4VcSiopAuthorizationResponsePayload = AuthorizationResponsePayload
export type OpenId4VcSiopIdTokenPayload = IDTokenPayload

export * from './OpenId4VcJwtIssuer'
export * from './CredentialHolderBinding'
export * from './OpenId4VciCredentialFormatProfile'
export * from './OpenId4VciAuthorizationServerConfig'
