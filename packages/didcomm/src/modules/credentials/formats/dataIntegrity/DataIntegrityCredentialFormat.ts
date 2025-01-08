import type {
  AnonCredsLinkSecretCredentialRequestOptions as AnonCredsLinkSecretAcceptOfferOptions,
  DataIntegrityCredential,
  DataIntegrityCredentialOffer,
  DataIntegrityCredentialRequest,
  DidCommSignedAttachmentCredentialRequestOptions as DidCommSignedAttachmentAcceptOfferOptions,
  W3C_VC_DATA_MODEL_VERSION,
} from './dataIntegrityExchange'
import type { JsonObject, W3cCredential } from '@credo-ts/core'
import type { CredentialFormat } from '../CredentialFormat'

export interface AnonCredsLinkSecretCreateOfferOptions {
  credentialDefinitionId: string
  revocationRegistryDefinitionId?: string
  revocationRegistryIndex?: number
}

export interface DidCommSignedAttachmentCreateOfferOptions {
  didMethodsSupported?: string[]
  algsSupported?: string[]
}

export interface DataIntegrityAcceptOfferFormat {
  dataModelVersion?: W3C_VC_DATA_MODEL_VERSION
  didCommSignedAttachment?: DidCommSignedAttachmentAcceptOfferOptions
  anonCredsLinkSecret?: AnonCredsLinkSecretAcceptOfferOptions
}

/**
 * This defines the module payload for calling CredentialsApi.offerCredential
 */
export interface DataIntegrityOfferCredentialFormat {
  credential: W3cCredential | JsonObject
  bindingRequired: boolean
  anonCredsLinkSecretBinding?: AnonCredsLinkSecretCreateOfferOptions
  didCommSignedAttachmentBinding?: DidCommSignedAttachmentCreateOfferOptions
}

/**
 * This defines the module payload for calling CredentialsApi.acceptRequest
 */
export interface DataIntegrityAcceptRequestFormat {
  credentialSubjectId?: string
  issuerVerificationMethod?: string
}

export interface DataIntegrityCredentialFormat extends CredentialFormat {
  formatKey: 'dataIntegrity'
  credentialRecordType: 'w3c'
  credentialFormats: {
    createProposal: never
    acceptProposal: never
    createOffer: DataIntegrityOfferCredentialFormat
    acceptOffer: DataIntegrityAcceptOfferFormat
    createRequest: never // cannot start from createRequest
    acceptRequest: DataIntegrityAcceptRequestFormat
  }
  formatData: {
    proposal: never
    offer: DataIntegrityCredentialOffer
    request: DataIntegrityCredentialRequest
    credential: DataIntegrityCredential
  }
}
