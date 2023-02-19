import type { IndyCredProposeOptions } from './models/IndyCredPropose'
import type { LinkedAttachment } from '../../../../utils/LinkedAttachment'
import type { CredentialPreviewAttributeOptions } from '../../models'
import type { CredentialFormat } from '../CredentialFormat'
import type { Cred, CredOffer, CredReq } from 'indy-sdk'

/**
 * This defines the module payload for calling CredentialsApi.createProposal
 * or CredentialsApi.negotiateOffer
 */
export interface IndyProposeCredentialFormat extends IndyCredProposeOptions {
  attributes?: CredentialPreviewAttributeOptions[]
  linkedAttachments?: LinkedAttachment[]
}

/**
 * This defines the module payload for calling CredentialsApi.acceptProposal
 */
export interface IndyAcceptProposalFormat {
  credentialDefinitionId?: string
  attributes?: CredentialPreviewAttributeOptions[]
  linkedAttachments?: LinkedAttachment[]
}

export interface IndyAcceptOfferFormat {
  holderDid?: string
}

/**
 * This defines the module payload for calling CredentialsApi.offerCredential
 * or CredentialsApi.negotiateProposal
 */
export interface IndyOfferCredentialFormat {
  credentialDefinitionId: string
  attributes: CredentialPreviewAttributeOptions[]
  linkedAttachments?: LinkedAttachment[]
}

export interface IndyCredentialFormat extends CredentialFormat {
  formatKey: 'indy'
  credentialRecordType: 'indy'
  credentialFormats: {
    createProposal: IndyProposeCredentialFormat
    acceptProposal: IndyAcceptProposalFormat
    createOffer: IndyOfferCredentialFormat
    acceptOffer: IndyAcceptOfferFormat
    createRequest: never // cannot start from createRequest
    acceptRequest: Record<string, never> // empty object
  }
  // Format data is based on RFC 0592
  // https://github.com/hyperledger/aries-rfcs/tree/main/features/0592-indy-attachments
  formatData: {
    proposal: {
      schema_issuer_did?: string
      schema_name?: string
      schema_version?: string
      schema_id?: string
      issuer_did?: string
      cred_def_id?: string
    }
    offer: CredOffer
    request: CredReq
    credential: Cred
  }
}
