import type {
  AnonCredsAcceptOfferFormat,
  AnonCredsAcceptProposalFormat,
  AnonCredsAcceptRequestFormat,
  AnonCredsCredentialProposalFormat,
  AnonCredsOfferCredentialFormat,
  AnonCredsProposeCredentialFormat,
} from './AnonCredsCredentialFormat'
import type { AnonCredsCredential, AnonCredsCredentialOffer, AnonCredsCredentialRequest } from '../models'
import type { CredentialFormat } from '@credo-ts/didcomm'

// Legacy indy credential proposal doesn't support _id properties
export type LegacyIndyCredentialProposalFormat = Omit<
  AnonCredsCredentialProposalFormat,
  'schema_issuer_id' | 'issuer_id'
>

/**
 * This defines the module payload for calling CredentialsApi.createProposal
 * or CredentialsApi.negotiateOffer
 *
 * NOTE: This doesn't include the `issuerId` and `schemaIssuerId` properties that are present in the newer format.
 */
export type LegacyIndyProposeCredentialFormat = Omit<AnonCredsProposeCredentialFormat, 'schemaIssuerId' | 'issuerId'>

export interface LegacyIndyCredentialRequest extends AnonCredsCredentialRequest {
  // prover_did is optional in AnonCreds credential request, but required in legacy format
  prover_did: string
}

export interface LegacyIndyCredentialFormat extends CredentialFormat {
  formatKey: 'indy'

  credentialRecordType: 'w3c'

  // credential formats are the same as the AnonCreds credential format
  credentialFormats: {
    // The createProposal interface is different between the interfaces
    createProposal: LegacyIndyProposeCredentialFormat
    acceptProposal: AnonCredsAcceptProposalFormat
    createOffer: AnonCredsOfferCredentialFormat
    acceptOffer: AnonCredsAcceptOfferFormat
    createRequest: never // cannot start from createRequest
    acceptRequest: AnonCredsAcceptRequestFormat
  }

  // Format data is based on RFC 0592
  // https://github.com/hyperledger/aries-rfcs/tree/main/features/0592-indy-attachments
  formatData: {
    proposal: LegacyIndyCredentialProposalFormat
    offer: AnonCredsCredentialOffer
    request: LegacyIndyCredentialRequest
    credential: AnonCredsCredential
  }
}
