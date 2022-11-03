import type { Attachment } from '../../../decorators/attachment/Attachment'
import type { IndyRevocationInterval } from '../../credentials'
import type { GetRequestedCredentialsConfig } from '../models'
import type { PresentationPreview } from '../protocol/v1/models/V1PresentationPreview'
import type { ProofExchangeRecord } from '../repository'
import type {
  ProofAttributeInfo,
  ProofPredicateInfo,
  ProofRequest,
  RequestedAttribute,
  RequestedPredicate,
} from './indy/models'

export interface IndyRequestProofFormat {
  name: string
  version: string
  nonce: string
  nonRevoked?: IndyRevocationInterval
  ver?: '1.0' | '2.0'
  requestedAttributes?: Record<string, ProofAttributeInfo> | Map<string, ProofAttributeInfo>
  requestedPredicates?: Record<string, ProofPredicateInfo> | Map<string, ProofPredicateInfo>
  proofRequest?: ProofRequest
}

export interface IndyVerifyProofFormat {
  proofJson: Attachment
  proofRequest: Attachment
}

export interface IndyPresentationProofFormat {
  requestedAttributes?: Record<string, RequestedAttribute>
  requestedPredicates?: Record<string, RequestedPredicate>
  selfAttestedAttributes?: Record<string, string>
}

export interface GetRequestedCredentialsFormat {
  attachment: Attachment
  presentationProposal?: PresentationPreview
  config?: GetRequestedCredentialsConfig
}

export interface IndyProofRequestFromProposalOptions {
  proofRecord: ProofExchangeRecord
  name?: string
  version?: string
  nonce?: string
}
