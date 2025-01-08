import type {
  AnonCredsNonRevokedInterval,
  AnonCredsPredicateType,
  AnonCredsProof,
  AnonCredsProofRequest,
  AnonCredsRequestedAttribute,
  AnonCredsRequestedAttributeMatch,
  AnonCredsRequestedPredicate,
  AnonCredsRequestedPredicateMatch,
  AnonCredsSelectedCredentials,
} from '../models'
import type { ProofFormat } from '@credo-ts/didcomm'

export interface AnonCredsPresentationPreviewAttribute {
  name: string
  credentialDefinitionId?: string
  mimeType?: string
  value?: string
  referent?: string
}

export interface AnonCredsPresentationPreviewPredicate {
  name: string
  credentialDefinitionId: string
  predicate: AnonCredsPredicateType
  threshold: number
}

/**
 * Interface for creating an anoncreds proof proposal.
 */
export interface AnonCredsProposeProofFormat {
  name?: string
  version?: string
  attributes?: AnonCredsPresentationPreviewAttribute[]
  predicates?: AnonCredsPresentationPreviewPredicate[]
  nonRevokedInterval?: AnonCredsNonRevokedInterval
}

/**
 * Interface for creating an anoncreds proof request.
 */
export interface AnonCredsRequestProofFormat {
  name: string
  version: string
  non_revoked?: AnonCredsNonRevokedInterval
  requested_attributes?: Record<string, AnonCredsRequestedAttribute>
  requested_predicates?: Record<string, AnonCredsRequestedPredicate>
}

/**
 * Interface for getting credentials for an indy proof request.
 */
export interface AnonCredsCredentialsForProofRequest {
  attributes: Record<string, AnonCredsRequestedAttributeMatch[]>
  predicates: Record<string, AnonCredsRequestedPredicateMatch[]>
}

export interface AnonCredsGetCredentialsForProofRequestOptions {
  filterByNonRevocationRequirements?: boolean
}

export interface AnonCredsProofFormat extends ProofFormat {
  formatKey: 'anoncreds'

  proofFormats: {
    createProposal: AnonCredsProposeProofFormat
    acceptProposal: {
      name?: string
      version?: string
    }
    createRequest: AnonCredsRequestProofFormat
    acceptRequest: AnonCredsSelectedCredentials

    getCredentialsForRequest: {
      input: AnonCredsGetCredentialsForProofRequestOptions
      output: AnonCredsCredentialsForProofRequest
    }
    selectCredentialsForRequest: {
      input: AnonCredsGetCredentialsForProofRequestOptions
      output: AnonCredsSelectedCredentials
    }
  }

  formatData: {
    proposal: AnonCredsProofRequest
    request: AnonCredsProofRequest
    presentation: AnonCredsProof
  }
}
