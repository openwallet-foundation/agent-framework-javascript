import type {
  DifPexInputDescriptorToCredentials,
  DifPexCredentialsForRequest,
  DifPresentationExchangeDefinitionV1,
  W3cJsonPresentation,
} from '@credo-ts/core'

import type { ProofFormat } from '../ProofFormat'

export type DifPresentationExchangeProposal = DifPresentationExchangeDefinitionV1

// eslint-disable-next-line @typescript-eslint/no-empty-interface
export interface DifPexGetCredentialsForProofRequestOptions {}

export type DifPresentationExchangeRequest = {
  options?: {
    challenge?: string
    domain?: string
  }
  presentation_definition: DifPresentationExchangeDefinitionV1
}

export type DifPresentationExchangePresentation =
  | W3cJsonPresentation
  // NOTE: this is not spec compliant, as it doesn't describe how to submit
  // JWT VPs but to support JWT VPs we also allow the value to be a string
  | string

export interface DifPresentationExchangeProofFormat extends ProofFormat {
  formatKey: 'presentationExchange'

  proofFormats: {
    createProposal: {
      presentationDefinition: DifPresentationExchangeDefinitionV1
    }

    acceptProposal: {
      options?: {
        challenge?: string
        domain?: string
      }
    }

    createRequest: {
      presentationDefinition: DifPresentationExchangeDefinitionV1
      options?: {
        challenge?: string
        domain?: string
      }
    }

    acceptRequest: {
      credentials?: DifPexInputDescriptorToCredentials
    }

    getCredentialsForRequest: {
      input: DifPexGetCredentialsForProofRequestOptions
      // Presentation submission details which the options that are available
      output: DifPexCredentialsForRequest
    }

    selectCredentialsForRequest: {
      input: DifPexGetCredentialsForProofRequestOptions
      // Input descriptor to credentials specifically details which credentials
      // should be used for which input descriptor
      output: {
        credentials: DifPexInputDescriptorToCredentials
      }
    }
  }

  formatData: {
    proposal: DifPresentationExchangeProposal
    request: DifPresentationExchangeRequest
    presentation: DifPresentationExchangePresentation
  }
}
