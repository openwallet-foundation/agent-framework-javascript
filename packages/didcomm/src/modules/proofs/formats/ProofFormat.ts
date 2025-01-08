/**
 * Get the payload for a specific method from a list of ProofFormat interfaces and a method
 *
 * @example
 * ```
 *
 * type CreateRequestProofFormats = ProofFormatPayload<[IndyProofFormat, PresentationExchangeProofFormat], 'createRequest'>
 *
 * // equal to
 * type CreateRequestProofFormats = {
 *  indy: {
 *   // ... params for indy create request ...
 *  },
 *  presentationExchange: {
 *  // ... params for pex create request ...
 *  }
 * }
 * ```
 */
export type ProofFormatPayload<PFs extends ProofFormat[], M extends keyof ProofFormat['proofFormats']> = {
  [ProofFormat in PFs[number] as ProofFormat['formatKey']]?: ProofFormat['proofFormats'][M]
}

/**
 * Get the input or output for the getCredentialsForRequest and selectCredentialsForRequest method with specific format data
 *
 * @example
 * ```
 *
 * type SelectedCredentialsForRequest = ProofFormatCredentialForRequestPayload<[IndyProofFormat, PresentationExchangeProofFormat], 'selectCredentialsForRequest', 'output'>
 *
 * // equal to
 * type SelectedCredentialsForRequest = {
 *  indy: {
 *   // ... return value for indy selected credentials ...
 *  },
 *  presentationExchange: {
 *  // ... return value for presentation exchange selected credentials ...
 *  }
 * }
 * ```
 */
export type ProofFormatCredentialForRequestPayload<
  PFs extends ProofFormat[],
  M extends 'selectCredentialsForRequest' | 'getCredentialsForRequest',
  IO extends 'input' | 'output'
> = {
  [ProofFormat in PFs[number] as ProofFormat['formatKey']]?: ProofFormat['proofFormats'][M][IO]
}

export interface ProofFormat {
  formatKey: string // e.g. 'presentationExchange', cannot be shared between different formats

  proofFormats: {
    createProposal: unknown
    acceptProposal: unknown
    createRequest: unknown
    acceptRequest: unknown

    getCredentialsForRequest: {
      input: unknown
      output: unknown
    }
    selectCredentialsForRequest: {
      input: unknown
      output: unknown
    }
  }
  formatData: {
    proposal: unknown
    request: unknown
    presentation: unknown
  }
}
