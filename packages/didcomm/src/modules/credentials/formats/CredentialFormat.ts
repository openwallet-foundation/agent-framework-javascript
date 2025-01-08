/**
 * Get the payload for a specific method from a list of CredentialFormat interfaces and a method
 *
 * @example
 * ```
 *
 * type CreateOfferCredentialFormats = CredentialFormatPayload<[IndyCredentialFormat, JsonLdCredentialFormat], 'createOffer'>
 *
 * // equal to
 * type CreateOfferCredentialFormats = {
 *  indy: {
 *   // ... params for indy create offer ...
 *  },
 *  jsonld: {
 *  // ... params for jsonld create offer ...
 *  }
 * }
 * ```
 */
export type CredentialFormatPayload<
  CFs extends CredentialFormat[],
  M extends keyof CredentialFormat['credentialFormats']
> = {
  [CredentialFormat in CFs[number] as CredentialFormat['formatKey']]?: CredentialFormat['credentialFormats'][M]
}

export interface CredentialFormat {
  formatKey: string // e.g. 'credentialManifest', cannot be shared between different formats
  credentialRecordType: string // e.g. 'w3c', can be shared between multiple formats
  credentialFormats: {
    createProposal: unknown
    acceptProposal: unknown
    createOffer: unknown
    acceptOffer: unknown
    createRequest: unknown
    acceptRequest: unknown
  }
  formatData: {
    proposal: unknown
    offer: unknown
    request: unknown
    credential: unknown
  }
}
