import type { JsonObject, SingleOrArray, W3cIssuerOptions } from '@credo-ts/core'
import type { CredentialFormat } from '../CredentialFormat'

export interface JsonCredential {
  '@context': Array<string> | JsonObject
  id?: string
  type: Array<string>
  issuer: string | W3cIssuerOptions
  issuanceDate: string
  expirationDate?: string
  credentialSubject: SingleOrArray<JsonObject>
  [key: string]: unknown
}

/**
 * Format for creating a jsonld proposal, offer or request.
 */
export interface JsonLdCredentialDetailFormat {
  credential: JsonCredential
  options: {
    proofPurpose: string
    proofType: string
  }
}

// use empty object in the acceptXXX jsonld format interface so we indicate that
// the jsonld format service needs to be invoked
type EmptyObject = Record<string, never>

/**
 * Format for accepting a jsonld credential request. Optionally allows the verification
 * method to use to sign the credential.
 */
export interface JsonLdAcceptRequestFormat {
  verificationMethod?: string
}

export interface JsonLdCredentialFormat extends CredentialFormat {
  formatKey: 'jsonld'
  credentialRecordType: 'w3c'
  credentialFormats: {
    createProposal: JsonLdCredentialDetailFormat
    acceptProposal: EmptyObject
    createOffer: JsonLdCredentialDetailFormat
    acceptOffer: EmptyObject
    createRequest: JsonLdCredentialDetailFormat
    acceptRequest: JsonLdAcceptRequestFormat
  }
  formatData: {
    proposal: JsonLdFormatDataCredentialDetail
    offer: JsonLdFormatDataCredentialDetail
    request: JsonLdFormatDataCredentialDetail
    credential: JsonLdFormatDataVerifiableCredential
  }
}

/**
 * Represents a signed verifiable credential. Only meant to be used for credential
 * format data interfaces.
 */
export interface JsonLdFormatDataVerifiableCredential extends JsonCredential {
  proof: {
    type: string
    proofPurpose: string
    verificationMethod: string
    created: string
    domain?: string
    challenge?: string
    jws?: string
    proofValue?: string
    nonce?: string
    [key: string]: unknown
  }
}

/**
 * Represents the jsonld credential detail. Only meant to be used for credential
 * format data interfaces.
 */
export interface JsonLdFormatDataCredentialDetail {
  credential: JsonCredential
  options: JsonLdFormatDataCredentialDetailOptions
}

/**
 * Represents the jsonld credential detail options. Only meant to be used for credential
 * format data interfaces.
 */
export interface JsonLdFormatDataCredentialDetailOptions {
  proofPurpose: string
  proofType: string
  created?: string
  domain?: string
  challenge?: string
  credentialStatus?: {
    type: string
    [key: string]: unknown
  }
}
