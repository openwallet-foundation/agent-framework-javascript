import type { SingleOrArray } from '../../../../utils'

export type CredentialStatusType = 'BitstringStatusListEntry'
// The purpose can be anything apart from this as well
export enum CredentialStatusPurpose {
  'revocation' = 'revocation',
  'suspension' = 'suspension',
  'message' = 'message',
}

export interface StatusMessage {
  // a string representing the hexadecimal value of the status prefixed with 0x
  status: string
  // a string used by software developers to assist with debugging which SHOULD NOT be displayed to end users
  message?: string
  // We can have some key value pairs as well
  [key: string]: unknown
}

export interface CredentialStatus {
  id: string
  // Since currenlty we are only trying to support 'BitStringStatusListEntry'
  type: CredentialStatusType
  statusPurpose: CredentialStatusPurpose
  // Unique identifier for the specific credential
  statusListIndex: string
  // Must be url referencing to a VC of type 'BitstringStatusListCredential'
  statusListCredential: string
  // The statusSize indicates the size of the status entry in bits
  statusSize?: number
  // Must be preset if statusPurpose is message
  /**
   * the length of which MUST equal the number of possible status messages indicated by statusSize
   * (e.g., statusMessage array MUST have 2 elements if statusSize has 1 bit,
   * 4 elements if statusSize has 2 bits, 8 elements if statusSize has 3 bits, etc.).
   */
  statusMessage?: StatusMessage[]
  // An implementer MAY include the statusReference property. If present, its value MUST be a URL or an array of URLs [URL] which dereference to material related to the status
  statusReference?: SingleOrArray<string>
}

// Define an interface for `credentialSubject`
export interface CredentialSubject {
  encodedList: string
}

// Define an interface for the `credential` object that uses `CredentialSubject`
export interface Credential {
  credentialSubject: CredentialSubject
}

// Use the `Credential` interface within `BitStringStatusListCredential`
export interface BitStringStatusListCredential {
  credential: Credential
}
