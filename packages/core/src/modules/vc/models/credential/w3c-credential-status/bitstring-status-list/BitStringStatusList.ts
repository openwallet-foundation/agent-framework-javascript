import { Type } from 'class-transformer'
import { IsEnum, IsNumber, IsString } from 'class-validator'

import { JsonLdCredentialDetail, W3cCredentialSubject } from '../../../../../..'
import { W3cCredential, W3cCredentialOptions } from '../../W3cCredential'
import { W3cCredentialStatus } from '../W3cCredentialStatus'

// The purpose can be anything apart from this as well
export enum BitstringStatusListCredentialStatusPurpose {
  Revocation = 'revocation',
  Suspension = 'suspension',
}

export interface BitStringStatusListMessageOptions {
  // a string representing the hexadecimal value of the status prefixed with 0x
  status: string
  // a string used by software developers to assist with debugging which SHOULD NOT be displayed to end users
  message?: string
  [key: string]: unknown
}

export class BitStringStatusListMessage {
  public constructor(options: BitStringStatusListMessageOptions) {
    if (options) {
      this.status = options.status
      this.message = options.message
    }
  }

  @IsString()
  public status!: string

  @IsString()
  public message?: string;

  [key: string]: unknown | undefined
}

/**
 * Status list Entry, used to check status of a credential being issued or verified during presentaton.
 *
 * @see https://www.w3.org/TR/vc-bitstring-status-list/#bitstringstatuslistentry
 */
export class BitStringStatusListEntry extends W3cCredentialStatus {
  public constructor(options: IBitStringStatusListEntryOptions) {
    super({ ...options, type: BitStringStatusListEntry.type })

    if (options) {
      this.statusPurpose = options.statusPurpose
      this.statusListCredential = options.statusListCredential
      this.statusListIndex = options.statusListIndex

      if (options.statusSize) this.statusSize = options.statusSize
      if (options.statusMessage) this.statusMessage = options.statusMessage
    }
  }
  public static type = 'BitstringStatusListEntry'

  @IsEnum(BitstringStatusListCredentialStatusPurpose)
  @IsString()
  public statusPurpose!: BitstringStatusListCredentialStatusPurpose

  @IsString()
  public statusListIndex!: string

  @IsString()
  public statusListCredential!: string

  @IsNumber()
  public statusSize?: number

  @Type(() => BitStringStatusListMessage)
  public statusMessage?: BitStringStatusListStatusMessage[]
}

export interface BitStringStatusListStatusMessage {
  // a string representing the hexadecimal value of the status prefixed with 0x
  status: string
  // a string used by software developers to assist with debugging which SHOULD NOT be displayed to end users
  message?: string
  // We can have some key value pairs as well
  [key: string]: unknown
}

export interface IBitStringStatusListEntryOptions {
  id: string
  type: 'BitstringStatusListEntry'
  statusPurpose: BitstringStatusListCredentialStatusPurpose
  // Unique identifier for specific credential
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
  statusMessage?: BitStringStatusListStatusMessage[]
  // An implementer MAY include the statusReference property. If present, its value MUST be a URL or an array of URLs [URL] which dereference to material related to the status
  statusReference?: string | string[]
}

export class BitStringStatusListCredentialStatus extends W3cCredential {
  public credentialStatus?: BitStringStatusListEntry | undefined
}

export class BitStringStatusListCredentialDetail extends JsonLdCredentialDetail {
  public credential!: BitStringStatusListCredentialStatus
}

/**
 * StatusListCredential describes the format of the verifiable credential that encapsulates the status list.
 *
 * @see https://www.w3.org/TR/vc-bitstring-status-list/#bitstringstatuslistcredential
 */
export class BitStringStatusListCredential extends W3cCredential {
  public constructor(options: IBitStringStatusListCredentialOptions) {
    super({
      ...options,
      type: BitStringStatusListCredential.type,
    })

    if (options) {
      this.credentialSubject = options.credentialSubject
    }
  }
  public static type = ['VerifiableCredential', 'BitstringStatusListCredential']

  @IsString()
  public credentialSubject!: BitStringStatusListCredentialSubject
}

export interface IBitStringStatusListCredentialOptions extends Omit<W3cCredentialOptions, 'credentialStatus'> {
  type: ['VerifiableCredential', 'BitstringStatusListCredential']
  credentialSubject: BitStringStatusListCredentialSubject
}

// Define an interface for `credentialSubject`
export interface BitStringStatusListCredentialSubject extends W3cCredentialSubject {
  type: 'BitstringStatusList'
  statusPurpose: BitstringStatusListCredentialStatusPurpose
  encodedList: string
}

// // Define an interface for the `credential` object that uses `CredentialSubject`
// export interface Credential {
//   credentialSubject: CredentialSubject
// }

// // Use the `Credential` interface within `BitStringStatusListCredential`
// export interface BitStringStatusListCredential {
//   credential: Credential
// }
