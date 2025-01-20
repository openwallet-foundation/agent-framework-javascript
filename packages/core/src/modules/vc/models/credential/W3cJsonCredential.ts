import type { W3cCredentialStatusOptions } from './w3c-credential-status/W3cCredentialStatus'
import type { JsonObject } from '../../../../types'
import type { SingleOrArray } from '../../../../utils'

export interface W3cJsonCredential {
  '@context': Array<string | JsonObject>
  id?: string
  type: Array<string>
  issuer: string | { id?: string }
  issuanceDate: string
  expirationDate?: string
  credentialSubject: SingleOrArray<JsonObject>
  credentialStatus?: SingleOrArray<W3cCredentialStatusOptions>
  [key: string]: unknown
}
