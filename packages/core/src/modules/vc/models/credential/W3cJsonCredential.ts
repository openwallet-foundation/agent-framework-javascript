import type { CredentialStatus } from './W3cJsonCredentialStatus'
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
  credentialStatus?: SingleOrArray<CredentialStatus>
  [key: string]: unknown
}
