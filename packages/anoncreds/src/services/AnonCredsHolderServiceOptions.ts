import type { AnonCredsCredentialInfo, AnonCredsSelectedCredentials } from '../models'
import type {
  AnonCredsCredential,
  AnonCredsCredentialOffer,
  AnonCredsCredentialRequest,
  AnonCredsNonRevokedInterval,
  AnonCredsProofRequest,
} from '../models/exchange'
import type {
  AnonCredsCredentialDefinition,
  AnonCredsRevocationRegistryDefinition,
  AnonCredsSchema,
} from '../models/registry'
import type {
  AnonCredsSchemas,
  AnonCredsCredentialDefinitions,
  AnonCredsRevocationRegistries,
  CredentialWithRevocationMetadata,
} from '../models/utils'
import type { AnonCredsCredentialRequestMetadata } from '../utils/metadata'
import type { W3cJsonLdVerifiableCredential } from '@credo-ts/core'

export interface AnonCredsAttributeInfo {
  name?: string
  names?: string[]
}

export interface CreateProofOptions {
  proofRequest: AnonCredsProofRequest
  selectedCredentials: AnonCredsSelectedCredentials
  schemas: AnonCredsSchemas
  credentialDefinitions: AnonCredsCredentialDefinitions
  revocationRegistries: AnonCredsRevocationRegistries
  useUnqualifiedIdentifiers?: boolean
}

export interface StoreCredentialOptions {
  credential: W3cJsonLdVerifiableCredential | AnonCredsCredential
  credentialRequestMetadata: AnonCredsCredentialRequestMetadata
  credentialDefinition: AnonCredsCredentialDefinition
  schema: AnonCredsSchema
  credentialDefinitionId: string
  credentialId?: string
  revocationRegistry?: {
    id: string
    definition: AnonCredsRevocationRegistryDefinition
  }
}

export interface GetCredentialOptions {
  id: string
  useUnqualifiedIdentifiersIfPresent?: boolean
}

export interface GetCredentialsOptions {
  credentialDefinitionId?: string
  schemaId?: string
  schemaIssuerId?: string
  schemaName?: string
  schemaVersion?: string
  issuerId?: string
  methodName?: string
}

// TODO: Maybe we can make this a bit more specific?
export type WalletQuery = Record<string, unknown>
export interface ReferentWalletQuery {
  [referent: string]: WalletQuery
}

export interface GetCredentialsForProofRequestOptions {
  proofRequest: AnonCredsProofRequest
  attributeReferent: string
  start?: number
  limit?: number
  extraQuery?: ReferentWalletQuery
}

export type GetCredentialsForProofRequestReturn = Array<{
  credentialInfo: AnonCredsCredentialInfo
  interval?: AnonCredsNonRevokedInterval
}>

export interface CreateCredentialRequestOptions {
  credentialOffer: AnonCredsCredentialOffer
  credentialDefinition: AnonCredsCredentialDefinition
  linkSecretId?: string
  useLegacyProverDid?: boolean
}

export interface CreateCredentialRequestReturn {
  credentialRequest: AnonCredsCredentialRequest
  credentialRequestMetadata: AnonCredsCredentialRequestMetadata
}

export interface CreateLinkSecretOptions {
  linkSecretId?: string
}

export interface CreateLinkSecretReturn {
  linkSecretId: string
  linkSecretValue?: string
}

export interface AnonCredsCredentialProve {
  entryIndex: number
  referent: string
  isPredicate: boolean
  reveal: boolean
}

export interface CreateW3cPresentationOptions {
  proofRequest: AnonCredsProofRequest
  linkSecretId: string
  schemas: AnonCredsSchemas
  credentialDefinitions: AnonCredsCredentialDefinitions
  credentialsProve: AnonCredsCredentialProve[]
  credentialsWithRevocationMetadata: CredentialWithRevocationMetadata[]
}

export interface LegacyToW3cCredentialOptions {
  credential: AnonCredsCredential
  issuerId: string
  processOptions?: {
    credentialDefinition: AnonCredsCredentialDefinition
    credentialRequestMetadata: AnonCredsCredentialRequestMetadata
    revocationRegistryDefinition: AnonCredsRevocationRegistryDefinition | undefined
  }
}

export interface W3cToLegacyCredentialOptions {
  credential: W3cJsonLdVerifiableCredential
}
