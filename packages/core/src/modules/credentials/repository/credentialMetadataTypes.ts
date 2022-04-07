import type { CredReqMetadata } from 'indy-sdk'

export enum CredentialMetadataKeys {
  IndyCredential = '_internal/indyCredential',
  IndyRequest = '_internal/indyRequest',
}

export type CredentialMetadata = {
  [CredentialMetadataKeys.IndyCredential]: {
    schemaId?: string
    credentialDefinitionId?: string
    revocationRegistryId?: string
    credentialRevocationId?: string
  }
  [CredentialMetadataKeys.IndyRequest]: CredReqMetadata
}
