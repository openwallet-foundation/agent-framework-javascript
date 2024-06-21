import type { AnonCredsClaimRecord } from './credential'
import type { W3cAnonCredsCredentialMetadata } from './metadata'
import type { AnonCredsCredentialInfo, AnonCredsSchema } from '../models'
import type { AnonCredsCredentialRecord } from '../repository'
import type { StoreCredentialOptions } from '../services'
import type { DefaultW3cCredentialTags, W3cCredentialSubject } from '@credo-ts/core'

import { CredoError, W3cCredentialRecord, utils } from '@credo-ts/core'

import { mapAttributeRawValuesToAnonCredsCredentialValues } from './credential'
import {
  getQualifiedDidIndyCredentialDefinition,
  getQualifiedDidIndyDid,
  getQualifiedDidIndyRevocationRegistryDefinition,
  getQualifiedDidIndySchema,
  isUnqualifiedDidIndyCredentialDefinition,
  isUnqualifiedDidIndyRevocationRegistryDefinition,
  isUnqualifiedDidIndySchema,
  isUnqualifiedCredentialDefinitionId,
  isUnqualifiedRevocationRegistryId,
  isIndyDid,
  getUnQualifiedDidIndyDid,
  isUnqualifiedIndyDid,
} from './indyIdentifiers'
import { W3cAnonCredsCredentialMetadataKey } from './metadata'

export type AnonCredsCredentialTags = {
  anonCredsLinkSecretId: string
  anonCredsCredentialRevocationId?: string
  anonCredsMethodName: string

  // the following keys can be used for every `attribute name` in credential.
  [key: `anonCredsAttr::${string}::marker`]: true | undefined
  [key: `anonCredsAttr::${string}::value`]: string | undefined

  anonCredsSchemaName: string
  anonCredsSchemaVersion: string

  anonCredsSchemaId: string
  anonCredsSchemaIssuerId: string
  anonCredsCredentialDefinitionId: string
  anonCredsRevocationRegistryId?: string

  anonCredsUnqualifiedIssuerId?: string
  anonCredsUnqualifiedSchemaId?: string
  anonCredsUnqualifiedSchemaIssuerId?: string
  anonCredsUnqualifiedCredentialDefinitionId?: string
  anonCredsUnqualifiedRevocationRegistryId?: string
}

function anonCredsCredentialInfoFromW3cRecord(
  w3cCredentialRecord: W3cCredentialRecord,
  useUnqualifiedIdentifiers?: boolean
): AnonCredsCredentialInfo {
  if (Array.isArray(w3cCredentialRecord.credential.credentialSubject)) {
    throw new CredoError('Credential subject must be an object, not an array.')
  }

  const anonCredsTags = getAnonCredsTagsFromRecord(w3cCredentialRecord)
  if (!anonCredsTags) throw new CredoError('AnonCreds tags not found on credential record.')

  const anonCredsCredentialMetadata = w3cCredentialRecord.metadata.get<W3cAnonCredsCredentialMetadata>(
    W3cAnonCredsCredentialMetadataKey
  )
  if (!anonCredsCredentialMetadata) throw new CredoError('AnonCreds metadata not found on credential record.')

  const credentialDefinitionId =
    useUnqualifiedIdentifiers && anonCredsTags.anonCredsUnqualifiedCredentialDefinitionId
      ? anonCredsTags.anonCredsUnqualifiedCredentialDefinitionId
      : anonCredsTags.anonCredsCredentialDefinitionId

  const schemaId =
    useUnqualifiedIdentifiers && anonCredsTags.anonCredsUnqualifiedSchemaId
      ? anonCredsTags.anonCredsUnqualifiedSchemaId
      : anonCredsTags.anonCredsSchemaId

  const revocationRegistryId =
    useUnqualifiedIdentifiers && anonCredsTags.anonCredsUnqualifiedRevocationRegistryId
      ? anonCredsTags.anonCredsUnqualifiedRevocationRegistryId
      : anonCredsTags.anonCredsRevocationRegistryId ?? null

  return {
    attributes: (w3cCredentialRecord.credential.credentialSubject.claims as AnonCredsClaimRecord) ?? {},
    credentialId: w3cCredentialRecord.id,
    credentialDefinitionId,
    schemaId,
    revocationRegistryId,
    credentialRevocationId: anonCredsCredentialMetadata.credentialRevocationId ?? null,
    methodName: anonCredsCredentialMetadata.methodName,
    linkSecretId: anonCredsCredentialMetadata.linkSecretId,
    createdAt: w3cCredentialRecord.createdAt,
    updatedAt: w3cCredentialRecord.updatedAt ?? w3cCredentialRecord.createdAt,
  }
}

function anonCredsCredentialInfoFromAnonCredsRecord(
  anonCredsCredentialRecord: AnonCredsCredentialRecord
): AnonCredsCredentialInfo {
  const attributes: { [key: string]: string } = {}
  for (const attribute in anonCredsCredentialRecord.credential) {
    attributes[attribute] = anonCredsCredentialRecord.credential.values[attribute].raw
  }

  return {
    attributes,
    credentialDefinitionId: anonCredsCredentialRecord.credential.cred_def_id,
    credentialId: anonCredsCredentialRecord.credentialId,
    schemaId: anonCredsCredentialRecord.credential.schema_id,
    credentialRevocationId: anonCredsCredentialRecord.credentialRevocationId ?? null,
    revocationRegistryId: anonCredsCredentialRecord.credential.rev_reg_id ?? null,
    methodName: anonCredsCredentialRecord.methodName,
    linkSecretId: anonCredsCredentialRecord.linkSecretId,
    createdAt: anonCredsCredentialRecord.createdAt,
    updatedAt: anonCredsCredentialRecord.updatedAt ?? anonCredsCredentialRecord.createdAt,
  }
}

export function getAnoncredsCredentialInfoFromRecord(
  credentialRecord: W3cCredentialRecord | AnonCredsCredentialRecord,
  useUnqualifiedIdentifiersIfPresent?: boolean
): AnonCredsCredentialInfo {
  if (credentialRecord instanceof W3cCredentialRecord) {
    return anonCredsCredentialInfoFromW3cRecord(credentialRecord, useUnqualifiedIdentifiersIfPresent)
  } else {
    return anonCredsCredentialInfoFromAnonCredsRecord(credentialRecord)
  }
}
export function getAnonCredsTagsFromRecord(record: W3cCredentialRecord) {
  const anoncredsMetadata = record.metadata.get<W3cAnonCredsCredentialMetadata>(W3cAnonCredsCredentialMetadataKey)
  if (!anoncredsMetadata) return undefined

  const tags = record.getTags() as DefaultW3cCredentialTags & Partial<AnonCredsCredentialTags>
  if (
    !tags.anonCredsLinkSecretId ||
    !tags.anonCredsMethodName ||
    !tags.anonCredsSchemaId ||
    !tags.anonCredsSchemaName ||
    !tags.anonCredsSchemaVersion ||
    !tags.anonCredsSchemaIssuerId ||
    !tags.anonCredsCredentialDefinitionId
  ) {
    return undefined
  }

  return Object.fromEntries(
    Object.entries(tags).filter(([key]) => key.startsWith('anonCreds'))
  ) as AnonCredsCredentialTags
}

export function getStoreCredentialOptions(
  options: StoreCredentialOptions,
  indyNamespace?: string
): StoreCredentialOptions {
  const {
    credentialRequestMetadata,
    credentialDefinitionId,
    schema,
    credential,
    credentialDefinition,
    revocationRegistry,
  } = options

  const storeCredentialOptions = {
    credentialId: utils.uuid(),
    credentialRequestMetadata,
    credential,
    credentialDefinitionId: isUnqualifiedCredentialDefinitionId(credentialDefinitionId)
      ? getQualifiedDidIndyDid(credentialDefinitionId, indyNamespace as string)
      : credentialDefinitionId,
    credentialDefinition: isUnqualifiedDidIndyCredentialDefinition(credentialDefinition)
      ? getQualifiedDidIndyCredentialDefinition(credentialDefinition, indyNamespace as string)
      : credentialDefinition,
    schema: isUnqualifiedDidIndySchema(schema) ? getQualifiedDidIndySchema(schema, indyNamespace as string) : schema,
    revocationRegistry: revocationRegistry?.definition
      ? {
          definition: isUnqualifiedDidIndyRevocationRegistryDefinition(revocationRegistry.definition)
            ? getQualifiedDidIndyRevocationRegistryDefinition(revocationRegistry.definition, indyNamespace as string)
            : revocationRegistry.definition,
          id: isUnqualifiedRevocationRegistryId(revocationRegistry.id)
            ? getQualifiedDidIndyDid(revocationRegistry.id, indyNamespace as string)
            : revocationRegistry.id,
        }
      : undefined,
  }

  return storeCredentialOptions
}

export function getW3cRecordAnonCredsTags(options: {
  credentialSubject: W3cCredentialSubject
  issuerId: string
  schemaId: string
  schema: Omit<AnonCredsSchema, 'attrNames'>
  credentialDefinitionId: string
  revocationRegistryId?: string
  credentialRevocationId?: string
  linkSecretId: string
  methodName: string
}) {
  const {
    credentialSubject,
    issuerId,
    schema,
    schemaId,
    credentialDefinitionId,
    revocationRegistryId,
    credentialRevocationId,
    linkSecretId,
    methodName,
  } = options

  const anonCredsCredentialRecordTags: AnonCredsCredentialTags = {
    anonCredsLinkSecretId: linkSecretId,
    anonCredsCredentialDefinitionId: credentialDefinitionId,
    anonCredsSchemaId: schemaId,
    anonCredsSchemaName: schema.name,
    anonCredsSchemaIssuerId: schema.issuerId,
    anonCredsSchemaVersion: schema.version,
    anonCredsMethodName: methodName,
    anonCredsRevocationRegistryId: revocationRegistryId,
    anonCredsCredentialRevocationId: credentialRevocationId,
    ...((isIndyDid(issuerId) || isUnqualifiedIndyDid(issuerId)) && {
      anonCredsUnqualifiedIssuerId: getUnQualifiedDidIndyDid(issuerId),
      anonCredsUnqualifiedCredentialDefinitionId: getUnQualifiedDidIndyDid(credentialDefinitionId),
      anonCredsUnqualifiedSchemaId: getUnQualifiedDidIndyDid(schemaId),
      anonCredsUnqualifiedSchemaIssuerId: getUnQualifiedDidIndyDid(schema.issuerId),
      anonCredsUnqualifiedRevocationRegistryId: revocationRegistryId
        ? getUnQualifiedDidIndyDid(revocationRegistryId)
        : undefined,
    }),
  }

  const values = mapAttributeRawValuesToAnonCredsCredentialValues(
    (credentialSubject.claims as AnonCredsClaimRecord) ?? {}
  )

  for (const [key, value] of Object.entries(values)) {
    anonCredsCredentialRecordTags[`anonCredsAttr::${key}::value`] = value.raw
    anonCredsCredentialRecordTags[`anonCredsAttr::${key}::marker`] = true
  }

  return anonCredsCredentialRecordTags
}
