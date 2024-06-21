import type { W3cAnonCredsCredentialMetadata } from '../../utils/metadata'
import type { AnonCredsCredentialTags } from '../../utils/w3cAnonCredsUtils'
import type {
  AnonCredsCredentialDefinition,
  AnonCredsCredentialInfo,
  AnonCredsCredentialOffer,
  AnonCredsSchema,
} from '@credo-ts/anoncreds'
import type { AgentContext } from '@credo-ts/core'
import type { JsonObject } from '@hyperledger/anoncreds-shared'

import {
  JsonTransformer,
  W3cCredentialRepository,
  W3cCredentialService,
  W3cJsonLdVerifiableCredential,
} from '@credo-ts/core'
import {
  CredentialDefinition,
  CredentialOffer,
  CredentialRequest,
  CredentialRevocationConfig,
  LinkSecret,
  RevocationRegistryDefinition,
  RevocationRegistryDefinitionPrivate,
  RevocationStatusList,
  Schema,
  W3cCredential,
  anoncreds,
} from '@hyperledger/anoncreds-shared'

import { W3cAnonCredsCredentialMetadataKey } from '../../utils/metadata'

/**
 * Creates a valid credential definition and returns its public and
 * private part, including its key correctness proof
 */
export function createCredentialDefinition(options: { attributeNames: string[]; issuerId: string }) {
  const { attributeNames, issuerId } = options

  const schema = Schema.create({
    issuerId,
    attributeNames,
    name: 'schema1',
    version: '1',
  })

  const { credentialDefinition, credentialDefinitionPrivate, keyCorrectnessProof } = CredentialDefinition.create({
    issuerId,
    schema,
    schemaId: 'schema:uri',
    signatureType: 'CL',
    supportRevocation: true, // FIXME: Revocation should not be mandatory but current anoncreds-rs is requiring it
    tag: 'TAG',
  })

  const returnObj = {
    credentialDefinition: credentialDefinition.toJson() as unknown as AnonCredsCredentialDefinition,
    credentialDefinitionPrivate: credentialDefinitionPrivate.toJson() as unknown as JsonObject,
    keyCorrectnessProof: keyCorrectnessProof.toJson() as unknown as JsonObject,
    schema: schema.toJson() as unknown as Schema,
  }

  credentialDefinition.handle.clear()
  credentialDefinitionPrivate.handle.clear()
  keyCorrectnessProof.handle.clear()
  schema.handle.clear()

  return returnObj
}

/**
 * Creates a valid credential offer and returns itsf
 */
export function createCredentialOffer(keyCorrectnessProof: Record<string, unknown>) {
  const credentialOffer = CredentialOffer.create({
    credentialDefinitionId: 'creddef:uri',
    keyCorrectnessProof,
    schemaId: 'schema:uri',
  })
  const credentialOfferJson = credentialOffer.toJson() as unknown as AnonCredsCredentialOffer
  credentialOffer.handle.clear()
  return credentialOfferJson
}

/**
 *
 * @returns Creates a valid link secret value for anoncreds-rs
 */
export function createLinkSecret() {
  return LinkSecret.create()
}

export async function createCredentialForHolder(options: {
  agentContext: AgentContext
  credentialDefinition: JsonObject
  credentialDefinitionPrivate: JsonObject
  keyCorrectnessProof: JsonObject
  schemaId: string
  credentialDefinitionId: string
  attributes: Record<string, string>
  linkSecret: string
  linkSecretId: string
  revocationRegistryDefinitionId: string
}) {
  const {
    credentialDefinition,
    credentialDefinitionPrivate,
    keyCorrectnessProof,
    schemaId,
    credentialDefinitionId,
    attributes,
    linkSecret,
    linkSecretId,
    revocationRegistryDefinitionId,
  } = options

  const credentialOffer = CredentialOffer.create({
    credentialDefinitionId,
    keyCorrectnessProof,
    schemaId,
  })

  const { credentialRequest, credentialRequestMetadata } = CredentialRequest.create({
    entropy: 'some-entropy',
    credentialDefinition,
    credentialOffer,
    linkSecret,
    linkSecretId: linkSecretId,
  })

  const { revocationRegistryDefinition, revocationRegistryDefinitionPrivate, tailsPath } =
    createRevocationRegistryDefinition({
      credentialDefinitionId,
      credentialDefinition,
    })

  const timeCreateRevStatusList = 12
  const revocationStatusList = RevocationStatusList.create({
    credentialDefinition,
    revocationRegistryDefinitionPrivate: new RevocationRegistryDefinitionPrivate(
      revocationRegistryDefinitionPrivate.handle
    ),
    issuerId: credentialDefinition.issuerId as string,
    timestamp: timeCreateRevStatusList,
    issuanceByDefault: true,
    revocationRegistryDefinition: new RevocationRegistryDefinition(revocationRegistryDefinition.handle),
    revocationRegistryDefinitionId: 'mock:uri',
  })

  const credentialObj = W3cCredential.create({
    credentialDefinition,
    credentialDefinitionPrivate,
    credentialOffer,
    credentialRequest,
    attributeRawValues: attributes,
    revocationRegistryId: revocationRegistryDefinitionId,
    revocationStatusList,
    revocationConfiguration: new CredentialRevocationConfig({
      statusList: revocationStatusList,
      registryDefinition: new RevocationRegistryDefinition(revocationRegistryDefinition.handle),
      registryDefinitionPrivate: new RevocationRegistryDefinitionPrivate(revocationRegistryDefinitionPrivate.handle),
      registryIndex: 9,
    }),
  })

  const w3cJsonLdCredential = JsonTransformer.fromJSON(credentialObj.toJson(), W3cJsonLdVerifiableCredential)

  const credentialInfo: Omit<AnonCredsCredentialInfo, 'credentialId'> = {
    attributes,
    credentialDefinitionId,
    linkSecretId,
    schemaId,
    methodName: 'inMemory',
    credentialRevocationId: null,
    revocationRegistryId: null,
    createdAt: new Date('2024-01-01T00:00:00Z'),
    updatedAt: new Date('2024-01-01T00:00:00Z'),
  }
  const returnObj = {
    credential: w3cJsonLdCredential,
    credentialInfo,
    revocationRegistryDefinition,
    tailsPath,
    credentialRequestMetadata,
  }

  credentialObj.handle.clear()
  credentialOffer.handle.clear()
  credentialRequest.handle.clear()
  revocationRegistryDefinitionPrivate.clear()
  revocationStatusList.handle.clear()

  return returnObj
}

export function createRevocationRegistryDefinition(options: {
  credentialDefinitionId: string
  credentialDefinition: Record<string, unknown>
}) {
  const { credentialDefinitionId, credentialDefinition } = options
  const { revocationRegistryDefinition, revocationRegistryDefinitionPrivate } =
    anoncreds.createRevocationRegistryDefinition({
      credentialDefinitionId,
      credentialDefinition: CredentialDefinition.fromJson(credentialDefinition).handle,
      issuerId: credentialDefinition.issuerId as string,
      tag: 'some_tag',
      revocationRegistryType: 'CL_ACCUM',
      maximumCredentialNumber: 10,
    })

  const tailsPath = anoncreds.revocationRegistryDefinitionGetAttribute({
    objectHandle: revocationRegistryDefinition,
    name: 'tails_location',
  })

  return { revocationRegistryDefinition, revocationRegistryDefinitionPrivate, tailsPath }
}

export async function storeCredential(
  agentContext: AgentContext,
  w3cJsonLdCredential: W3cJsonLdVerifiableCredential,
  options: {
    linkSecretId: string
    credentialDefinitionId: string
    schemaId: string
    schema: AnonCredsSchema
  }
) {
  const w3cCredentialService = agentContext.dependencyManager.resolve(W3cCredentialService)
  const record = await w3cCredentialService.storeCredential(agentContext, {
    credential: w3cJsonLdCredential,
  })

  const anonCredsCredentialRecordTags: AnonCredsCredentialTags = {
    anonCredsLinkSecretId: options.linkSecretId,
    anonCredsCredentialDefinitionId: options.credentialDefinitionId,
    anonCredsSchemaId: options.schemaId,
    anonCredsSchemaName: options.schema.name,
    anonCredsSchemaIssuerId: options.schema.issuerId,
    anonCredsSchemaVersion: options.schema.version,
    anonCredsMethodName: 'method',
  }

  const anonCredsCredentialMetadata: W3cAnonCredsCredentialMetadata = {
    credentialRevocationId: anonCredsCredentialRecordTags.anonCredsCredentialRevocationId,
    linkSecretId: anonCredsCredentialRecordTags.anonCredsLinkSecretId,
    methodName: anonCredsCredentialRecordTags.anonCredsMethodName,
  }

  record.setTags(anonCredsCredentialRecordTags)
  record.metadata.set(W3cAnonCredsCredentialMetadataKey, anonCredsCredentialMetadata)

  const w3cCredentialRepository = agentContext.dependencyManager.resolve(W3cCredentialRepository)
  await w3cCredentialRepository.update(agentContext, record)

  return record
}
