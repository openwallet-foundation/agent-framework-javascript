import type { AnonCredsHolderService } from '../../services'
import type { W3cAnonCredsCredentialMetadata } from '../../utils/metadata'
import type { AgentContext, BaseAgent } from '@credo-ts/core'

import { CacheModuleConfig, CredoError, W3cCredentialRepository, W3cCredentialService } from '@credo-ts/core'
import { CredentialRepository } from '@credo-ts/didcomm'

import { AnonCredsCredentialRepository, type AnonCredsCredentialRecord } from '../../repository'
import { AnonCredsHolderServiceSymbol } from '../../services'
import { fetchCredentialDefinition } from '../../utils/anonCredsObjects'
import {
  getIndyNamespaceFromIndyDid,
  getQualifiedDidIndyDid,
  getUnqualifiedRevocationRegistryDefinitionId,
  isIndyDid,
  isUnqualifiedCredentialDefinitionId,
  isUnqualifiedIndyDid,
  parseIndyRevocationRegistryId,
} from '../../utils/indyIdentifiers'
import { W3cAnonCredsCredentialMetadataKey } from '../../utils/metadata'
import { getW3cRecordAnonCredsTags } from '../../utils/w3cAnonCredsUtils'

async function getIndyNamespace(
  agentContext: AgentContext,
  legacyCredentialDefinitionId: string,
  legacyIssuerId: string
) {
  const cacheModuleConfig = agentContext.dependencyManager.resolve(CacheModuleConfig)
  const cache = cacheModuleConfig.cache

  const indyCacheKey = `IndyVdrPoolService:${legacyIssuerId}`
  const sovCacheKey = `IndySdkPoolService:${legacyIssuerId}`

  const cachedNymResponse: Record<string, string> | null =
    (await cache.get(agentContext, indyCacheKey)) ?? (await cache.get(agentContext, sovCacheKey))

  if (!cachedNymResponse?.indyNamespace || typeof cachedNymResponse?.indyNamespace !== 'string') {
    const credentialDefinitionReturn = await fetchCredentialDefinition(agentContext, legacyCredentialDefinitionId)
    const namespace = credentialDefinitionReturn.indyNamespace

    if (!namespace) {
      throw new CredoError(
        'Could not determine the indyNamespace required for storing anoncreds in the new w3c format.'
      )
    }

    return namespace
  } else {
    return cachedNymResponse.indyNamespace
  }
}

async function migrateLegacyToW3cCredential(agentContext: AgentContext, legacyRecord: AnonCredsCredentialRecord) {
  const legacyTags = legacyRecord.getTags()

  let indyNamespace: string | undefined
  let qualifiedSchemaId: string
  let qualifiedSchemaIssuerId: string
  let qualifiedCredentialDefinitionId: string
  let qualifiedIssuerId: string
  let qualifiedRevocationRegistryId: string | undefined

  if (
    !isUnqualifiedCredentialDefinitionId(legacyTags.credentialDefinitionId) &&
    !isUnqualifiedIndyDid(legacyTags.issuerId)
  ) {
    if (isIndyDid(legacyTags.issuerId)) {
      indyNamespace = getIndyNamespaceFromIndyDid(legacyTags.issuerId)
    }
  } else {
    indyNamespace = await getIndyNamespace(agentContext, legacyTags.credentialDefinitionId, legacyTags.issuerId)
  }

  if (indyNamespace) {
    qualifiedCredentialDefinitionId = getQualifiedDidIndyDid(legacyTags.credentialDefinitionId, indyNamespace)
    qualifiedIssuerId = getQualifiedDidIndyDid(legacyTags.issuerId, indyNamespace)
    qualifiedRevocationRegistryId = legacyTags.revocationRegistryId
      ? getQualifiedDidIndyDid(legacyTags.revocationRegistryId, indyNamespace)
      : undefined
    qualifiedSchemaId = getQualifiedDidIndyDid(legacyTags.schemaId, indyNamespace)
    qualifiedSchemaIssuerId = getQualifiedDidIndyDid(legacyTags.schemaIssuerId, indyNamespace)
  } else {
    qualifiedCredentialDefinitionId = legacyTags.credentialDefinitionId
    qualifiedIssuerId = legacyTags.issuerId
    qualifiedRevocationRegistryId = legacyTags.revocationRegistryId
    qualifiedSchemaId = legacyTags.schemaId
    qualifiedSchemaIssuerId = legacyTags.schemaIssuerId
  }

  const anonCredsHolderService =
    agentContext.dependencyManager.resolve<AnonCredsHolderService>(AnonCredsHolderServiceSymbol)
  const w3cJsonLdCredential = await anonCredsHolderService.legacyToW3cCredential(agentContext, {
    credential: legacyRecord.credential,
    issuerId: qualifiedIssuerId,
  })

  if (Array.isArray(w3cJsonLdCredential.credentialSubject)) {
    throw new CredoError('Credential subject must be an object, not an array.')
  }

  const anonCredsTags = getW3cRecordAnonCredsTags({
    credentialSubject: w3cJsonLdCredential.credentialSubject,
    issuerId: w3cJsonLdCredential.issuerId,
    schemaId: qualifiedSchemaId,
    schema: {
      issuerId: qualifiedSchemaIssuerId,
      name: legacyTags.schemaName,
      version: legacyTags.schemaVersion,
    },
    credentialRevocationId: legacyTags.credentialRevocationId,
    revocationRegistryId: qualifiedRevocationRegistryId,
    credentialDefinitionId: qualifiedCredentialDefinitionId,
    linkSecretId: legacyTags.linkSecretId,
    methodName: legacyTags.methodName,
  })

  const w3cCredentialService = agentContext.dependencyManager.resolve(W3cCredentialService)
  const w3cCredentialRecord = await w3cCredentialService.storeCredential(agentContext, {
    credential: w3cJsonLdCredential,
  })

  for (const [key, meta] of Object.entries(legacyRecord.metadata.data)) {
    w3cCredentialRecord.metadata.set(key, meta)
  }

  const anonCredsCredentialMetadata: W3cAnonCredsCredentialMetadata = {
    credentialRevocationId: anonCredsTags.anonCredsCredentialRevocationId,
    linkSecretId: anonCredsTags.anonCredsLinkSecretId,
    methodName: anonCredsTags.anonCredsMethodName,
  }

  w3cCredentialRecord.setTags(anonCredsTags)
  w3cCredentialRecord.metadata.set(W3cAnonCredsCredentialMetadataKey, anonCredsCredentialMetadata)

  const w3cCredentialRepository = agentContext.dependencyManager.resolve(W3cCredentialRepository)
  await w3cCredentialRepository.update(agentContext, w3cCredentialRecord)

  // Find the credential exchange record bound to this anoncreds credential and update it to point to the newly created w3c record
  const credentialExchangeRepository = agentContext.dependencyManager.resolve(CredentialRepository)
  const [relatedCredentialExchangeRecord] = await credentialExchangeRepository.findByQuery(agentContext, {
    credentialIds: [legacyRecord.credentialId],
  })

  if (relatedCredentialExchangeRecord) {
    // Replace the related binding by the new one
    const credentialBindingIndex = relatedCredentialExchangeRecord.credentials.findIndex(
      (binding) => binding.credentialRecordId === legacyRecord.credentialId
    )
    if (credentialBindingIndex !== -1) {
      relatedCredentialExchangeRecord.credentials[credentialBindingIndex] = {
        credentialRecordType: 'w3c',
        credentialRecordId: w3cCredentialRecord.id,
      }

      // If using Indy dids, store both qualified/unqualified revRegId forms
      // to allow retrieving it from revocation notification service
      if (legacyTags.revocationRegistryId && indyNamespace) {
        const { credentialDefinitionTag, namespaceIdentifier, revocationRegistryTag, schemaSeqNo } =
          parseIndyRevocationRegistryId(legacyTags.revocationRegistryId)

        relatedCredentialExchangeRecord.setTags({
          anonCredsRevocationRegistryId: getQualifiedDidIndyDid(legacyTags.revocationRegistryId, indyNamespace),
          anonCredsUnqualifiedRevocationRegistryId: getUnqualifiedRevocationRegistryDefinitionId(
            namespaceIdentifier,
            schemaSeqNo,
            credentialDefinitionTag,
            revocationRegistryTag
          ),
        })
      }

      await credentialExchangeRepository.update(agentContext, relatedCredentialExchangeRecord)
    }
  }
}

/**
 * Stores all anoncreds credentials in the new w3c format
 */
export async function storeAnonCredsInW3cFormatV0_5<Agent extends BaseAgent>(agent: Agent) {
  agent.config.logger.info('Migration of legacy AnonCreds records to the new W3C format version 0.5')

  const anoncredsRepository = agent.dependencyManager.resolve(AnonCredsCredentialRepository)

  agent.config.logger.debug(`Fetching all anoncreds credential records from storage`)
  const records = await anoncredsRepository.getAll(agent.context)

  agent.config.logger.debug(`Found a total of ${records.length} legacy anonCreds credential records to update.`)

  for (const record of records) {
    agent.config.logger.debug(
      `Re-saving anonCreds credential record with id ${record.id} in the new w3c format, and deleting the legacy record`
    )
    try {
      await migrateLegacyToW3cCredential(agent.context, record)
      await anoncredsRepository.delete(agent.context, record)
      agent.config.logger.debug(
        `Successfully migrated w3c credential record with id ${record.id} to storage version 0.5`
      )
    } catch (error) {
      agent.config.logger.error(
        `Failed to migrate w3c credential record with id ${record.id} to storage version 0.5`,
        error
      )
    }
  }
}
