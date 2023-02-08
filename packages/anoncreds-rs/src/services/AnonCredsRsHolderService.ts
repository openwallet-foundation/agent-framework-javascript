import type {
  AnonCredsHolderService,
  AnonCredsProof,
  CreateCredentialRequestOptions,
  CreateCredentialRequestReturn,
  CreateProofOptions,
  GetCredentialOptions,
  StoreCredentialOptions,
  GetCredentialsForProofRequestOptions,
  GetCredentialsForProofRequestReturn,
  AnonCredsCredentialInfo,
  CreateLinkSecretOptions,
  CreateLinkSecretReturn,
  AnonCredsProofRequestRestriction,
  AnonCredsRequestedAttribute,
  AnonCredsRequestedPredicate,
  AnonCredsCredential,
} from '@aries-framework/anoncreds'
import type { AgentContext, Query } from '@aries-framework/core'
import type { CredentialEntry, CredentialProve } from '@hyperledger/anoncreds-shared'

import {
  AnonCredsSchemaRepository,
  AnonCredsCredentialRecord,
  AnonCredsLinkSecretRepository,
  AnonCredsCredentialRepository,
} from '@aries-framework/anoncreds'
import {
  CredentialRequestMetadata,
  Credential,
  CredentialDefinition,
  CredentialOffer,
  CredentialRequest,
  CredentialRevocationState,
  MasterSecret,
  Presentation,
  PresentationRequest,
  RevocationRegistryDefinition,
  RevocationStatusList,
  Schema,
} from '@hyperledger/anoncreds-shared'

import { uuid } from '../../../core/src/utils/uuid'
import { AnonCredsRsError } from '../errors/AnonCredsRsError'

export class AnonCredsRsHolderService implements AnonCredsHolderService {
  public async createLinkSecret(
    agentContext: AgentContext,
    options?: CreateLinkSecretOptions
  ): Promise<CreateLinkSecretReturn> {
    try {
      return {
        linkSecretId: options?.linkSecretId ?? uuid(),
        linkSecretValue: JSON.parse(MasterSecret.create().toJson()).value.ms,
      }
    } catch (error) {
      agentContext.config.logger.error(`Error creating Link Secret`, {
        error,
      })
      throw new AnonCredsRsError('Error creating Link Secret', { cause: error })
    }
  }

  public async createProof(agentContext: AgentContext, options: CreateProofOptions): Promise<AnonCredsProof> {
    const { credentialDefinitions, proofRequest, requestedCredentials, schemas } = options

    try {
      const rsCredentialDefinitions: Record<string, CredentialDefinition> = {}
      for (const credDefId in credentialDefinitions) {
        rsCredentialDefinitions[credDefId] = CredentialDefinition.load(JSON.stringify(credentialDefinitions[credDefId]))
      }

      const rsSchemas: Record<string, Schema> = {}
      for (const schemaId in schemas) {
        rsSchemas[schemaId] = Schema.load(JSON.stringify(schemas[schemaId]))
      }

      const credentialRepository = agentContext.dependencyManager.resolve(AnonCredsCredentialRepository)

      // Cache retrieved credentials in order to minimize storage calls
      const retrievedCredentials = new Map<string, AnonCredsCredentialRecord>()

      const credentialEntryFromAttribute = async (
        attribute: AnonCredsRequestedAttribute | AnonCredsRequestedPredicate
      ): Promise<{ linkSecretId: string; credentialEntry: CredentialEntry }> => {
        let credentialRecord = retrievedCredentials.get(attribute.credentialId)
        if (!credentialRecord) {
          credentialRecord = await credentialRepository.getByCredentialId(agentContext, attribute.credentialId)
          retrievedCredentials.set(attribute.credentialId, credentialRecord)
        }

        const credential = Credential.load(JSON.stringify(credentialRecord.credential))

        const revocationRegistryDefinitionId = credential.revocationRegistryId
        const revocationRegistryIndex = credential.revocationRegistryIndex

        // TODO: Check if credential has a revocation registry id (check response from anoncreds-rs API, as it is
        // sending back a mandatory string in Credential.revocationRegistryId)
        const timestamp = attribute.timestamp

        let revocationState
        if (timestamp) {
          if (revocationRegistryIndex) {
            if (!options.revocationRegistries[revocationRegistryDefinitionId]) {
              throw new AnonCredsRsError(`Revocation Registry ${revocationRegistryDefinitionId} not found`)
            }

            const { definition, tailsFilePath } = options.revocationRegistries[revocationRegistryDefinitionId]

            const revocationRegistryDefinition = RevocationRegistryDefinition.load(JSON.stringify(definition))
            revocationState = CredentialRevocationState.create({
              revocationRegistryIndex,
              revocationRegistryDefinition,
              tailsPath: tailsFilePath,
              revocationStatusList: RevocationStatusList.create({
                issuanceByDefault: true,
                revocationRegistryDefinition,
                revocationRegistryDefinitionId,
                timestamp,
              }),
            })
          }
        }
        return {
          linkSecretId: credentialRecord.linkSecretId,
          credentialEntry: {
            credential,
            revocationState,
            timestamp,
          },
        }
      }

      const credentialsProve: CredentialProve[] = []
      const credentials: { linkSecretId: string; credentialEntry: CredentialEntry }[] = []

      let entryIndex = 0
      for (const referent in requestedCredentials.requestedAttributes) {
        const attribute = requestedCredentials.requestedAttributes[referent]
        credentials.push(await credentialEntryFromAttribute(attribute))
        credentialsProve.push({ entryIndex, isPredicate: false, referent, reveal: attribute.revealed })
        entryIndex = entryIndex + 1
      }

      for (const referent in requestedCredentials.requestedPredicates) {
        const predicate = requestedCredentials.requestedPredicates[referent]
        credentials.push(await credentialEntryFromAttribute(predicate))
        credentialsProve.push({ entryIndex, isPredicate: true, referent, reveal: true })
        entryIndex = entryIndex + 1
      }

      // Get all requested credentials and take linkSecret. If it's not the same for every credential, throw error
      const linkSecretsMatch = credentials.every((item) => item.linkSecretId === credentials[0].linkSecretId)
      if (!linkSecretsMatch) {
        throw new AnonCredsRsError('All credentials in a Proof should have been issued using the same Link Secret')
      }

      const linkSecretRecord = await agentContext.dependencyManager
        .resolve(AnonCredsLinkSecretRepository)
        .getByLinkSecretId(agentContext, credentials[0].linkSecretId)

      if (!linkSecretRecord.value) {
        throw new AnonCredsRsError('Link Secret value not stored')
      }

      const presentation = Presentation.create({
        credentialDefinitions: rsCredentialDefinitions,
        schemas: rsSchemas,
        presentationRequest: PresentationRequest.load(JSON.stringify(proofRequest)),
        credentials: credentials.map((entry) => entry.credentialEntry),
        credentialsProve,
        selfAttest: requestedCredentials.selfAttestedAttributes,
        masterSecret: MasterSecret.load(JSON.stringify({ value: { ms: linkSecretRecord.value } })),
      })

      return JSON.parse(presentation.toJson())
    } catch (error) {
      agentContext.config.logger.error(`Error creating AnonCreds Proof`, {
        error,
        proofRequest,
        requestedCredentials,
      })
      throw new AnonCredsRsError(`Error creating proof: ${error}`, { cause: error })
    }
  }

  public async createCredentialRequest(
    agentContext: AgentContext,
    options: CreateCredentialRequestOptions
  ): Promise<CreateCredentialRequestReturn> {
    const { credentialDefinition, credentialOffer } = options
    try {
      const linkSecretRepository = agentContext.dependencyManager.resolve(AnonCredsLinkSecretRepository)

      // If a link secret is specified, use it. Otherwise, attempt to use default link secret
      const linkSecretRecord = options.linkSecretId
        ? await linkSecretRepository.getByLinkSecretId(agentContext, options.linkSecretId)
        : await linkSecretRepository.findDefault(agentContext)

      if (!linkSecretRecord) {
        // No default link secret: TODO: shall we create a new one?
        throw new AnonCredsRsError('Link Secret not found')
      }

      const { credentialRequest, credentialRequestMetadata } = CredentialRequest.create({
        credentialDefinition: CredentialDefinition.load(JSON.stringify(credentialDefinition)),
        credentialOffer: CredentialOffer.load(JSON.stringify(credentialOffer)),
        masterSecret: MasterSecret.load(JSON.stringify({ value: { ms: linkSecretRecord.value } })),
        masterSecretId: linkSecretRecord.linkSecretId,
      })

      return {
        credentialRequest: JSON.parse(credentialRequest.toJson()),
        credentialRequestMetadata: JSON.parse(credentialRequestMetadata.toJson()),
      }
    } catch (error) {
      throw new AnonCredsRsError(`Error creating credential request: ${error}`, { cause: error })
    }
  }

  public async storeCredential(agentContext: AgentContext, options: StoreCredentialOptions): Promise<string> {
    const linkSecretRecord = await agentContext.dependencyManager
      .resolve(AnonCredsLinkSecretRepository)
      .getByLinkSecretId(agentContext, options.credentialRequestMetadata.master_secret_name)

    // TODO: In order to support all tags from AnonCreds spec (section 9.1.1 about Restrictions), we need to tag
    // the credential records with some properties of the schema it is based on. This means that Schema should have been
    // previously retrieved and present in the storage. Can we assume that at this point it will be stored?
    const schemaRecord = await agentContext.dependencyManager
      .resolve(AnonCredsSchemaRepository)
      .getBySchemaId(agentContext, options.credential.schema_id)

    const revocationRegistryDefinition = options.revocationRegistry?.definition
      ? RevocationRegistryDefinition.load(JSON.stringify(options.revocationRegistry.definition))
      : undefined

    const credentialId = options.credentialId ?? uuid()

    const processedCredential = Credential.load(JSON.stringify(options.credential)).process({
      credentialDefinition: CredentialDefinition.load(JSON.stringify(options.credentialDefinition)),
      credentialRequestMetadata: CredentialRequestMetadata.load(JSON.stringify(options.credentialRequestMetadata)),
      masterSecret: MasterSecret.load(JSON.stringify({ value: { ms: linkSecretRecord.value } })),
      revocationRegistryDefinition,
    })

    const credentialRepository = agentContext.dependencyManager.resolve(AnonCredsCredentialRepository)

    await credentialRepository.save(
      agentContext,
      new AnonCredsCredentialRecord({
        credential: JSON.parse(processedCredential.toJson()) as AnonCredsCredential,
        credentialId,
        linkSecretId: linkSecretRecord.linkSecretId,
        issuerId: options.credentialDefinition.issuerId,
        schemaName: schemaRecord.schema.name,
        schemaIssuerId: schemaRecord.schema.issuerId,
        schemaVersion: schemaRecord.schema.version,
      })
    )

    return credentialId
  }

  public async getCredential(
    agentContext: AgentContext,
    options: GetCredentialOptions
  ): Promise<AnonCredsCredentialInfo> {
    const credentialRecord = await agentContext.dependencyManager
      .resolve(AnonCredsCredentialRepository)
      .getByCredentialId(agentContext, options.credentialId)

    const attributes: { [key: string]: string } = {}
    for (const attribute in credentialRecord.credential.values) {
      attributes[attribute] = credentialRecord.credential.values[attribute].raw
    }
    return {
      attributes,
      credentialDefinitionId: credentialRecord.credential.cred_def_id,
      credentialId: credentialRecord.credentialId,
      schemaId: credentialRecord.credential.schema_id,
      credentialRevocationId: credentialRecord.credentialRevocationId,
      revocationRegistryId: credentialRecord.credential.rev_reg_id,
    }
  }

  public async deleteCredential(agentContext: AgentContext, credentialId: string): Promise<void> {
    const credentialRepository = agentContext.dependencyManager.resolve(AnonCredsCredentialRepository)
    const credentialRecord = await credentialRepository.getByCredentialId(agentContext, credentialId)
    await credentialRepository.delete(agentContext, credentialRecord)
  }

  public async getCredentialsForProofRequest(
    agentContext: AgentContext,
    options: GetCredentialsForProofRequestOptions
  ): Promise<GetCredentialsForProofRequestReturn> {
    const proofRequest = options.proofRequest
    const referent = options.attributeReferent

    const requestedAttribute =
      proofRequest.requested_attributes[referent] ?? proofRequest.requested_predicates[referent]

    if (!requestedAttribute) {
      throw new AnonCredsRsError(`Referent not found in proof request`)
    }
    const attributes = requestedAttribute.name ? [requestedAttribute.name] : requestedAttribute.names

    const restrictionQuery = requestedAttribute.restrictions
      ? this.queryFromRestrictions(requestedAttribute.restrictions)
      : undefined

    const query: Query<AnonCredsCredentialRecord> = {
      attributes,
      ...restrictionQuery,
      ...options.extraQuery,
    }

    const credentials = await agentContext.dependencyManager
      .resolve(AnonCredsCredentialRepository)
      .findByQuery(agentContext, query)

    return credentials.map((credentialRecord) => {
      const attributes: { [key: string]: string } = {}
      for (const attribute in credentialRecord.credential.values) {
        attributes[attribute] = credentialRecord.credential.values[attribute].raw
      }
      return {
        credentialInfo: {
          attributes,
          credentialDefinitionId: credentialRecord.credential.cred_def_id,
          credentialId: credentialRecord.credentialId,
          schemaId: credentialRecord.credential.schema_id,
          credentialRevocationId: credentialRecord.credentialRevocationId,
          revocationRegistryId: credentialRecord.credential.rev_reg_id,
        },
        interval: proofRequest.non_revoked,
      }
    })
  }

  private queryFromRestrictions(restrictions: AnonCredsProofRequestRestriction[]) {
    const query: Query<AnonCredsCredentialRecord>[] = []

    for (const restriction of restrictions) {
      const queryElements: Query<AnonCredsCredentialRecord>[] = []

      if (restriction.cred_def_id) {
        queryElements.push({ credentialDefinitionId: restriction.cred_def_id })
      }

      if (restriction.issuer_id || restriction.issuer_did) {
        queryElements.push({ issuerId: restriction.issuer_id ?? restriction.issuer_did })
      }
      // TODO queryElement.revocationRegistryId = restriction.rev_reg_id

      if (restriction.schema_id) {
        queryElements.push({ schemaId: restriction.schema_id })
      }

      if (restriction.schema_issuer_id || restriction.schema_issuer_did) {
        queryElements.push({ schemaIssuerId: restriction.schema_issuer_id ?? restriction.schema_issuer_did })
      }

      if (restriction.schema_name) {
        queryElements.push({ schemaName: restriction.schema_name })
      }

      if (restriction.schema_version) {
        queryElements.push({ schemaVersion: restriction.schema_version })
      }

      if (queryElements.length > 0) {
        query.push(queryElements.length === 1 ? queryElements[0] : { $or: queryElements })
      }
    }

    return query.length === 1 ? query[0] : { $and: query }
  }
}
