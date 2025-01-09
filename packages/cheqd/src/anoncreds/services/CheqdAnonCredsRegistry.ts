import type { CheqdCreateResourceOptions } from '../../dids'
import type {
  AnonCredsRegistry,
  GetCredentialDefinitionReturn,
  GetRevocationStatusListReturn,
  GetRevocationRegistryDefinitionReturn,
  GetSchemaReturn,
  RegisterCredentialDefinitionOptions,
  RegisterCredentialDefinitionReturn,
  RegisterSchemaReturn,
  RegisterSchemaOptions,
  RegisterRevocationRegistryDefinitionReturn,
  RegisterRevocationStatusListReturn,
  RegisterRevocationRegistryDefinitionOptions,
  RegisterRevocationStatusListOptions,
} from '@credo-ts/anoncreds'
import type { AgentContext } from '@credo-ts/core'

import { CredoError, Hasher, JsonTransformer, TypedArrayEncoder, utils } from '@credo-ts/core'

import { CheqdDidResolver, CheqdDidRegistrar } from '../../dids'
import {
  cheqdAnonCredsResourceTypes,
  cheqdSdkAnonCredsRegistryIdentifierRegex,
  parseCheqdDid,
} from '../utils/identifiers'
import {
  CheqdCredentialDefinition,
  CheqdRevocationRegistryDefinition,
  CheqdRevocationStatusList,
  CheqdSchema,
} from '../utils/transform'

export class CheqdAnonCredsRegistry implements AnonCredsRegistry {
  public methodName = 'cheqd'

  /**
   * This class supports resolving and registering objects with cheqd identifiers.
   * It needs to include support for the schema, credential definition, revocation registry as well
   * as the issuer id (which is needed when registering objects).
   */
  public readonly supportedIdentifier = cheqdSdkAnonCredsRegistryIdentifierRegex

  public async getSchema(agentContext: AgentContext, schemaId: string): Promise<GetSchemaReturn> {
    try {
      const cheqdDidResolver = agentContext.dependencyManager.resolve(CheqdDidResolver)
      const parsedDid = parseCheqdDid(schemaId)
      if (!parsedDid) throw new CredoError(`Invalid schemaId: ${schemaId}`)

      agentContext.config.logger.trace(`Submitting get schema request for schema '${schemaId}' to ledger`)

      const response = await cheqdDidResolver.resolveResource(agentContext, schemaId)
      const schema = JsonTransformer.fromJSON(response.resource, CheqdSchema)

      return {
        schema: {
          attrNames: schema.attrNames,
          name: schema.name,
          version: schema.version,
          issuerId: parsedDid.did,
        },
        schemaId,
        resolutionMetadata: {},
        schemaMetadata: {},
      }
    } catch (error) {
      agentContext.config.logger.error(`Error retrieving schema '${schemaId}'`, {
        error,
        schemaId,
      })

      return {
        schemaId,
        resolutionMetadata: {
          error: 'notFound',
          message: `unable to resolve schema: ${error.message}`,
        },
        schemaMetadata: {},
      }
    }
  }

  public async registerSchema(
    agentContext: AgentContext,
    options: RegisterSchemaOptions
  ): Promise<RegisterSchemaReturn> {
    try {
      const cheqdDidRegistrar = agentContext.dependencyManager.resolve(CheqdDidRegistrar)

      const schema = options.schema
      const schemaResource = {
        id: utils.uuid(),
        name: `${schema.name}-Schema`,
        resourceType: cheqdAnonCredsResourceTypes.schema,
        data: {
          name: schema.name,
          version: schema.version,
          attrNames: schema.attrNames,
        },
        version: schema.version,
      } satisfies CheqdCreateResourceOptions

      const response = await cheqdDidRegistrar.createResource(agentContext, schema.issuerId, schemaResource)
      if (response.resourceState.state !== 'finished') {
        throw new CredoError(response.resourceState.reason ?? 'Unknown error')
      }

      return {
        schemaState: {
          state: 'finished',
          schema,
          schemaId: `${schema.issuerId}/resources/${schemaResource.id}`,
        },
        registrationMetadata: {},
        schemaMetadata: {},
      }
    } catch (error) {
      agentContext.config.logger.debug(`Error registering schema for did '${options.schema.issuerId}'`, {
        error,
        did: options.schema.issuerId,
        schema: options,
      })

      return {
        schemaMetadata: {},
        registrationMetadata: {},
        schemaState: {
          state: 'failed',
          schema: options.schema,
          reason: `unknownError: ${error.message}`,
        },
      }
    }
  }

  public async registerCredentialDefinition(
    agentContext: AgentContext,
    options: RegisterCredentialDefinitionOptions
  ): Promise<RegisterCredentialDefinitionReturn> {
    try {
      const cheqdDidRegistrar = agentContext.dependencyManager.resolve(CheqdDidRegistrar)
      const { credentialDefinition } = options
      const schema = await this.getSchema(agentContext, credentialDefinition.schemaId)
      if (!schema.schema) throw new CredoError(`Schema not found for schemaId: ${credentialDefinition.schemaId}`)

      const credDefName = `${schema.schema.name}-${credentialDefinition.tag}`
      const credDefNameHashBuffer = Hasher.hash(credDefName, 'sha-256')

      const credDefResource = {
        id: utils.uuid(),
        name: TypedArrayEncoder.toHex(credDefNameHashBuffer),
        resourceType: cheqdAnonCredsResourceTypes.credentialDefinition,
        data: {
          type: credentialDefinition.type,
          tag: credentialDefinition.tag,
          value: credentialDefinition.value,
          schemaId: credentialDefinition.schemaId,
        },
        version: utils.uuid(),
      } satisfies CheqdCreateResourceOptions

      const response = await cheqdDidRegistrar.createResource(
        agentContext,
        credentialDefinition.issuerId,
        credDefResource
      )
      if (response.resourceState.state !== 'finished')
        throw new CredoError(response.resourceState.reason ?? 'Unknown error')

      return {
        credentialDefinitionState: {
          state: 'finished',
          credentialDefinition,
          credentialDefinitionId: `${credentialDefinition.issuerId}/resources/${credDefResource.id}`,
        },
        registrationMetadata: {},
        credentialDefinitionMetadata: {},
      }
    } catch (error) {
      agentContext.config.logger.error(
        `Error registering credential definition for did '${options.credentialDefinition.issuerId}'`,
        {
          error,
          did: options.credentialDefinition.issuerId,
          schema: options,
        }
      )

      return {
        credentialDefinitionMetadata: {},
        registrationMetadata: {},
        credentialDefinitionState: {
          state: 'failed',
          credentialDefinition: options.credentialDefinition,
          reason: `unknownError: ${error.message}`,
        },
      }
    }
  }

  public async getCredentialDefinition(
    agentContext: AgentContext,
    credentialDefinitionId: string
  ): Promise<GetCredentialDefinitionReturn> {
    try {
      const cheqdDidResolver = agentContext.dependencyManager.resolve(CheqdDidResolver)
      const parsedDid = parseCheqdDid(credentialDefinitionId)
      if (!parsedDid) throw new CredoError(`Invalid credentialDefinitionId: ${credentialDefinitionId}`)

      agentContext.config.logger.trace(
        `Submitting get credential definition request for '${credentialDefinitionId}' to ledger`
      )

      const response = await cheqdDidResolver.resolveResource(agentContext, credentialDefinitionId)
      const credentialDefinition = JsonTransformer.fromJSON(response.resource, CheqdCredentialDefinition)
      return {
        credentialDefinition: {
          ...credentialDefinition,
          issuerId: parsedDid.did,
        },
        credentialDefinitionId,
        resolutionMetadata: {},
        credentialDefinitionMetadata: (response.resourceMetadata ?? {}) as Record<string, unknown>,
      }
    } catch (error) {
      agentContext.config.logger.error(`Error retrieving credential definition '${credentialDefinitionId}'`, {
        error,
        credentialDefinitionId,
      })

      return {
        credentialDefinitionId,
        resolutionMetadata: {
          error: 'notFound',
          message: `unable to resolve credential definition: ${error.message}`,
        },
        credentialDefinitionMetadata: {},
      }
    }
  }

  public async getRevocationRegistryDefinition(
    agentContext: AgentContext,
    revocationRegistryDefinitionId: string
  ): Promise<GetRevocationRegistryDefinitionReturn> {
    try {
      const cheqdDidResolver = agentContext.dependencyManager.resolve(CheqdDidResolver)
      const parsedDid = parseCheqdDid(revocationRegistryDefinitionId)
      if (!parsedDid) throw new CredoError(`Invalid revocationRegistryDefinitionId: ${revocationRegistryDefinitionId}`)

      agentContext.config.logger.trace(
        `Submitting get revocation registry definition request for '${revocationRegistryDefinitionId}' to ledger`
      )

      const searchDid = parsedDid.path
        ? revocationRegistryDefinitionId
        : `${revocationRegistryDefinitionId}${revocationRegistryDefinitionId.includes('?') ? '&' : '?'}resourceType=${
            cheqdAnonCredsResourceTypes.revocationRegistryDefinition
          }`

      const response = await cheqdDidResolver.resolveResource(agentContext, searchDid)
      const revocationRegistryDefinition = JsonTransformer.fromJSON(
        response.resource,
        CheqdRevocationRegistryDefinition
      )
      return {
        revocationRegistryDefinition: {
          ...revocationRegistryDefinition,
          issuerId: parsedDid.did,
        },
        revocationRegistryDefinitionId,
        resolutionMetadata: {},
        revocationRegistryDefinitionMetadata: (response.resourceMetadata ?? {}) as Record<string, unknown>,
      }
    } catch (error) {
      agentContext.config.logger.error(
        `Error retrieving revocation registry definition '${revocationRegistryDefinitionId}'`,
        {
          error,
          revocationRegistryDefinitionId,
        }
      )

      return {
        revocationRegistryDefinitionId,
        resolutionMetadata: {
          error: 'notFound',
          message: `unable to resolve revocation registry definition: ${error.message}`,
        },
        revocationRegistryDefinitionMetadata: {},
      }
    }
  }

  public async registerRevocationRegistryDefinition(
    agentContext: AgentContext,
    { revocationRegistryDefinition, options }: RegisterRevocationRegistryDefinitionOptions
  ): Promise<RegisterRevocationRegistryDefinitionReturn> {
    try {
      const credentialDefinition = await this.getCredentialDefinition(
        agentContext,
        revocationRegistryDefinition.credDefId
      )
      if (!credentialDefinition.credentialDefinition)
        throw new CredoError(`Credential definition not found for id: ${revocationRegistryDefinition.credDefId}`)

      const credentialDefinitionName = credentialDefinition.credentialDefinitionMetadata.name
      if (!credentialDefinitionName)
        throw new CredoError(`Credential definition name not found for id: ${revocationRegistryDefinition.credDefId}`)

      const cheqdDidRegistrar = agentContext.dependencyManager.resolve(CheqdDidRegistrar)

      const revocDefName = `${credentialDefinitionName}-${revocationRegistryDefinition.tag}`
      const revocDefNameHashedBuffer = Hasher.hash(revocDefName, 'sha-256')

      const revocationRegistryDefinitionResource = {
        id: utils.uuid(),
        name: TypedArrayEncoder.toHex(revocDefNameHashedBuffer),
        resourceType: cheqdAnonCredsResourceTypes.revocationRegistryDefinition,
        data: {
          credDefId: revocationRegistryDefinition.credDefId,
          revocDefType: revocationRegistryDefinition.revocDefType,
          tag: revocationRegistryDefinition.tag,
          value: revocationRegistryDefinition.value,
        },
        version: utils.uuid(),
      } satisfies CheqdCreateResourceOptions

      const response = await cheqdDidRegistrar.createResource(
        agentContext,
        revocationRegistryDefinition.issuerId,
        revocationRegistryDefinitionResource
      )
      if (response.resourceState.state !== 'finished')
        throw new CredoError(response.resourceState.reason ?? 'Unknown error')

      return {
        revocationRegistryDefinitionState: {
          state: 'finished',
          revocationRegistryDefinition,
          revocationRegistryDefinitionId: `${revocationRegistryDefinition.issuerId}/resources/${revocationRegistryDefinitionResource.id}`,
        },
        registrationMetadata: {},
        revocationRegistryDefinitionMetadata: (response.resourceMetadata ?? {}) as Record<string, unknown>,
      }
    } catch (error) {
      agentContext.config.logger.error(
        `Error registering revocation registry definition for did '${revocationRegistryDefinition.issuerId}'`,
        {
          error,
          did: revocationRegistryDefinition.issuerId,
          options,
        }
      )

      return {
        revocationRegistryDefinitionMetadata: {},
        registrationMetadata: {},
        revocationRegistryDefinitionState: {
          state: 'failed',
          revocationRegistryDefinition,
          reason: `unknownError: ${error.message}`,
        },
      }
    }
  }

  public async getRevocationStatusList(
    agentContext: AgentContext,
    revocationRegistryId: string,
    timestamp: number
  ): Promise<GetRevocationStatusListReturn> {
    try {
      const cheqdDidResolver = agentContext.dependencyManager.resolve(CheqdDidResolver)
      const parsedDid = parseCheqdDid(revocationRegistryId)
      if (!parsedDid) throw new CredoError(`Invalid revocationRegistryId: ${revocationRegistryId}`)

      agentContext.config.logger.trace(
        `Submitting get revocation status request for '${revocationRegistryId}' to ledger`
      )

      const revocationRegistryDefinition = await this.getRevocationRegistryDefinition(
        agentContext,
        revocationRegistryId
      )
      if (!revocationRegistryDefinition.revocationRegistryDefinition)
        throw new CredoError(`Revocation registry definition not found for id: ${revocationRegistryId}`)

      const revocationRegistryDefinitionName = revocationRegistryDefinition.revocationRegistryDefinitionMetadata.name
      if (!revocationRegistryDefinitionName)
        throw new CredoError(`Revocation registry definition name not found for id: ${revocationRegistryId}`)

      const response = await cheqdDidResolver.resolveResource(
        agentContext,
        `${parsedDid.did}?resourceType=${cheqdAnonCredsResourceTypes.revocationStatusList}&resourceVersionTime=${timestamp}&resourceName=${revocationRegistryDefinitionName}`
      )

      const revocationStatusList = JsonTransformer.fromJSON(response.resource, CheqdRevocationStatusList)

      const statusListTimestamp = response.resourceMetadata?.created
        ? Math.floor(response.resourceMetadata.created.getTime() / 1000)
        : undefined
      if (statusListTimestamp === undefined)
        throw new CredoError(`Unable to extract revocation status list timestamp from resource ${revocationRegistryId}`)

      return {
        revocationStatusList: {
          ...revocationStatusList,
          issuerId: parsedDid.did,
          timestamp: statusListTimestamp,
        },
        resolutionMetadata: {},
        revocationStatusListMetadata: (response.resourceMetadata ?? {}) as Record<string, unknown>,
      }
    } catch (error) {
      agentContext.config.logger.error(`Error retrieving revocation registry status list '${revocationRegistryId}'`, {
        error,
        revocationRegistryId,
      })

      return {
        resolutionMetadata: {
          error: 'notFound',
          message: `unable to resolve revocation registry status list: ${error.message}`,
        },
        revocationStatusListMetadata: {},
      }
    }
  }

  public async registerRevocationStatusList(
    agentContext: AgentContext,
    { revocationStatusList, options }: RegisterRevocationStatusListOptions
  ): Promise<RegisterRevocationStatusListReturn> {
    try {
      const revocationRegistryDefinition = await this.getRevocationRegistryDefinition(
        agentContext,
        revocationStatusList.revRegDefId
      )
      if (!revocationRegistryDefinition.revocationRegistryDefinition) {
        throw new CredoError(`Revocation registry definition not found for id: ${revocationStatusList.revRegDefId}`)
      }

      const revocationRegistryDefinitionName = revocationRegistryDefinition.revocationRegistryDefinitionMetadata.name
      if (!revocationRegistryDefinitionName)
        throw new CredoError(
          `Revocation registry definition name not found for id: ${revocationStatusList.revRegDefId}`
        )

      const cheqdDidRegistrar = agentContext.dependencyManager.resolve(CheqdDidRegistrar)
      const revocationStatusListResource = {
        id: utils.uuid(),
        name: revocationRegistryDefinitionName as string,
        resourceType: cheqdAnonCredsResourceTypes.revocationStatusList,
        data: {
          currentAccumulator: revocationStatusList.currentAccumulator,
          revRegDefId: revocationStatusList.revRegDefId,
          revocationList: revocationStatusList.revocationList,
        },
        version: utils.uuid(),
      } satisfies CheqdCreateResourceOptions

      const response = await cheqdDidRegistrar.createResource(
        agentContext,
        revocationStatusList.issuerId,
        revocationStatusListResource
      )
      if (response.resourceState.state !== 'finished')
        throw new CredoError(response.resourceState.reason ?? 'Unknown error')

      // It's not possible to get the timestamp from the response, so we set it to the current time
      const nowTimestamp = Math.floor(Date.now() / 1000)

      return {
        revocationStatusListState: {
          state: 'finished',
          revocationStatusList: {
            ...revocationStatusList,
            timestamp: nowTimestamp,
          },
        },
        registrationMetadata: {},
        revocationStatusListMetadata: (response.resourceMetadata ?? {}) as Record<string, unknown>,
      }
    } catch (error) {
      agentContext.config.logger.error(
        `Error registering revocation status list for did '${revocationStatusList.issuerId}'`,
        {
          error,
          did: revocationStatusList.issuerId,
          options,
        }
      )

      return {
        revocationStatusListMetadata: {},
        registrationMetadata: {},
        revocationStatusListState: {
          state: 'failed',
          revocationStatusList,
          reason: `unknownError: ${error.message}`,
        },
      }
    }
  }
}
