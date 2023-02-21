import type {
  AnonCredsRegistry,
  GetCredentialDefinitionReturn,
  GetSchemaReturn,
  RegisterSchemaOptions,
  RegisterCredentialDefinitionOptions,
  RegisterSchemaReturn,
  RegisterCredentialDefinitionReturn,
  GetRevocationStatusListReturn,
  GetRevocationRegistryDefinitionReturn,
} from '@aries-framework/anoncreds'
import type { AgentContext } from '@aries-framework/core'

import { DidsApi, getKeyDidMappingByVerificationMethod } from '@aries-framework/core'
import {
  GetSchemaRequest,
  SchemaRequest,
  GetCredentialDefinitionRequest,
  CredentialDefinitionRequest,
  GetTransactionRequest,
  GetRevocationRegistryDeltaRequest,
  GetRevocationRegistryDefinitionRequest,
} from '@hyperledger/indy-vdr-shared'

import { IndyVdrPoolService } from '../pool'

import {
  didFromSchemaId,
  didFromCredentialDefinitionId,
  didFromRevocationRegistryDefinitionId,
  getLegacySchemaId,
  getLegacyCredentialDefinitionId,
  indyVdrAnonCredsRegistryIdentifierRegex,
} from './utils/identifiers'
import { anonCredsRevocationStatusListFromIndyVdr } from './utils/transform'

export class IndyVdrAnonCredsRegistry implements AnonCredsRegistry {
  public readonly supportedIdentifier = indyVdrAnonCredsRegistryIdentifierRegex

  public async getSchema(agentContext: AgentContext, schemaId: string): Promise<GetSchemaReturn> {
    try {
      const indyVdrPoolService = agentContext.dependencyManager.resolve(IndyVdrPoolService)

      const did = didFromSchemaId(schemaId)

      const pool = await indyVdrPoolService.getPoolForDid(agentContext, did)

      agentContext.config.logger.debug(`Getting schema '${schemaId}' from ledger '${pool.indyNamespace}'`)
      const request = new GetSchemaRequest({ submitterDid: did, schemaId })

      agentContext.config.logger.trace(
        `Submitting get schema request for schema '${schemaId}' to ledger '${pool.indyNamespace}'`
      )
      const response = await pool.submitReadRequest(request)

      agentContext.config.logger.trace(`Got un-parsed schema '${schemaId}' from ledger '${pool.indyNamespace}'`, {
        response,
      })

      const issuerId = didFromSchemaId(schemaId)

      if ('attr_names' in response.result.data) {
        return {
          schema: {
            attrNames: response.result.data.attr_names,
            name: response.result.data.name,
            version: response.result.data.version,
            issuerId,
          },
          schemaId: schemaId,
          resolutionMetadata: {},
          schemaMetadata: {
            didIndyNamespace: pool.indyNamespace,
            // NOTE: the seqNo is required by the indy-sdk even though not present in AnonCreds v1.
            // For this reason we return it in the metadata.
            indyLedgerSeqNo: response.result.seqNo,
          },
        }
      }

      agentContext.config.logger.error(`Error retrieving schema '${schemaId}'`)

      return {
        schemaId,
        resolutionMetadata: {
          error: 'notFound',
          message: `unable to find schema with id ${schemaId}`,
        },
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
        },
        schemaMetadata: {},
      }
    }
  }

  public async registerSchema(
    agentContext: AgentContext,
    options: IndyVdrRegisterSchemaOptions
  ): Promise<RegisterSchemaReturn> {
    if (!options.options.didIndyNamespace) {
      return {
        schemaMetadata: {},
        registrationMetadata: {},
        schemaState: {
          reason: 'no didIndyNamespace defined in the options. didIndyNamespace is required when using the Indy VDR',
          schema: options.schema,
          state: 'failed',
        },
      }
    }

    try {
      const indyVdrPoolService = agentContext.dependencyManager.resolve(IndyVdrPoolService)

      const schemaRequest = new SchemaRequest({
        submitterDid: options.schema.issuerId,
        schema: {
          id: getLegacySchemaId(options.schema.issuerId, options.schema.name, options.schema.version),
          name: options.schema.name,
          ver: '1.0',
          version: options.schema.version,
          attrNames: options.schema.attrNames,
        },
      })

      const pool = indyVdrPoolService.getPoolForNamespace(options.options.didIndyNamespace)

      // FIXME: we should store the didDocument in the DidRecord so we don't have to fetch our own did
      // from the ledger to know which key is associated with the did
      const didsApi = agentContext.dependencyManager.resolve(DidsApi)
      const didResult = await didsApi.resolve(`did:sov:${options.schema.issuerId}`)

      if (!didResult.didDocument) {
        return {
          schemaMetadata: {},
          registrationMetadata: {},
          schemaState: {
            schema: options.schema,
            state: 'failed',
            reason: `didNotFound: unable to resolve did did:sov:${options.schema.issuerId}: ${didResult.didResolutionMetadata.message}`,
          },
        }
      }

      const verificationMethod = didResult.didDocument.dereferenceKey(`did:sov:${options.schema.issuerId}#key-1`)
      const { getKeyFromVerificationMethod } = getKeyDidMappingByVerificationMethod(verificationMethod)
      const key = getKeyFromVerificationMethod(verificationMethod)

      const response = await pool.submitWriteRequest(agentContext, schemaRequest, key)

      return {
        schemaState: {
          state: 'finished',
          schema: {
            attrNames: options.schema.attrNames,
            issuerId: options.schema.issuerId,
            name: options.schema.name,
            version: options.schema.version,
          },
          schemaId: getLegacySchemaId(options.schema.issuerId, options.schema.name, options.schema.version),
        },
        registrationMetadata: {},
        schemaMetadata: {
          // NOTE: the seqNo is required by the indy-sdk even though not present in AnonCreds v1.
          // For this reason we return it in the metadata.
          indyLedgerSeqNo: response.result.txnMetadata.seqNo,
          didIndyNamespace: pool.indyNamespace,
        },
      }
    } catch (error) {
      agentContext.config.logger.error(`Error registering schema for did '${options.schema.issuerId}'`, {
        error,
        did: options.schema.issuerId,
        schema: options.schema,
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

  public async getCredentialDefinition(
    agentContext: AgentContext,
    credentialDefinitionId: string
  ): Promise<GetCredentialDefinitionReturn> {
    try {
      const indyVdrPoolService = agentContext.dependencyManager.resolve(IndyVdrPoolService)

      const did = didFromCredentialDefinitionId(credentialDefinitionId)

      const pool = await indyVdrPoolService.getPoolForDid(agentContext, did)

      agentContext.config.logger.debug(
        `Getting credential definition '${credentialDefinitionId}' from ledger '${pool.indyNamespace}'`
      )

      const request = new GetCredentialDefinitionRequest({
        submitterDid: did,
        credentialDefinitionId,
      })

      agentContext.config.logger.trace(
        `Submitting get credential definition request for credential definition '${credentialDefinitionId}' to ledger '${pool.indyNamespace}'`
      )

      const response = await pool.submitReadRequest(request)

      const schema = await this.fetchIndySchemaWithSeqNo(agentContext, response.result.ref, did)

      if (response.result.data && schema) {
        return {
          credentialDefinitionId: credentialDefinitionId,
          credentialDefinition: {
            issuerId: didFromCredentialDefinitionId(credentialDefinitionId),
            schemaId: schema.schema.schemaId,
            tag: response.result.tag,
            type: 'CL',
            value: response.result.data,
          },
          credentialDefinitionMetadata: {
            didIndyNamespace: pool.indyNamespace,
          },
          resolutionMetadata: {},
        }
      }

      agentContext.config.logger.error(`Error retrieving credential definition '${credentialDefinitionId}'`)

      return {
        credentialDefinitionId,
        credentialDefinitionMetadata: {},
        resolutionMetadata: {
          error: 'notFound',
          message: `unable to resolve credential definition with id ${credentialDefinitionId}`,
        },
      }
    } catch (error) {
      agentContext.config.logger.error(`Error retrieving credential definition '${credentialDefinitionId}'`, {
        error,
        credentialDefinitionId,
      })

      return {
        credentialDefinitionId,
        credentialDefinitionMetadata: {},
        resolutionMetadata: {
          error: 'notFound',
          message: `unable to resolve credential definition: ${error.message}`,
        },
      }
    }
  }

  public async registerCredentialDefinition(
    agentContext: AgentContext,
    options: IndyVdrRegisterCredentialDefinitionOptions
  ): Promise<RegisterCredentialDefinitionReturn> {
    // Make sure didIndyNamespace is passed
    if (!options.options.didIndyNamespace) {
      return {
        credentialDefinitionMetadata: {},
        registrationMetadata: {},
        credentialDefinitionState: {
          reason: 'no didIndyNamespace defined in the options. didIndyNamespace is required when using the Indy SDK',
          credentialDefinition: options.credentialDefinition,
          state: 'failed',
        },
      }
    }

    try {
      const indyVdrPoolService = agentContext.dependencyManager.resolve(IndyVdrPoolService)

      const pool = indyVdrPoolService.getPoolForNamespace(options.options.didIndyNamespace)

      const { schema, schemaMetadata, resolutionMetadata } = await this.getSchema(
        agentContext,
        options.credentialDefinition.schemaId
      )

      if (!schema || !schemaMetadata.indyLedgerSeqNo || typeof schemaMetadata.indyLedgerSeqNo !== 'number') {
        return {
          registrationMetadata: {},
          credentialDefinitionMetadata: {
            didIndyNamespace: pool.indyNamespace,
          },
          credentialDefinitionState: {
            credentialDefinition: options.credentialDefinition,
            state: 'failed',
            reason: `error resolving schema with id ${options.credentialDefinition.schemaId}: ${resolutionMetadata.error} ${resolutionMetadata.message}`,
          },
        }
      }

      const credentialDefinitionId = getLegacyCredentialDefinitionId(
        options.credentialDefinition.issuerId,
        schemaMetadata.indyLedgerSeqNo,
        options.credentialDefinition.tag
      )

      const credentialDefinitionRequest = new CredentialDefinitionRequest({
        submitterDid: options.credentialDefinition.issuerId,
        credentialDefinition: {
          ver: '1.0',
          id: credentialDefinitionId,
          schemaId: `${schemaMetadata.indyLedgerSeqNo}`,
          type: 'CL',
          tag: options.credentialDefinition.tag,
          value: options.credentialDefinition.value,
        },
      })

      // FIXME: we should store the didDocument in the DidRecord so we don't have to fetch our own did
      // from the ledger to know which key is associated with the did
      const didsApi = agentContext.dependencyManager.resolve(DidsApi)
      const didResult = await didsApi.resolve(`did:sov:${options.credentialDefinition.issuerId}`)

      if (!didResult.didDocument) {
        return {
          credentialDefinitionMetadata: {},
          registrationMetadata: {},
          credentialDefinitionState: {
            credentialDefinition: options.credentialDefinition,
            state: 'failed',
            reason: `didNotFound: unable to resolve did did:sov:${options.credentialDefinition.issuerId}: ${didResult.didResolutionMetadata.message}`,
          },
        }
      }

      const verificationMethod = didResult.didDocument.dereferenceKey(
        `did:sov:${options.credentialDefinition.issuerId}#key-1`
      )
      const { getKeyFromVerificationMethod } = getKeyDidMappingByVerificationMethod(verificationMethod)
      const key = getKeyFromVerificationMethod(verificationMethod)

      const response = await pool.submitWriteRequest(agentContext, credentialDefinitionRequest, key)

      agentContext.config.logger.debug(
        `Registered credential definition '${credentialDefinitionId}' on ledger '${pool.indyNamespace}'`,
        {
          response,
          credentialDefinition: options.credentialDefinition,
        }
      )

      return {
        credentialDefinitionMetadata: {
          didIndyNamespace: pool.indyNamespace,
        },
        credentialDefinitionState: {
          credentialDefinition: options.credentialDefinition,
          credentialDefinitionId,
          state: 'finished',
        },
        registrationMetadata: {},
      }
    } catch (error) {
      agentContext.config.logger.error(
        `Error registering credential definition for schema '${options.credentialDefinition.schemaId}'`,
        {
          error,
          did: options.credentialDefinition.issuerId,
          credentialDefinition: options.credentialDefinition,
        }
      )

      return {
        credentialDefinitionMetadata: {},
        registrationMetadata: {},
        credentialDefinitionState: {
          credentialDefinition: options.credentialDefinition,
          state: 'failed',
          reason: `unknownError: ${error.message}`,
        },
      }
    }
  }

  public async getRevocationRegistryDefinition(
    agentContext: AgentContext,
    revocationRegistryDefinitionId: string
  ): Promise<GetRevocationRegistryDefinitionReturn> {
    try {
      const indySdkPoolService = agentContext.dependencyManager.resolve(IndyVdrPoolService)
      const did = didFromRevocationRegistryDefinitionId(revocationRegistryDefinitionId)

      const pool = await indySdkPoolService.getPoolForDid(agentContext, did)

      agentContext.config.logger.debug(
        `Using ledger '${pool.indyNamespace}' to retrieve revocation registry definition '${revocationRegistryDefinitionId}'`
      )

      const request = new GetRevocationRegistryDefinitionRequest({
        submitterDid: did,
        revocationRegistryId: revocationRegistryDefinitionId,
      })

      agentContext.config.logger.trace(
        `Submitting get revocation registry definition request for revocation registry definition '${revocationRegistryDefinitionId}' to ledger`
      )

      const response = await pool.submitReadRequest(request)

      if (!response.result.data) {
        agentContext.config.logger.error(
          `Error retrieving revocation registry definition '${revocationRegistryDefinitionId}' from ledger`,
          {
            revocationRegistryDefinitionId,
          }
        )

        return {
          resolutionMetadata: {
            error: 'notFound',
            message: `unable to resolve revocation registry definition`,
          },
          revocationRegistryDefinitionId,
          revocationRegistryDefinitionMetadata: {},
        }
      }

      const revocationRegistryDefinition = {
        issuerId: did,
        revocDefType: response.result.data?.revocDefType,
        value: {
          maxCredNum: response.result.data?.value.maxCredNum,
          tailsHash: response.result.data?.value.tailsHash,
          tailsLocation: response.result.data?.value.tailsLocation,
          publicKeys: {
            accumKey: {
              z: response.result.data?.value.publicKeys.accumKey.z,
            },
          },
        },
        tag: response.result.data?.tag,
        credDefId: response.result.data?.credDefId,
      }

      return {
        revocationRegistryDefinitionId,
        revocationRegistryDefinition,
        revocationRegistryDefinitionMetadata: {
          issuanceType: response.result.data?.value.issuanceType,
          didIndyNamespace: pool.indyNamespace,
        },
        resolutionMetadata: {},
      }
    } catch (error) {
      agentContext.config.logger.error(
        `Error retrieving revocation registry definition '${revocationRegistryDefinitionId}' from ledger`,
        {
          error,
          revocationRegistryDefinitionId,
        }
      )

      return {
        resolutionMetadata: {
          error: 'notFound',
          message: `unable to resolve revocation registry definition: ${error.message}`,
        },
        revocationRegistryDefinitionId,
        revocationRegistryDefinitionMetadata: {},
      }
    }
  }

  public async getRevocationStatusList(
    agentContext: AgentContext,
    revocationRegistryId: string,
    timestamp: number
  ): Promise<GetRevocationStatusListReturn> {
    try {
      const indySdkPoolService = agentContext.dependencyManager.resolve(IndyVdrPoolService)
      const did = didFromRevocationRegistryDefinitionId(revocationRegistryId)

      const pool = await indySdkPoolService.getPoolForDid(agentContext, did)

      agentContext.config.logger.debug(
        `Using ledger '${pool.indyNamespace}' to retrieve revocation registry deltas with revocation registry definition id '${revocationRegistryId}' until ${timestamp}`
      )

      const request = new GetRevocationRegistryDeltaRequest({
        submitterDid: did,
        revocationRegistryId,
        toTs: timestamp,
      })

      agentContext.config.logger.trace(
        `Submitting get revocation registry delta request for revocation registry '${revocationRegistryId}' to ledger`
      )

      const response = await pool.submitReadRequest(request)

      agentContext.config.logger.debug(
        `Got revocation registry deltas '${revocationRegistryId}' until timestamp ${timestamp} from ledger`
      )

      const { revocationRegistryDefinition, resolutionMetadata, revocationRegistryDefinitionMetadata } =
        await this.getRevocationRegistryDefinition(agentContext, revocationRegistryId)

      if (
        !revocationRegistryDefinition ||
        !revocationRegistryDefinitionMetadata.issuanceType ||
        typeof revocationRegistryDefinitionMetadata.issuanceType !== 'string'
      ) {
        return {
          resolutionMetadata: {
            error: `error resolving revocation registry definition with id ${revocationRegistryId}: ${resolutionMetadata.error} ${resolutionMetadata.message}`,
          },
          revocationStatusListMetadata: {
            didIndyNamespace: pool.indyNamespace,
          },
        }
      }

      const isIssuanceByDefault = revocationRegistryDefinitionMetadata.issuanceType === 'ISSUANCE_BY_DEFAULT'

      if (!response.result.data) {
        return {
          resolutionMetadata: {
            error: 'notFound',
            message: `Error retrieving revocation registry delta '${revocationRegistryId}' from ledger, potentially revocation interval ends before revocation registry creation`,
          },
          revocationStatusListMetadata: {},
        }
      }

      const revocationRegistryDelta = {
        accum: response.result.data?.value.accum_to.value.accum,
        issued: response.result.data?.value.issued,
        revoked: response.result.data?.value.revoked,
      }

      return {
        resolutionMetadata: {},
        revocationStatusList: anonCredsRevocationStatusListFromIndyVdr(
          revocationRegistryId,
          revocationRegistryDefinition,
          revocationRegistryDelta,
          response.result.data.value.accum_to.txnTime,
          isIssuanceByDefault
        ),
        revocationStatusListMetadata: {
          didIndyNamespace: pool.indyNamespace,
        },
      }
    } catch (error) {
      agentContext.config.logger.error(
        `Error retrieving revocation registry delta '${revocationRegistryId}' from ledger, potentially revocation interval ends before revocation registry creation?"`,
        {
          error,
          revocationRegistryId: revocationRegistryId,
        }
      )

      return {
        resolutionMetadata: {
          error: 'notFound',
          message: `Error retrieving revocation registry delta '${revocationRegistryId}' from ledger, potentially revocation interval ends before revocation registry creation: ${error.message}`,
        },
        revocationStatusListMetadata: {},
      }
    }
  }

  private async fetchIndySchemaWithSeqNo(agentContext: AgentContext, seqNo: number, did: string) {
    const indyVdrPoolService = agentContext.dependencyManager.resolve(IndyVdrPoolService)

    const pool = await indyVdrPoolService.getPoolForDid(agentContext, did)

    agentContext.config.logger.debug(`Getting transaction with seqNo '${seqNo}' from ledger '${pool.indyNamespace}'`)
    // ledgerType 1 is domain ledger
    const request = new GetTransactionRequest({ ledgerType: 1, seqNo })

    agentContext.config.logger.trace(`Submitting get transaction request to ledger '${pool.indyNamespace}'`)
    const response = await pool.submitReadRequest(request)

    if (response.result.data?.txn.type !== '101') {
      agentContext.config.logger.error(`Could not get schema from ledger for seq no ${seqNo}'`)
      return null
    }

    const schema = response.result.data?.txn.data as SchemaType

    const schemaId = getLegacySchemaId(did, schema.data.name, schema.data.version)

    return {
      schema: {
        schemaId,
        attr_name: schema.data.attr_names,
        name: schema.data.name,
        version: schema.data.version,
        issuerId: did,
        seqNo,
      },
      indyNamespace: pool.indyNamespace,
    }
  }
}

interface SchemaType {
  data: {
    attr_names: string[]
    version: string
    name: string
  }
}

export interface IndyVdrRegisterSchemaOptions extends RegisterSchemaOptions {
  options: {
    didIndyNamespace: string
  }
}

export interface IndyVdrRegisterCredentialDefinitionOptions extends RegisterCredentialDefinitionOptions {
  options: {
    didIndyNamespace: string
  }
}
