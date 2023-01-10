import type { AnonCredsVerifierService, VerifyProofOptions } from '@aries-framework/anoncreds'
import type { CredentialDefs, Schemas, RevocRegDefs, RevRegs } from 'indy-sdk'

import { inject } from '@aries-framework/core'

import { IndySdkError, isIndyError } from '../../error'
import { IndySdk, IndySdkSymbol } from '../../types'
import { getIndySeqNoFromUnqualifiedCredentialDefinitionId } from '../utils/identifiers'
import {
  indySdkCredentialDefinitionFromAnonCreds,
  indySdkRevocationRegistryDefinitionFromAnonCreds,
  indySdkRevocationRegistryFromAnonCreds,
  indySdkSchemaFromAnonCreds,
} from '../utils/transform'

export class IndySdkVerifierService implements AnonCredsVerifierService {
  private indySdk: IndySdk

  public constructor(@inject(IndySdkSymbol) indySdk: IndySdk) {
    this.indySdk = indySdk
  }

  public async verifyProof(options: VerifyProofOptions): Promise<boolean> {
    try {
      // The AnonCredsSchema doesn't contain the seqNo anymore. However, the indy credential definition id
      // does contain the seqNo, so we can extract it from the credential definition id.
      const seqNoMap: { [schemaId: string]: number } = {}

      // Convert AnonCreds credential definitions to Indy credential definitions
      const indyCredentialDefinitions: CredentialDefs = {}
      for (const credentialDefinitionId in options.credentialDefinitions) {
        const credentialDefinition = options.credentialDefinitions[credentialDefinitionId]

        indyCredentialDefinitions[credentialDefinitionId] = indySdkCredentialDefinitionFromAnonCreds(
          credentialDefinitionId,
          credentialDefinition
        )

        // Get the seqNo for the schemas so we can use it when transforming the schemas
        const schemaSeqNo = getIndySeqNoFromUnqualifiedCredentialDefinitionId(credentialDefinitionId)
        seqNoMap[credentialDefinition.schemaId] = schemaSeqNo
      }

      // Convert AnonCreds schemas to Indy schemas
      const indySchemas: Schemas = {}
      for (const schemaId in options.schemas) {
        const schema = options.schemas[schemaId]
        indySchemas[schemaId] = indySdkSchemaFromAnonCreds(schemaId, schema, seqNoMap[schemaId])
      }

      // Convert AnonCreds revocation definitions to Indy revocation definitions
      const indyRevocationDefinitions: RevocRegDefs = {}
      const indyRevocationRegistries: RevRegs = {}

      for (const revocationRegistryDefinitionId in options.revocationStates) {
        const { definition, revocationLists } = options.revocationStates[revocationRegistryDefinitionId]
        indyRevocationDefinitions[revocationRegistryDefinitionId] = indySdkRevocationRegistryDefinitionFromAnonCreds(
          revocationRegistryDefinitionId,
          definition
        )

        // Initialize empty object for this revocation registry
        indyRevocationRegistries[revocationRegistryDefinitionId] = {}

        // Also transform the revocation lists for the specified timestamps into the revocation registry
        // format Indy expects
        for (const timestamp in revocationLists) {
          const revocationList = revocationLists[timestamp]
          indyRevocationRegistries[revocationRegistryDefinitionId][timestamp] =
            indySdkRevocationRegistryFromAnonCreds(revocationList)
        }
      }

      return await this.indySdk.verifierVerifyProof(
        options.proofRequest,
        options.proof,
        indySchemas,
        indyCredentialDefinitions,
        indyRevocationDefinitions,
        indyRevocationRegistries
      )
    } catch (error) {
      throw isIndyError(error) ? new IndySdkError(error) : error
    }
  }
}
