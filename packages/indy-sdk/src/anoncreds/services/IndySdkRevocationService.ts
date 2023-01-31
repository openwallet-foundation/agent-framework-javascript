import type {
  AnonCredsRevocationRegistryDefinition,
  AnonCredsRevocationList,
  AnonCredsProofRequest,
  AnonCredsRequestedCredentials,
  AnonCredsCredentialInfo,
  AnonCredsNonRevokedInterval,
} from '@aries-framework/anoncreds'
import type { AgentContext } from '@aries-framework/core'
import type { RevStates } from 'indy-sdk'

import { AriesFrameworkError, inject, injectable } from '@aries-framework/core'

import { IndySdkError, isIndyError } from '../../error'
import { IndySdk, IndySdkSymbol } from '../../types'
import { createTailsReader } from '../utils/tails'
import {
  indySdkRevocationDeltaFromAnonCreds,
  indySdkRevocationRegistryDefinitionFromAnonCreds,
} from '../utils/transform'

enum RequestReferentType {
  Attribute = 'attribute',
  Predicate = 'predicate',
  SelfAttestedAttribute = 'self-attested-attribute',
}

/**
 * Internal class that handles revocation related logic for the Indy SDK
 *
 * @internal
 */
@injectable()
export class IndySdkRevocationService {
  private indySdk: IndySdk

  public constructor(@inject(IndySdkSymbol) indySdk: IndySdk) {
    this.indySdk = indySdk
  }

  /**
   * Creates the revocation state for the requested credentials in a format that the Indy SDK expects.
   */
  public async createRevocationState(
    agentContext: AgentContext,
    proofRequest: AnonCredsProofRequest,
    requestedCredentials: AnonCredsRequestedCredentials,
    revocationRegistries: {
      [revocationRegistryDefinitionId: string]: {
        // Tails is already downloaded
        tailsFilePath: string
        definition: AnonCredsRevocationRegistryDefinition
        revocationLists: {
          [timestamp: string]: AnonCredsRevocationList
        }
      }
    }
  ): Promise<RevStates> {
    try {
      agentContext.config.logger.debug(`Creating Revocation State(s) for proof request`, {
        proofRequest,
        requestedCredentials,
      })
      const indyRevocationStates: RevStates = {}
      const referentCredentials: Array<{
        type: RequestReferentType
        referent: string
        credentialInfo: AnonCredsCredentialInfo
        referentRevocationInterval: AnonCredsNonRevokedInterval | undefined
      }> = []

      //Retrieve information for referents and push to single array
      for (const [referent, requestedCredential] of Object.entries(requestedCredentials.requestedAttributes ?? {})) {
        referentCredentials.push({
          referent,
          credentialInfo: requestedCredential.credentialInfo,
          type: RequestReferentType.Attribute,
          referentRevocationInterval: proofRequest.requested_attributes[referent].non_revoked,
        })
      }
      for (const [referent, requestedCredential] of Object.entries(requestedCredentials.requestedPredicates ?? {})) {
        referentCredentials.push({
          referent,
          credentialInfo: requestedCredential.credentialInfo,
          type: RequestReferentType.Predicate,
          referentRevocationInterval: proofRequest.requested_predicates[referent].non_revoked,
        })
      }

      for (const { referent, credentialInfo, type, referentRevocationInterval } of referentCredentials) {
        // Prefer referent-specific revocation interval over global revocation interval
        const requestRevocationInterval = referentRevocationInterval ?? proofRequest.non_revoked
        const credentialRevocationId = credentialInfo.credentialRevocationId
        const revocationRegistryId = credentialInfo.revocationRegistryId

        // If revocation interval is present and the credential is revocable then create revocation state
        if (requestRevocationInterval && credentialRevocationId && revocationRegistryId) {
          agentContext.config.logger.trace(
            `Presentation is requesting proof of non revocation for ${type} referent '${referent}', creating revocation state for credential`,
            {
              requestRevocationInterval,
              credentialRevocationId,
              revocationRegistryId,
            }
          )

          this.assertRevocationInterval(requestRevocationInterval)

          const { definition, revocationLists, tailsFilePath } = revocationRegistries[revocationRegistryId]
          // NOTE: we assume that the revocationLists have been added based on timestamps of the `to` query. On a higher level it means we'll find the
          // most accurate revocation list for a given timestamp. It doesn't have to be that the revocationList is from the `to` timestamp however.
          const revocationList = revocationLists[requestRevocationInterval.to]

          const tails = await createTailsReader(agentContext, tailsFilePath)

          const revocationState = await this.indySdk.createRevocationState(
            tails,
            indySdkRevocationRegistryDefinitionFromAnonCreds(revocationRegistryId, definition),
            indySdkRevocationDeltaFromAnonCreds(revocationList),
            revocationList.timestamp,
            credentialRevocationId
          )
          const timestamp = revocationState.timestamp

          if (!indyRevocationStates[revocationRegistryId]) {
            indyRevocationStates[revocationRegistryId] = {}
          }
          indyRevocationStates[revocationRegistryId][timestamp] = revocationState
        }
      }

      agentContext.config.logger.debug(`Created Revocation States for Proof Request`, {
        indyRevocationStates,
      })

      return indyRevocationStates
    } catch (error) {
      agentContext.config.logger.error(`Error creating Indy Revocation State for Proof Request`, {
        error,
        proofRequest,
        requestedCredentials,
      })

      throw isIndyError(error) ? new IndySdkError(error) : error
    }
  }

  // TODO: Add Test
  // TODO: we should do this verification on a higher level I think?
  // Check revocation interval in accordance with https://github.com/hyperledger/aries-rfcs/blob/main/concepts/0441-present-proof-best-practices/README.md#semantics-of-non-revocation-interval-endpoints
  private assertRevocationInterval(
    revocationInterval: AnonCredsNonRevokedInterval
  ): asserts revocationInterval is BestPracticeNonRevokedInterval {
    if (!revocationInterval.to) {
      throw new AriesFrameworkError(`Presentation requests proof of non-revocation with no 'to' value specified`)
    }

    if (
      (revocationInterval.from || revocationInterval.from === 0) &&
      revocationInterval.to !== revocationInterval.from
    ) {
      throw new AriesFrameworkError(
        `Presentation requests proof of non-revocation with an interval from: '${revocationInterval.from}' that does not match the interval to: '${revocationInterval.to}', as specified in Aries RFC 0441`
      )
    }
  }
}

// This sets the `to` value to be required. We do this check in the `assertRevocationInterval` method,
// and it makes it easier to work with the object in TS
interface BestPracticeNonRevokedInterval {
  from?: number
  to: number
}
