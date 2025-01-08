import type { BaseAgent, JsonObject } from '@credo-ts/core'

import type { PlaintextMessage } from '../../types'

import { ProofRepository, ProofState, type ProofExchangeRecord } from '../../modules/proofs'
import { DidCommMessageRole, DidCommMessageRepository, DidCommMessageRecord } from '../../repository'

/**
 * Migrates the {@link ProofExchangeRecord} to 0.3 compatible format. It fetches all records from storage
 * and applies the needed updates to the records. After a record has been transformed, it is updated
 * in storage and the next record will be transformed.
 *
 * The following transformations are applied:
 *  - {@link migrateInternalProofExchangeRecordProperties}
 *  - {@link moveDidCommMessages}
 */
export async function migrateProofExchangeRecordToV0_3<Agent extends BaseAgent>(agent: Agent) {
  agent.config.logger.info('Migrating proof records to storage version 0.3')
  const proofRepository = agent.dependencyManager.resolve(ProofRepository)

  agent.config.logger.debug(`Fetching all proof records from storage`)
  const allProofs = await proofRepository.getAll(agent.context)

  agent.config.logger.debug(`Found a total of ${allProofs.length} proof records to update.`)
  for (const proofRecord of allProofs) {
    agent.config.logger.debug(`Migrating proof record with id ${proofRecord.id} to storage version 0.3`)

    await migrateInternalProofExchangeRecordProperties(agent, proofRecord)
    await moveDidCommMessages(agent, proofRecord)

    await proofRepository.update(agent.context, proofRecord)

    agent.config.logger.debug(`Successfully migrated proof record with id ${proofRecord.id} to storage version 0.3`)
  }
}

export enum V02_03MigrationProofRole {
  Verifier,
  Prover,
}

const proverProofStates = [
  ProofState.Declined,
  ProofState.ProposalSent,
  ProofState.RequestReceived,
  ProofState.PresentationSent,
  ProofState.Done,
]

const didCommMessageRoleMapping = {
  [V02_03MigrationProofRole.Verifier]: {
    proposalMessage: DidCommMessageRole.Receiver,
    requestMessage: DidCommMessageRole.Sender,
    presentationMessage: DidCommMessageRole.Receiver,
  },
  [V02_03MigrationProofRole.Prover]: {
    proposalMessage: DidCommMessageRole.Sender,
    requestMessage: DidCommMessageRole.Receiver,
    presentationMessage: DidCommMessageRole.Sender,
  },
}

const proofRecordMessageKeys = ['proposalMessage', 'requestMessage', 'presentationMessage'] as const

export function getProofRole(proofRecord: ProofExchangeRecord) {
  // Proofs will only have an isVerified value when a presentation is verified, meaning we're the verifier
  if (proofRecord.isVerified !== undefined) {
    return V02_03MigrationProofRole.Verifier
  }
  // If proofRecord.isVerified doesn't have any value, and we're also not in state done it means we're the prover.
  else if (proofRecord.state === ProofState.Done) {
    return V02_03MigrationProofRole.Prover
  }
  // For these states we know for certain that we're the prover
  else if (proverProofStates.includes(proofRecord.state)) {
    return V02_03MigrationProofRole.Prover
  }

  // For all other states we can be certain we're the verifier
  return V02_03MigrationProofRole.Verifier
}

/**
 * With the addition of support for different protocol versions the proof record now stores the protocol version.
 *
 * The following 0.2.0 proof record structure (unrelated keys omitted):
 *
 * ```json
 * {
 * }
 * ```
 *
 * Will be transformed into the following 0.3.0 structure (unrelated keys omitted):
 *
 * ```json
 * {
 *  "protocolVersion: "v1"
 * }
 * ```
 */
export async function migrateInternalProofExchangeRecordProperties<Agent extends BaseAgent>(
  agent: Agent,
  proofRecord: ProofExchangeRecord
) {
  agent.config.logger.debug(`Migrating internal proof record ${proofRecord.id} properties to storage version 0.3`)

  if (!proofRecord.protocolVersion) {
    agent.config.logger.debug(`Setting protocolVersion to v1`)
    proofRecord.protocolVersion = 'v1'
  }

  agent.config.logger.debug(
    `Successfully migrated internal proof record ${proofRecord.id} properties to storage version 0.3`
  )
}

/**
 * In 0.3.0 the v1 didcomm messages have been moved out of the proof record into separate record using the DidCommMessageRepository.
 * This migration scripts extracts all message (proposalMessage, requestMessage, presentationMessage) and moves
 * them into the DidCommMessageRepository.
 */
export async function moveDidCommMessages<Agent extends BaseAgent>(agent: Agent, proofRecord: ProofExchangeRecord) {
  agent.config.logger.debug(
    `Moving didcomm messages from proof record with id ${proofRecord.id} to DidCommMessageRecord`
  )
  const didCommMessageRepository = agent.dependencyManager.resolve(DidCommMessageRepository)

  for (const messageKey of proofRecordMessageKeys) {
    agent.config.logger.debug(
      `Starting move of ${messageKey} from proof record with id ${proofRecord.id} to DIDCommMessageRecord`
    )
    const proofRecordJson = proofRecord as unknown as JsonObject
    const message = proofRecordJson[messageKey] as PlaintextMessage | undefined

    if (message) {
      const proofRole = getProofRole(proofRecord)
      const didCommMessageRole = didCommMessageRoleMapping[proofRole][messageKey]

      const didCommMessageRecord = new DidCommMessageRecord({
        role: didCommMessageRole,
        associatedRecordId: proofRecord.id,
        message,
      })
      await didCommMessageRepository.save(agent.context, didCommMessageRecord)

      agent.config.logger.debug(
        `Successfully moved ${messageKey} from proof record with id ${proofRecord.id} to DIDCommMessageRecord`
      )

      delete proofRecordJson[messageKey]
    } else {
      agent.config.logger.debug(
        `Proof record with id ${proofRecord.id} does not have a ${messageKey}. Not creating a DIDCommMessageRecord`
      )
    }
  }

  agent.config.logger.debug(
    `Successfully moved didcomm messages from proof record with id ${proofRecord.id} to DIDCommMessageRecord`
  )
}
