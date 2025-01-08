import type { BaseAgent } from '@credo-ts/core'

import { CredoError } from '@credo-ts/core'
import {
  ProofRepository,
  ProofRole,
  ProofState,
  V2ProposePresentationMessage,
  V2RequestPresentationMessage,
  type ProofExchangeRecord,
} from '../../modules/proofs'
import { DidCommMessageRepository, DidCommMessageRole } from '../../repository'
import { parseMessageType } from '../../util/messageType'

/**
 * Migrates the {@link ProofExchangeExchangeRecord} to 0.5 compatible format. It fetches all proof exchange records from
 *  storage and applies the needed updates to the records. After a record has been transformed, it is updated
 * in storage and the next record will be transformed.
 *
 * The following transformations are applied:
 *  - {@link migrateRole}
 */
export async function migrateProofExchangeRecordToV0_5<Agent extends BaseAgent>(agent: Agent) {
  agent.config.logger.info('Migrating proof exchange records to storage version 0.5')
  const proofRepository = agent.dependencyManager.resolve(ProofRepository)

  agent.config.logger.debug(`Fetching all proof records from storage`)
  const proofRecords = await proofRepository.getAll(agent.context)

  agent.config.logger.debug(`Found a total of ${proofRecords.length} proof exchange records to update.`)
  for (const proofRecord of proofRecords) {
    agent.config.logger.debug(`Migrating proof exchange record with id ${proofRecord.id} to storage version 0.5`)

    await migrateRole(agent, proofRecord)

    // Save updated record
    await proofRepository.update(agent.context, proofRecord)

    agent.config.logger.debug(
      `Successfully migrated proof exchange record with id ${proofRecord.id} to storage version 0.5`
    )
  }
}

const proverProofStates = [
  ProofState.RequestReceived,
  ProofState.ProposalSent,
  ProofState.PresentationSent,
  ProofState.Declined,
]
const verifierProofStates = [ProofState.RequestSent, ProofState.ProposalReceived, ProofState.PresentationReceived]

export async function getProofRole(agent: BaseAgent, proofRecord: ProofExchangeRecord) {
  // For these states we know for certain that we're the prover
  if (proverProofStates.includes(proofRecord.state)) {
    return ProofRole.Prover
  }
  // For these states we know for certain that we're the verifier
  else if (verifierProofStates.includes(proofRecord.state)) {
    return ProofRole.Verifier
  }

  // We now need to determine the role based on the didcomm message. Only the Done and Abandoned states
  // remain and we can't be certain of the role based on the state alone.

  // Fetch any of the associated proof messages that we can use to determine the role
  // Either one of these MUST be present or we can't determine the role.
  const didCommMessageRepository = agent.dependencyManager.resolve(DidCommMessageRepository)
  const [didCommMessageRecord] = await didCommMessageRepository.findByQuery(agent.context, {
    associatedRecordId: proofRecord.id,
    $or: [
      // We can't be certain which messages will be present.
      { messageName: V2ProposePresentationMessage.type.messageName },
      { messageName: V2RequestPresentationMessage.type.messageName },
    ],
  })

  if (!didCommMessageRecord) {
    throw new CredoError(
      `Unable to determine the role of the proof exchange record with id ${proofRecord.id} without any didcomm messages and state abandoned/done`
    )
  }

  // Maps the message name and the didcomm message role to the respective proof role
  const roleStateMapping = {
    [V2ProposePresentationMessage.type.messageName]: {
      [DidCommMessageRole.Sender]: ProofRole.Prover,
      [DidCommMessageRole.Receiver]: ProofRole.Verifier,
    },
    [V2RequestPresentationMessage.type.messageName]: {
      [DidCommMessageRole.Sender]: ProofRole.Verifier,
      [DidCommMessageRole.Receiver]: ProofRole.Prover,
    },
  }

  const messageName = parseMessageType(didCommMessageRecord.message['@type']).messageName
  const proofRole = roleStateMapping[messageName][didCommMessageRecord.role]

  return proofRole
}

/**
 * Add a role to the proof record.
 */
export async function migrateRole<Agent extends BaseAgent>(agent: Agent, proofRecord: ProofExchangeRecord) {
  agent.config.logger.debug(`Adding role to record with id ${proofRecord.id} to for version 0.5`)

  proofRecord.role = await getProofRole(agent, proofRecord)

  agent.config.logger.debug(
    `Successfully updated role to '${proofRecord.role}' on proof record with id ${proofRecord.id} to for version 0.5`
  )
}
