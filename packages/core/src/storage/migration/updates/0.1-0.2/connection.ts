import type { BaseAgent } from '../../../../agent/BaseAgent'
import type { ConnectionRecord } from '../../../../modules/connections'
import type { JsonObject } from '../../../../types'

import { outOfBandServiceToInlineKeysNumAlgo2Did } from '../../../..//modules/dids/methods/peer/peerDidNumAlgo2'
import {
  DidExchangeState,
  ConnectionState,
  ConnectionInvitationMessage,
  ConnectionRole,
  DidDoc,
  ConnectionRepository,
  DidExchangeRole,
} from '../../../../modules/connections'
import { convertToNewDidDocument } from '../../../../modules/connections/services/helpers'
import { DidKey } from '../../../../modules/dids'
import { DidDocumentRole } from '../../../../modules/dids/domain/DidDocumentRole'
import { DidRecord, DidRepository } from '../../../../modules/dids/repository'
import { DidRecordMetadataKeys } from '../../../../modules/dids/repository/didRecordMetadataTypes'
import { OutOfBandRole } from '../../../../modules/oob/domain/OutOfBandRole'
import { OutOfBandState } from '../../../../modules/oob/domain/OutOfBandState'
import { convertToNewInvitation } from '../../../../modules/oob/helpers'
import { OutOfBandRecord, OutOfBandRepository } from '../../../../modules/oob/repository'
import { JsonEncoder, JsonTransformer } from '../../../../utils'

/**
 * Migrates the {@link ConnectionRecord} to 0.2 compatible format. It fetches all records from storage
 * and applies the needed updates to the records. After a record has been transformed, it is updated
 * in storage and the next record will be transformed.
 *
 * The following transformations are applied:
 *  - {@link updateConnectionRoleAndState}
 *  - {@link extractDidDocument}
 *  - {@link migrateToOobRecord}
 */
export async function migrateConnectionRecordToV0_2<Agent extends BaseAgent>(agent: Agent) {
  agent.config.logger.info('Migrating connection records to storage version 0.2')
  const connectionRepository = agent.dependencyManager.resolve(ConnectionRepository)

  agent.config.logger.debug(`Fetching all connection records from storage`)
  const allConnections = await connectionRepository.getAll(agent.context)

  agent.config.logger.debug(`Found a total of ${allConnections.length} connection records to update.`)
  for (const connectionRecord of allConnections) {
    agent.config.logger.debug(`Migrating connection record with id ${connectionRecord.id} to storage version 0.2`)
    await updateConnectionRoleAndState(agent, connectionRecord)
    await extractDidDocument(agent, connectionRecord)

    // migration of oob record MUST run after extracting the did document as it relies on the updated did
    // it also MUST run after update the connection role and state as it assumes the values are
    // did exchange roles and states
    const _connectionRecord = await migrateToOobRecord(agent, connectionRecord)

    // migrateToOobRecord will return the connection record if it has not been deleted. When using multiUseInvitation the connection record
    // will be removed after processing, in which case the update method will throw an error.
    if (_connectionRecord) {
      await connectionRepository.update(agent.context, connectionRecord)
    }

    agent.config.logger.debug(
      `Successfully migrated connection record with id ${connectionRecord.id} to storage version 0.2`
    )
  }
}

/**
 * With the addition of the did exchange protocol there are now two states and roles related to the connection record; for the did exchange protocol and for the connection protocol.
 * To keep it easy to work with the connection record, all state and role values are updated to those of the {@link DidExchangeRole} and {@link DidExchangeState}.
 *
 * This migration method transforms all connection record state and role values to their respective values of the {@link DidExchangeRole} and {@link DidExchangeState}. For convenience a getter
 * property `rfc0160ConnectionState` is added to the connection record which returns the {@link ConnectionState} value.
 *
 * The following 0.1.0 connection record structure (unrelated keys omitted):
 *
 * ```json
 * {
 *   "state": "invited",
 *   "role": "inviter"
 * }
 * ```
 *
 * Will be transformed into the following 0.2.0 structure (unrelated keys omitted):
 *
 * ```json
 * {
 *   "state": "invitation-sent",
 *   "role": "responder",
 * }
 * ```
 */
export async function updateConnectionRoleAndState<Agent extends BaseAgent>(
  agent: Agent,
  connectionRecord: ConnectionRecord
) {
  agent.config.logger.debug(
    `Extracting 'didDoc' and 'theirDidDoc' from connection record into separate DidRecord and updating unqualified dids to did:peer dids`
  )

  const oldState = connectionRecord.state
  const oldRole = connectionRecord.role

  const [didExchangeRole, didExchangeState] = didExchangeStateAndRoleFromRoleAndState(
    connectionRecord.role,
    connectionRecord.state
  )

  connectionRecord.role = didExchangeRole
  connectionRecord.state = didExchangeState

  agent.config.logger.debug(
    `Updated connection record state from ${oldState} to ${connectionRecord.state} and role from ${oldRole} to ${connectionRecord.role}`
  )
}

/**
 * The connection record previously stored both did documents from a connection in the connection record itself. Version 0.2.0 added a generic did storage that can be used for numerous usages, one of which
 * is the storage of did documents for connection records.
 *
 * This migration method extracts the did documents from the `didDoc` and `theirDidDoc` properties from the connection record, updates them to did documents compliant with the DID Core spec, and stores them
 * in the did repository. By doing so it also updates the unqualified dids in the `did` and `theirDid` fields generated by the indy-sdk to fully qualified `did:peer` dids compliant with
 * the [Peer DID Method Specification](https://identity.foundation/peer-did-method-spec/).
 *
 * To account for the fact that the mechanism to migrate legacy did document to peer did documents is not defined yet, the legacy did and did document are stored in the did record metadata.
 * This will be deleted later if we can be certain the did doc conversion to a did:peer did document is correct.
 *
 * The following 0.1.0 connection record structure (unrelated keys omitted):
 *
 * ```json
 * {
 *   "did": "BBPoJqRKatdcfLEAFL7exC",
 *   "theirDid": "N8NQHLtCKfPmWMgCSdfa7h",
 *   "didDoc": <legacyDidDoc>,
 *   "theirDidDoc": <legacyTheirDidDoc>,
 *   "verkey": "GjZWsBLgZCR18aL468JAT7w9CZRiBnpxUPPgyQxh4voa"
 * }
 * ```
 *
 * Will be transformed into the following 0.2.0 structure (unrelated keys omitted):
 *
 * ```json
 * {
 *   "did": "did:peer:1zQmXUaPPhPCbUVZ3hGYmQmGxWTwyDfhqESXCpMFhKaF9Y2A",
 *   "theirDid": "did:peer:1zQmZMygzYqNwU6Uhmewx5Xepf2VLp5S4HLSwwgf2aiKZuwa"
 * }
 * ```
 */
export async function extractDidDocument<Agent extends BaseAgent>(agent: Agent, connectionRecord: ConnectionRecord) {
  agent.config.logger.debug(
    `Extracting 'didDoc' and 'theirDidDoc' from connection record into separate DidRecord and updating unqualified dids to did:peer dids`
  )

  const didRepository = agent.dependencyManager.resolve(DidRepository)

  const untypedConnectionRecord = connectionRecord as unknown as JsonObject
  const oldOurDidDocJson = untypedConnectionRecord.didDoc as JsonObject | undefined
  const oldTheirDidDocJson = untypedConnectionRecord.theirDidDoc as JsonObject | undefined

  if (oldOurDidDocJson) {
    const oldOurDidDoc = JsonTransformer.fromJSON(oldOurDidDocJson, DidDoc)

    agent.config.logger.debug(
      `Found a legacy did document for did ${oldOurDidDoc.id} in connection record didDoc. Converting it to a peer did document.`
    )

    const newOurDidDocument = convertToNewDidDocument(oldOurDidDoc)

    // Maybe we already have a record for this did because the migration failed previously
    // NOTE: in 0.3.0 the id property was updated to be a uuid, and a new did property was added. As this is the update from 0.1 to 0.2,
    // the `id` property of the record is still the did here.
    let ourDidRecord = await didRepository.findById(agent.context, newOurDidDocument.id)

    if (!ourDidRecord) {
      agent.config.logger.debug(`Creating did record for our did ${newOurDidDocument.id}`)
      ourDidRecord = new DidRecord({
        // NOTE: in 0.3.0 the id property was updated to be a uuid, and a new did property was added. Here we make the id and did property both the did.
        // In the 0.3.0 update the `id` property will be updated to an uuid.
        id: newOurDidDocument.id,
        did: newOurDidDocument.id,
        role: DidDocumentRole.Created,
        didDocument: newOurDidDocument,
        createdAt: connectionRecord.createdAt,
      })

      ourDidRecord.metadata.set(DidRecordMetadataKeys.LegacyDid, {
        unqualifiedDid: oldOurDidDoc.id,
        didDocumentString: JsonEncoder.toString(oldOurDidDocJson),
      })

      await didRepository.save(agent.context, ourDidRecord)

      agent.config.logger.debug(`Successfully saved did record for did ${newOurDidDocument.id}`)
    } else {
      agent.config.logger.debug(`Found existing did record for did ${newOurDidDocument.id}, not creating did record.`)
    }

    agent.config.logger.debug(`Deleting old did document from connection record and storing new did:peer did`)
    // Remove didDoc and assign the new did:peer did to did
    delete untypedConnectionRecord.didDoc
    connectionRecord.did = newOurDidDocument.id
  } else {
    agent.config.logger.debug(
      `Did not find a did document in connection record didDoc. Not converting it to a peer did document.`
    )
  }

  if (oldTheirDidDocJson) {
    const oldTheirDidDoc = JsonTransformer.fromJSON(oldTheirDidDocJson, DidDoc)

    agent.config.logger.debug(
      `Found a legacy did document for theirDid ${oldTheirDidDoc.id} in connection record theirDidDoc. Converting it to a peer did document.`
    )

    const newTheirDidDocument = convertToNewDidDocument(oldTheirDidDoc)

    // Maybe we already have a record for this did because the migration failed previously
    // NOTE: in 0.3.0 the id property was updated to be a uuid, and a new did property was added. As this is the update from 0.1 to 0.2,
    // the `id` property of the record is still the did here.
    let theirDidRecord = await didRepository.findById(agent.context, newTheirDidDocument.id)

    if (!theirDidRecord) {
      agent.config.logger.debug(`Creating did record for theirDid ${newTheirDidDocument.id}`)

      theirDidRecord = new DidRecord({
        // NOTE: in 0.3.0 the id property was updated to be a uuid, and a new did property was added. Here we make the id and did property both the did.
        // In the 0.3.0 update the `id` property will be updated to an uuid.
        id: newTheirDidDocument.id,
        did: newTheirDidDocument.id,
        role: DidDocumentRole.Received,
        didDocument: newTheirDidDocument,
        createdAt: connectionRecord.createdAt,
      })

      theirDidRecord.metadata.set(DidRecordMetadataKeys.LegacyDid, {
        unqualifiedDid: oldTheirDidDoc.id,
        didDocumentString: JsonEncoder.toString(oldTheirDidDocJson),
      })

      await didRepository.save(agent.context, theirDidRecord)

      agent.config.logger.debug(`Successfully saved did record for theirDid ${newTheirDidDocument.id}`)
    } else {
      agent.config.logger.debug(
        `Found existing did record for theirDid ${newTheirDidDocument.id}, not creating did record.`
      )
    }

    agent.config.logger.debug(`Deleting old theirDidDoc from connection record and storing new did:peer theirDid`)
    // Remove theirDidDoc and assign the new did:peer did to theirDid
    delete untypedConnectionRecord.theirDidDoc
    connectionRecord.theirDid = newTheirDidDocument.id
  } else {
    agent.config.logger.debug(
      `Did not find a did document in connection record theirDidDoc. Not converting it to a peer did document.`
    )
  }

  // Delete legacy verkey property
  delete untypedConnectionRecord.verkey
}

/**
 * With the addition of the out of band protocol, invitations are now stored in the {@link OutOfBandRecord}. In addition a new field `invitationDid` is added to the connection record that
 * is generated based on the invitation service or did. This allows to reuse existing connections.
 *
 * This migration method extracts the invitation and other relevant data into a separate {@link OutOfBandRecord}. By doing so it converts the old connection protocol invitation into the new
 * Out of band invitation message. Based on the service or did of the invitation, the `invitationDid` is populated.
 *
 * Previously when creating a multi use invitation, a connection record would be created with the `multiUseInvitation` set to true. The connection record would always be in state `invited`.
 * If a request for the multi use invitation came in, a new connection record would be created. With the addition of the out of band module, no connection records are created until a request
 * is received. So for multi use invitation this means that the connection record with multiUseInvitation=true will be deleted, and instead all connections created using that out of band invitation
 * will contain the `outOfBandId` of the multi use invitation.
 *
 * The following 0.1.0 connection record structure (unrelated keys omitted):
 *
 * ```json
 * {
 *   "invitation": {
 *     "@type": "https://didcomm.org/connections/1.0/invitation",
 *     "@id": "04a2c382-999e-4de9-a1d2-9dec0b2fa5e4",
 *     "recipientKeys": ["E6D1m3eERqCueX4ZgMCY14B4NceAr6XP2HyVqt55gDhu"],
 *     "serviceEndpoint": "https://example.com",
 *     "label": "test",
 *   },
 *   "multiUseInvitation": false
 * }
 * ```
 *
 * Will be transformed into the following 0.2.0 structure (unrelated keys omitted):
 *
 * ```json
 * {
 *   "invitationDid": "did:peer:2.Ez6MksYU4MHtfmNhNm1uGMvANr9j4CBv2FymjiJtRgA36bSVH.SeyJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbSJ9",
 *   "outOfBandId": "04a2c382-999e-4de9-a1d2-9dec0b2fa5e4"
 * }
 * ```
 */
export async function migrateToOobRecord<Agent extends BaseAgent>(
  agent: Agent,
  connectionRecord: ConnectionRecord
): Promise<ConnectionRecord | undefined> {
  agent.config.logger.debug(
    `Migrating properties from connection record with id ${connectionRecord.id} to out of band record`
  )

  const oobRepository = agent.dependencyManager.resolve(OutOfBandRepository)
  const connectionRepository = agent.dependencyManager.resolve(ConnectionRepository)

  const untypedConnectionRecord = connectionRecord as unknown as JsonObject
  const oldInvitationJson = untypedConnectionRecord.invitation as JsonObject | undefined
  const oldMultiUseInvitation = untypedConnectionRecord.multiUseInvitation as boolean | undefined

  // Only migrate if there is an invitation stored
  if (oldInvitationJson) {
    const oldInvitation = JsonTransformer.fromJSON(oldInvitationJson, ConnectionInvitationMessage)

    agent.config.logger.debug(`Found a legacy invitation in connection record. Migrating it to an out of band record.`)

    const outOfBandInvitation = convertToNewInvitation(oldInvitation)

    // If both the recipientKeys, the @id and the role match we assume the connection was created using the same invitation.
    const recipientKeyFingerprints = outOfBandInvitation
      .getInlineServices()
      .map((s) => s.recipientKeys)
      .reduce((acc, curr) => [...acc, ...curr], [])
      .map((didKey) => DidKey.fromDid(didKey).key.fingerprint)

    const oobRole = connectionRecord.role === DidExchangeRole.Responder ? OutOfBandRole.Sender : OutOfBandRole.Receiver
    const oobRecords = await oobRepository.findByQuery(agent.context, {
      invitationId: oldInvitation.id,
      recipientKeyFingerprints,
      role: oobRole,
    })

    let oobRecord: OutOfBandRecord | undefined = oobRecords[0]

    if (!oobRecord) {
      agent.config.logger.debug(`Create out of band record.`)

      const connectionRole = connectionRecord.role as DidExchangeRole
      const connectionState = connectionRecord.state as DidExchangeState
      const oobState = oobStateFromDidExchangeRoleAndState(connectionRole, connectionState)

      oobRecord = new OutOfBandRecord({
        role: oobRole,
        state: oobState,
        alias: connectionRecord.alias,
        autoAcceptConnection: connectionRecord.autoAcceptConnection,
        outOfBandInvitation,
        reusable: oldMultiUseInvitation,
        mediatorId: connectionRecord.mediatorId,
        createdAt: connectionRecord.createdAt,
        tags: { recipientKeyFingerprints },
      })

      await oobRepository.save(agent.context, oobRecord)
      agent.config.logger.debug(`Successfully saved out of band record for invitation @id ${oldInvitation.id}`)
    } else {
      agent.config.logger.debug(
        `Found existing out of band record for invitation @id ${oldInvitation.id} and did ${connectionRecord.did}, not creating a new out of band record.`
      )
    }

    // We need to update the oob record with the reusable data. We don't know initially if an oob record is reusable or not, as there can be 1..n connections for each invitation
    // only when we find the multiUseInvitation we can update it.
    if (oldMultiUseInvitation) {
      oobRecord.reusable = true
      oobRecord.state = OutOfBandState.AwaitResponse
      oobRecord.mediatorId = connectionRecord.mediatorId
      oobRecord.autoAcceptConnection = connectionRecord.autoAcceptConnection

      await oobRepository.update(agent.context, oobRecord)
      await connectionRepository.delete(agent.context, connectionRecord)
      agent.config.logger.debug(
        `Set reusable=true for out of band record with invitation @id ${oobRecord.outOfBandInvitation.id} and role ${oobRole}.`
      )

      return
    }

    agent.config.logger.debug(`Setting invitationDid and outOfBand Id, and removing invitation from connection record`)
    // All connections have been made using the connection protocol, which means we can be certain
    // that there was only one service, thus we can use the first oob message service
    // Note: since this is an update from 0.1 to 0.2, we use former way of calculating numAlgo2Dids
    const [invitationDid] = [
      ...oobRecord.outOfBandInvitation.getDidServices(),
      ...oobRecord.outOfBandInvitation.getInlineServices().map(outOfBandServiceToInlineKeysNumAlgo2Did),
    ]
    connectionRecord.invitationDid = invitationDid

    // Remove invitation and assign the oob id to the connection record
    delete untypedConnectionRecord.invitation
    connectionRecord.outOfBandId = oobRecord.id
  }

  agent.config.logger.debug('Removing multiUseInvitation property from connection record')
  // multiUseInvitation is now stored as reusable in the out of band record
  delete untypedConnectionRecord.multiUseInvitation

  return connectionRecord
}

/**
 * Determine the out of band state based on the did exchange role and state.
 */
export function oobStateFromDidExchangeRoleAndState(role: DidExchangeRole, state: DidExchangeState) {
  const stateMapping = {
    [DidExchangeState.InvitationReceived]: OutOfBandState.PrepareResponse,
    [DidExchangeState.InvitationSent]: OutOfBandState.AwaitResponse,

    [DidExchangeState.RequestReceived]: OutOfBandState.Done,
    [DidExchangeState.RequestSent]: OutOfBandState.Done,

    [DidExchangeState.ResponseReceived]: OutOfBandState.Done,
    [DidExchangeState.ResponseSent]: OutOfBandState.Done,

    [DidExchangeState.Completed]: OutOfBandState.Done,
    [DidExchangeState.Abandoned]: OutOfBandState.Done,
  }

  if (state === DidExchangeState.Start) {
    return role === DidExchangeRole.Requester ? OutOfBandState.PrepareResponse : OutOfBandState.AwaitResponse
  }

  return stateMapping[state]
}

/**
 * Determine the did exchange state based on the connection/did-exchange role and state.
 */
export function didExchangeStateAndRoleFromRoleAndState(
  role: ConnectionRole | DidExchangeRole,
  state: ConnectionState | DidExchangeState
): [DidExchangeRole, DidExchangeState] {
  const roleMapping = {
    // Responder / Inviter
    [DidExchangeRole.Responder]: DidExchangeRole.Responder,
    [ConnectionRole.Inviter]: DidExchangeRole.Responder,

    // Request / Invitee
    [DidExchangeRole.Requester]: DidExchangeRole.Requester,
    [ConnectionRole.Invitee]: DidExchangeRole.Requester,
  }

  const roleStateMapping = {
    [DidExchangeRole.Requester]: {
      // DidExchangeRole.Requester
      [ConnectionState.Invited]: DidExchangeState.InvitationReceived,
      [ConnectionState.Requested]: DidExchangeState.RequestSent,
      [ConnectionState.Responded]: DidExchangeState.ResponseReceived,
      [ConnectionState.Complete]: DidExchangeState.Completed,
      [ConnectionState.Null]: DidExchangeState.Start,
    },
    [DidExchangeRole.Responder]: {
      // DidExchangeRole.Responder
      [ConnectionState.Invited]: DidExchangeState.InvitationSent,
      [ConnectionState.Requested]: DidExchangeState.RequestReceived,
      [ConnectionState.Responded]: DidExchangeState.ResponseSent,
      [ConnectionState.Complete]: DidExchangeState.Completed,
      [ConnectionState.Null]: DidExchangeState.Start,
    },
  }

  // Map the role to did exchange role. Can handle did exchange roles to make the function re-runnable
  const didExchangeRole = roleMapping[role]

  // Take into account possibility that the record state was already updated to
  // didExchange state and roles. This makes the script re-runnable and
  // adds some resiliency to the script.
  const stateMapping = roleStateMapping[didExchangeRole]

  // Check if state is a valid connection state
  if (isConnectionState(state)) {
    return [didExchangeRole, stateMapping[state]]
  }

  // If state is not a valid state we assume the state is already a did exchange state
  return [didExchangeRole, state]
}

function isConnectionState(state: string): state is ConnectionState {
  return Object.values(ConnectionState).includes(state as ConnectionState)
}
