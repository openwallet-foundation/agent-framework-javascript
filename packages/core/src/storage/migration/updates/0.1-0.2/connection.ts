import type { Agent } from '../../../../agent/Agent'
import type { ConnectionRecord } from '../../../../modules/connections'
import type { JsonObject } from '../../../../types'

import {
  ConnectionState,
  ConnectionInvitationMessage,
  ConnectionRole,
  DidDoc,
  ConnectionRepository,
} from '../../../../modules/connections'
import { convertToNewDidDocument } from '../../../../modules/connections/services/helpers'
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
 *  - {@link extractDidDocument}
 *  - {@link migrateToOobRecord}
 */
export async function migrateConnectionRecordToV0_2(agent: Agent) {
  agent.config.logger.info('Migrating connection records to storage version 0.2')
  const connectionRepository = agent.injectionContainer.resolve(ConnectionRepository)

  agent.config.logger.debug(`Fetching all connection records from storage`)
  const allConnections = await connectionRepository.getAll()

  agent.config.logger.debug(`Found a total of ${allConnections.length} connection records to update.`)
  for (const connectionRecord of allConnections) {
    agent.config.logger.debug(`Migrating connection record with id ${connectionRecord.id} to storage version 0.2`)

    await extractDidDocument(agent, connectionRecord)
    // migration of oob record MUST run after extracting the did document as it relies on the updated did
    await migrateToOobRecord(agent, connectionRecord)

    await connectionRepository.update(connectionRecord)

    agent.config.logger.debug(
      `Successfully migrated connection record with id ${connectionRecord.id} to storage version 0.2`
    )
  }
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
export async function extractDidDocument(agent: Agent, connectionRecord: ConnectionRecord) {
  agent.config.logger.debug(
    `Extracting 'didDoc' and 'theirDidDoc' from connection record into separate DidRecord and updating unqualified dids to did:peer dids`
  )

  // TODO: add logs

  const didRepository = agent.injectionContainer.resolve(DidRepository)

  const untypedConnectionRecord = connectionRecord as unknown as JsonObject
  const oldDidDocJson = untypedConnectionRecord.didDoc as JsonObject | undefined
  const oldTheirDidDocJson = untypedConnectionRecord.theirDidDoc as JsonObject | undefined

  // FIXME: what to do if the did is not a fully qualified did, but there is no did document? I think we should just ignore it, it will cause issues
  // when the did is used in the future, but it doesn't break the whole storage. In theory this should never happen

  if (oldDidDocJson) {
    const oldDidDoc = JsonTransformer.fromJSON(oldDidDocJson, DidDoc)

    // FIXME: revamp the implementation of convertToNewDidDocument. However this already gives us a did:peer:1
    // that can be used to create a new did record.
    // FIXME: How do we decide on the peer did numAlgo to use? Should we store the old record until we know
    // what the community coordinated update is going to look like?
    const newDidDocument = convertToNewDidDocument(oldDidDoc)

    // Maybe we already have a record for this did because the migration failed previously
    let didRecord = await didRepository.findById(newDidDocument.id)

    if (!didRecord) {
      didRecord = new DidRecord({
        id: newDidDocument.id,
        role: DidDocumentRole.Created,
        didDocument: newDidDocument,
        createdAt: connectionRecord.createdAt,
        tags: {
          recipientKeys: newDidDocument.recipientKeys,
        },
      })

      didRecord.metadata.set(DidRecordMetadataKeys.LegacyDid, {
        unqualifiedDid: oldDidDoc.id,
        didDocumentString: JsonEncoder.toString(oldDidDocJson),
      })

      await didRepository.save(didRecord)
    }

    // Remove didDoc and assign the new did:peer did to did
    delete untypedConnectionRecord.didDoc
    connectionRecord.did = newDidDocument.id
  }

  if (oldTheirDidDocJson) {
    const oldTheirDidDoc = JsonTransformer.fromJSON(oldTheirDidDocJson, DidDoc)

    // FIXME: revamp the implementation of convertToNewDidDocument. However this already gives us a did:peer:1
    // that can be used to create a new did record.
    // FIXME: How do we decide on the peer did numAlgo to use? Should we store the old record until we know
    // what the community coordinated update is going to look like?
    const newTheirDidDocument = convertToNewDidDocument(oldTheirDidDoc)

    // Maybe we already have a record for this did because the migration failed previously
    let didRecord = await didRepository.findById(newTheirDidDocument.id)

    if (!didRecord) {
      didRecord = new DidRecord({
        id: newTheirDidDocument.id,
        role: DidDocumentRole.Received,
        didDocument: newTheirDidDocument,
        createdAt: connectionRecord.createdAt,
        tags: {
          recipientKeys: newTheirDidDocument.recipientKeys,
        },
      })

      didRecord.metadata.set(DidRecordMetadataKeys.LegacyDid, {
        unqualifiedDid: oldTheirDidDoc.id,
        didDocumentString: JsonEncoder.toString(oldTheirDidDocJson),
      })

      await didRepository.save(didRecord)
    }

    // Remove theirDidDoc and assign the new did:peer did to theirDid
    delete untypedConnectionRecord.theirDidDoc
    connectionRecord.theirDid = newTheirDidDocument.id
  }
}

/**
 * With the addition of the out of band protocol, invitations are now stored in the {@link OutOfBandRecord}. In addition a new field `invitationDid` is added to the connection record that
 * is generated based on the invitation service or did. This allows to reuse existing connections.
 *
 * This migration method extracts the invitation and other relevant data into a separate {@link OutOfBandRecord}. By doing so it converts the old connection protocol invitation into the new
 * Out of band invitation message. Based on the service or did of the invitation, the `invitationDid` is populated.
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
 *   }
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
export async function migrateToOobRecord(agent: Agent, connectionRecord: ConnectionRecord) {
  agent.config.logger.debug(`Migrating properties from connection record with id ${connectionRecord.id} to OOB record`)

  // TODO: add logs

  const oobRepository = agent.injectionContainer.resolve(OutOfBandRepository)

  const untypedConnectionRecord = connectionRecord as unknown as JsonObject
  const oldInvitationJson = untypedConnectionRecord.invitation as JsonObject | undefined

  // Only migrate if there is an invitation stored
  if (oldInvitationJson) {
    const oldInvitation = JsonTransformer.fromJSON(oldInvitationJson, ConnectionInvitationMessage)

    // FIXME: it could potentially happen that multiple invitations exist with the same id
    // This would mean we don't migrate the invitation. Are there other ways to detect whether
    // the connection record is already migrated?
    let [oobRecord] = await oobRepository.findByQuery({ messageId: oldInvitation.id })

    if (!oobRecord) {
      // FIXME: not sure if the accept profiles in the converted invitation are correct
      const outOfBandInvitation = convertToNewInvitation(oldInvitation)

      const oobRole = connectionRecord.role === ConnectionRole.Inviter ? OutOfBandRole.Sender : OutOfBandRole.Receiver

      const connectionRole = connectionRecord.role as ConnectionRole
      const connectionState = connectionRecord.state as ConnectionState
      const oobState = oobStateFromConnectionRoleAndState(connectionRole, connectionState)

      oobRecord = new OutOfBandRecord({
        role: oobRole,
        state: oobState,
        autoAcceptConnection: connectionRecord.autoAcceptConnection,
        did: connectionRecord.did,
        outOfBandMessage: outOfBandInvitation,
        reusable: connectionRecord.multiUseInvitation,
        mediatorId: connectionRecord.mediatorId,
        createdAt: connectionRecord.createdAt,
      })

      await oobRepository.save(oobRecord)
    }

    // All connections have been made using the connection protocol, which means we can be certain
    // that there was only one service, thus we can use the first oob message service
    const [invitationDid] = oobRecord.outOfBandMessage.invitationDids
    connectionRecord.invitationDid = invitationDid

    // Remove invitation and assign the oob id to the connection record
    delete untypedConnectionRecord.invitation
    connectionRecord.outOfBandId = oobRecord.id
  }
}

/**
 * Determine the out of band state based on the connection role and state.
 */
export function oobStateFromConnectionRoleAndState(role: ConnectionRole, state: ConnectionState) {
  // FIXME: other places in the framework are not transitioning at the correct moment
  // This does follow the correct mapping but can cause issues if we don't update the other parts
  const stateMapping = {
    [ConnectionRole.Invitee]: {
      [ConnectionState.Invited]: OutOfBandState.PrepareResponse,
      [ConnectionState.Requested]: OutOfBandState.Done,
      [ConnectionState.Responded]: OutOfBandState.Done,
      [ConnectionState.Complete]: OutOfBandState.Done,
    },
    [ConnectionRole.Inviter]: {
      [ConnectionState.Invited]: OutOfBandState.AwaitResponse,
      [ConnectionState.Requested]: OutOfBandState.Done,
      [ConnectionState.Responded]: OutOfBandState.Done,
      [ConnectionState.Complete]: OutOfBandState.Done,
    },
  }

  return stateMapping[role][state]
}
