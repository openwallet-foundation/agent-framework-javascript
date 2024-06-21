import type { Routing } from './ConnectionService'
import type { AgentContext } from '../../../agent'
import type { InboundMessageContext } from '../../../agent/models/InboundMessageContext'
import type { ConnectionDidRotatedEvent } from '../ConnectionEvents'
import type { ConnectionRecord } from '../repository/ConnectionRecord'

import { EventEmitter } from '../../../agent/EventEmitter'
import { OutboundMessageContext } from '../../../agent/models'
import { InjectionSymbols } from '../../../constants'
import { CredoError } from '../../../error'
import { Logger } from '../../../logger'
import { inject, injectable } from '../../../plugins'
import { AckStatus } from '../../common'
import {
  DidRepository,
  DidResolverService,
  PeerDidNumAlgo,
  getAlternativeDidsForPeerDid,
  getNumAlgoFromPeerDid,
  isValidPeerDid,
} from '../../dids'
import { getMediationRecordForDidDocument } from '../../routing/services/helpers'
import { ConnectionEventTypes } from '../ConnectionEvents'
import { ConnectionsModuleConfig } from '../ConnectionsModuleConfig'
import { DidRotateMessage, DidRotateAckMessage, DidRotateProblemReportMessage, HangupMessage } from '../messages'
import { ConnectionMetadataKeys } from '../repository/ConnectionMetadataTypes'

import { ConnectionService } from './ConnectionService'
import { createPeerDidFromServices, getDidDocumentForCreatedDid, routingToServices } from './helpers'

@injectable()
export class DidRotateService {
  private didResolverService: DidResolverService
  private logger: Logger
  private eventEmitter: EventEmitter

  public constructor(
    didResolverService: DidResolverService,
    @inject(InjectionSymbols.Logger) logger: Logger,
    eventEmitter: EventEmitter
  ) {
    this.didResolverService = didResolverService
    this.logger = logger
    this.eventEmitter = eventEmitter
  }

  public async createRotate(
    agentContext: AgentContext,
    options: { connection: ConnectionRecord; toDid?: string; routing?: Routing }
  ) {
    const { connection, toDid, routing } = options

    const config = agentContext.dependencyManager.resolve(ConnectionsModuleConfig)

    // Do not allow to receive concurrent did rotation flows
    const didRotateMetadata = connection.metadata.get(ConnectionMetadataKeys.DidRotate)

    if (didRotateMetadata) {
      throw new CredoError(`There is already an existing opened did rotation flow for connection id ${connection.id}`)
    }

    let didDocument, mediatorId
    // If did is specified, make sure we have all key material for it
    if (toDid) {
      didDocument = await getDidDocumentForCreatedDid(agentContext, toDid)
      mediatorId = (await getMediationRecordForDidDocument(agentContext, didDocument))?.id

      // Otherwise, create a did:peer based on the provided routing
    } else {
      if (!routing) {
        throw new CredoError('Routing configuration must be defined when rotating to a new peer did')
      }

      didDocument = await createPeerDidFromServices(
        agentContext,
        routingToServices(routing),
        config.peerNumAlgoForDidRotation
      )
      mediatorId = routing.mediatorId
    }

    const message = new DidRotateMessage({ toDid: didDocument.id })

    // We set new info into connection metadata for further 'sealing' it once we receive an acknowledge
    // All messages sent in-between will be using previous connection information
    connection.metadata.set(ConnectionMetadataKeys.DidRotate, {
      threadId: message.threadId,
      did: didDocument.id,
      mediatorId,
    })

    await agentContext.dependencyManager.resolve(ConnectionService).update(agentContext, connection)

    return message
  }

  public async createHangup(agentContext: AgentContext, options: { connection: ConnectionRecord }) {
    const { connection } = options

    const message = new HangupMessage({})

    // Remove did to indicate termination status for this connection
    if (connection.did) {
      connection.previousDids = [...connection.previousDids, connection.did]
    }

    connection.did = undefined

    await agentContext.dependencyManager.resolve(ConnectionService).update(agentContext, connection)

    return message
  }

  /**
   * Process a Hangup message and mark connection's theirDid as undefined so it is effectively terminated.
   * Connection Record itself is not deleted (TODO: config parameter to automatically do so)
   *
   * Its previous did will be stored in record in order to be able to recognize any message received
   * afterwards.
   *
   * @param messageContext
   */
  public async processHangup(messageContext: InboundMessageContext<HangupMessage>) {
    const connection = messageContext.assertReadyConnection()
    const { agentContext } = messageContext

    if (connection.theirDid) {
      connection.previousTheirDids = [...connection.previousTheirDids, connection.theirDid]
    }

    connection.theirDid = undefined

    await agentContext.dependencyManager.resolve(ConnectionService).update(agentContext, connection)
  }

  /**
   * Process an incoming DID Rotate message and update connection if success. Any acknowledge
   * or problem report will be sent to the prior DID, so the created context will take former
   * connection record data
   *
   * @param param
   * @param connection
   * @returns
   */
  public async processRotate(messageContext: InboundMessageContext<DidRotateMessage>) {
    const connection = messageContext.assertReadyConnection()
    const { message, agentContext } = messageContext

    // Check and store their new did
    const newDid = message.toDid

    // DID Rotation not supported for peer:1 dids, as we need explicit did document information
    if (isValidPeerDid(newDid) && getNumAlgoFromPeerDid(newDid) === PeerDidNumAlgo.GenesisDoc) {
      this.logger.error(`Unable to resolve DID Document for '${newDid}`)

      const response = new DidRotateProblemReportMessage({
        description: { en: 'DID Method Unsupported', code: 'e.did.method_unsupported' },
      })
      return new OutboundMessageContext(response, { agentContext, connection })
    }

    const didDocument = (await this.didResolverService.resolve(agentContext, newDid)).didDocument

    // Cannot resolve did
    if (!didDocument) {
      this.logger.error(`Unable to resolve DID Document for '${newDid}`)

      const response = new DidRotateProblemReportMessage({
        description: { en: 'DID Unresolvable', code: 'e.did.unresolvable' },
      })
      return new OutboundMessageContext(response, { agentContext, connection })
    }

    // Did is resolved but no compatible DIDComm services found
    if (!didDocument.didCommServices) {
      const response = new DidRotateProblemReportMessage({
        description: { en: 'DID Document Unsupported', code: 'e.did.doc_unsupported' },
      })
      return new OutboundMessageContext(response, { agentContext, connection })
    }

    // Send acknowledge to previous did and persist new did. Previous did will be stored in connection record in
    // order to still accept messages from it
    const outboundMessageContext = new OutboundMessageContext(
      new DidRotateAckMessage({
        threadId: message.threadId,
        status: AckStatus.OK,
      }),
      { agentContext, connection: connection.clone() }
    )

    // Store received did and update connection for further message processing
    await agentContext.dependencyManager.resolve(DidRepository).storeReceivedDid(agentContext, {
      did: didDocument.id,
      didDocument,
      tags: {
        // For did:peer, store any alternative dids (like short form did:peer:4),
        // it may have in order to relate any message referencing it
        alternativeDids: isValidPeerDid(didDocument.id) ? getAlternativeDidsForPeerDid(didDocument.id) : undefined,
      },
    })

    if (connection.theirDid) {
      connection.previousTheirDids = [...connection.previousTheirDids, connection.theirDid]
    }

    const previousTheirDid = connection.theirDid
    connection.theirDid = newDid

    await agentContext.dependencyManager.resolve(ConnectionService).update(agentContext, connection)
    this.emitDidRotatedEvent(agentContext, connection, {
      previousTheirDid,
    })

    return outboundMessageContext
  }

  public async processRotateAck(inboundMessage: InboundMessageContext<DidRotateAckMessage>) {
    const { agentContext, message } = inboundMessage

    const connection = inboundMessage.assertReadyConnection()

    // Update connection info based on metadata set when creating the rotate message
    const didRotateMetadata = connection.metadata.get(ConnectionMetadataKeys.DidRotate)

    if (!didRotateMetadata) {
      throw new CredoError(`No did rotation data found for connection with id '${connection.id}'`)
    }

    if (didRotateMetadata.threadId !== message.threadId) {
      throw new CredoError(
        `Existing did rotation flow thread id '${didRotateMetadata.threadId} does not match incoming message'`
      )
    }

    // Store previous did in order to still accept out-of-order messages that arrived later using it
    if (connection.did) connection.previousDids = [...connection.previousDids, connection.did]

    const previousOurDid = connection.did
    connection.did = didRotateMetadata.did
    connection.mediatorId = didRotateMetadata.mediatorId
    connection.metadata.delete(ConnectionMetadataKeys.DidRotate)

    await agentContext.dependencyManager.resolve(ConnectionService).update(agentContext, connection)
    this.emitDidRotatedEvent(agentContext, connection, {
      previousOurDid,
    })
  }

  /**
   * Process a problem report related to did rotate protocol, by simply deleting any temporary metadata.
   *
   * No specific event is thrown other than generic message processing
   *
   * @param messageContext
   */
  public async processProblemReport(
    messageContext: InboundMessageContext<DidRotateProblemReportMessage>
  ): Promise<void> {
    const { message, agentContext } = messageContext

    const connection = messageContext.assertReadyConnection()

    this.logger.debug(`Processing problem report with id ${message.id}`)

    // Delete any existing did rotation metadata in order to 'reset' the connection
    const didRotateMetadata = connection.metadata.get(ConnectionMetadataKeys.DidRotate)

    if (!didRotateMetadata) {
      throw new CredoError(`No did rotation data found for connection with id '${connection.id}'`)
    }

    connection.metadata.delete(ConnectionMetadataKeys.DidRotate)

    await agentContext.dependencyManager.resolve(ConnectionService).update(agentContext, connection)
  }

  public async clearDidRotationData(agentContext: AgentContext, connection: ConnectionRecord) {
    const didRotateMetadata = connection.metadata.get(ConnectionMetadataKeys.DidRotate)

    if (!didRotateMetadata) {
      throw new CredoError(`No did rotation data found for connection with id '${connection.id}'`)
    }

    connection.metadata.delete(ConnectionMetadataKeys.DidRotate)

    await agentContext.dependencyManager.resolve(ConnectionService).update(agentContext, connection)
  }

  private emitDidRotatedEvent(
    agentContext: AgentContext,
    connectionRecord: ConnectionRecord,
    { previousOurDid, previousTheirDid }: { previousOurDid?: string; previousTheirDid?: string }
  ) {
    this.eventEmitter.emit<ConnectionDidRotatedEvent>(agentContext, {
      type: ConnectionEventTypes.ConnectionDidRotated,
      payload: {
        // Connection record in event should be static
        connectionRecord: connectionRecord.clone(),

        ourDid:
          previousOurDid && connectionRecord.did
            ? {
                from: previousOurDid,
                to: connectionRecord.did,
              }
            : undefined,

        theirDid:
          previousTheirDid && connectionRecord.theirDid
            ? {
                from: previousTheirDid,
                to: connectionRecord.theirDid,
              }
            : undefined,
      },
    })
  }
}
