import type { Routing } from './ConnectionService'
import type { AgentContext } from '../../../agent'
import type { InboundMessageContext } from '../../../agent/models/InboundMessageContext'
import type { ConnectionRecord } from '../repository/ConnectionRecord'

import { EventEmitter } from '../../../agent/EventEmitter'
import { OutboundMessageContext } from '../../../agent/models'
import { InjectionSymbols } from '../../../constants'
import { AriesFrameworkError } from '../../../error'
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
import { ConnectionsModuleConfig } from '../ConnectionsModuleConfig'
import { RotateMessage, RotateAckMessage, DidRotateProblemReportMessage, HangupMessage } from '../messages'
import { ConnectionMetadataKeys } from '../repository/ConnectionMetadataTypes'

import { ConnectionService } from './ConnectionService'
import { createPeerDidFromServices, getDidDocumentForCreatedDid, routingToServices } from './helpers'

@injectable()
export class DidRotateService {
  private eventEmitter: EventEmitter
  private didResolverService: DidResolverService
  private logger: Logger

  public constructor(
    eventEmitter: EventEmitter,
    didResolverService: DidResolverService,
    @inject(InjectionSymbols.Logger) logger: Logger
  ) {
    this.eventEmitter = eventEmitter
    this.didResolverService = didResolverService
    this.logger = logger
  }

  public async createRotate(
    agentContext: AgentContext,
    options: { connection: ConnectionRecord; did?: string; routing: Routing }
  ) {
    const { connection, did, routing } = options

    const config = agentContext.dependencyManager.resolve(ConnectionsModuleConfig)

    // Do not allow to receive concurrent did rotation flows
    const didRotateMetadata = connection.metadata.get(ConnectionMetadataKeys.DidRotate)

    if (didRotateMetadata) {
      this.logger.warn(`There is already an existing opened did rotation flow for connection id ${connection.id}`)
    }

    let didDocument, mediatorId
    // If did is specified, make sure we have all key material for it
    if (did) {
      didDocument = await getDidDocumentForCreatedDid(agentContext, did)
      mediatorId = (await getMediationRecordForDidDocument(agentContext, didDocument))?.id

      // Otherwise, create a did:peer based on the provided routing
    } else {
      didDocument = await createPeerDidFromServices(
        agentContext,
        routingToServices(routing),
        config.peerNumAlgoForDidRotation
      )
      mediatorId = routing.mediatorId
    }

    const message = new RotateMessage({ did: didDocument.id })

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
    connection.did = undefined

    await agentContext.dependencyManager.resolve(ConnectionService).update(agentContext, connection)

    return message
  }

  /**
   * Process a Hangup message and mark connection's theirDid as undefined so it is effectively terminated.
   * Connection Record itself is not deleted (TODO: config parameter to automatically do so)
   *
   * Its previous did will be stored as a tag in order to be able to recognize any message received
   * afterwards.
   *
   * @param messageContext
   */
  public async processHangup(messageContext: InboundMessageContext<RotateAckMessage>) {
    const connection = messageContext.assertReadyConnection()
    const { agentContext } = messageContext

    const previousTheirDids = connection.getTag('previousTheirDids')
    if (connection.theirDid) {
      connection.setTag(
        'previousTheirDids',
        Array.isArray(previousTheirDids) ? [...previousTheirDids, connection.theirDid] : [connection.theirDid]
      )
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
  public async processRotate(messageContext: InboundMessageContext<RotateMessage>) {
    const connection = messageContext.assertReadyConnection()
    const { message, agentContext } = messageContext

    // Check and store their new did
    const newDid = message.did

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

    // Send acknowledge to previous did and persist new did. Previous did will be stored in connection tags in
    // order to still accept messages from it
    const outboundMessageContext = new OutboundMessageContext(
      new RotateAckMessage({
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
        recipientKeyFingerprints: didDocument.recipientKeys.map((key) => key.fingerprint),

        // For did:peer, store any alternative dids (like short form did:peer:4),
        // it may have in order to relate any message referencing it
        alternativeDids: isValidPeerDid(didDocument.id) ? getAlternativeDidsForPeerDid(didDocument.id) : undefined,
      },
    })

    if (connection.theirDid) {
      connection.previousTheirDids = [...connection.previousTheirDids, connection.theirDid]
    }

    connection.theirDid = newDid

    await agentContext.dependencyManager.resolve(ConnectionService).update(agentContext, connection)

    return outboundMessageContext
  }

  public async processRotateAck(inboundMessage: InboundMessageContext<RotateAckMessage>) {
    const { agentContext, message } = inboundMessage

    const connection = inboundMessage.assertReadyConnection()

    // Update connection info based on metadata set when creating the rotate message
    const didRotateMetadata = connection.metadata.get(ConnectionMetadataKeys.DidRotate)

    if (!didRotateMetadata) {
      throw new AriesFrameworkError(`No did rotation data found for connection with id '${connection.id}'`)
    }

    if (didRotateMetadata.threadId !== message.threadId) {
      throw new AriesFrameworkError(
        `Existing did rotation flow thread id '${didRotateMetadata.threadId} does not match incoming message'`
      )
    }

    // Store previous did in order to still accept out-of-order messages that arrived later using it
    if (connection.did) connection.previousDids = [...connection.previousDids, connection.did]

    connection.did = didRotateMetadata.did
    connection.mediatorId = didRotateMetadata.mediatorId
    connection.metadata.delete(ConnectionMetadataKeys.DidRotate)

    await agentContext.dependencyManager.resolve(ConnectionService).update(agentContext, connection)
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
      throw new AriesFrameworkError(`No did rotation data found for connection with id '${connection.id}'`)
    }

    connection.metadata.delete(ConnectionMetadataKeys.DidRotate)

    await agentContext.dependencyManager.resolve(ConnectionService).update(agentContext, connection)
  }
}
