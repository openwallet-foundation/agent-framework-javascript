import type { MessageHandler, MessageHandlerInboundMessage } from '../../../agent/MessageHandler'
import type { DidRepository } from '../../dids/repository'
import type { OutOfBandService } from '../../oob/OutOfBandService'
import type { RoutingService } from '../../routing/services/RoutingService'
import type { ConnectionsModuleConfig } from '../ConnectionsModuleConfig'
import type { ConnectionService } from '../services/ConnectionService'

import { TransportService } from '../../../agent/TransportService'
import { OutboundMessageContext } from '../../../agent/models'
import { CredoError } from '../../../error/CredoError'
import { tryParseDid } from '../../dids/domain/parse'
import { ConnectionRequestMessage } from '../messages'
import { HandshakeProtocol } from '../models'

export class ConnectionRequestHandler implements MessageHandler {
  private connectionService: ConnectionService
  private outOfBandService: OutOfBandService
  private routingService: RoutingService
  private didRepository: DidRepository
  private connectionsModuleConfig: ConnectionsModuleConfig
  public supportedMessages = [ConnectionRequestMessage]

  public constructor(
    connectionService: ConnectionService,
    outOfBandService: OutOfBandService,
    routingService: RoutingService,
    didRepository: DidRepository,
    connectionsModuleConfig: ConnectionsModuleConfig
  ) {
    this.connectionService = connectionService
    this.outOfBandService = outOfBandService
    this.routingService = routingService
    this.didRepository = didRepository
    this.connectionsModuleConfig = connectionsModuleConfig
  }

  public async handle(messageContext: MessageHandlerInboundMessage<ConnectionRequestHandler>) {
    const { agentContext, connection, recipientKey, senderKey, message, sessionId } = messageContext

    if (!recipientKey || !senderKey) {
      throw new CredoError('Unable to process connection request without senderVerkey or recipientKey')
    }

    const parentThreadId = message.thread?.parentThreadId

    const outOfBandRecord =
      parentThreadId && tryParseDid(parentThreadId)
        ? await this.outOfBandService.createFromImplicitInvitation(agentContext, {
            did: parentThreadId,
            threadId: message.threadId,
            recipientKey,
            handshakeProtocols: [HandshakeProtocol.Connections],
          })
        : await this.outOfBandService.findCreatedByRecipientKey(agentContext, recipientKey)

    if (!outOfBandRecord) {
      throw new CredoError(`Out-of-band record for recipient key ${recipientKey.fingerprint} was not found.`)
    }

    if (connection && !outOfBandRecord.reusable) {
      throw new CredoError(`Connection record for non-reusable out-of-band ${outOfBandRecord.id} already exists.`)
    }

    const receivedDidRecord = await this.didRepository.findReceivedDidByRecipientKey(agentContext, senderKey)
    if (receivedDidRecord) {
      throw new CredoError(`A received did record for sender key ${senderKey.fingerprint} already exists.`)
    }

    const connectionRecord = await this.connectionService.processRequest(messageContext, outOfBandRecord)

    // Associate the new connection with the session created for the inbound message
    if (sessionId) {
      const transportService = agentContext.dependencyManager.resolve(TransportService)
      transportService.setConnectionIdForSession(sessionId, connectionRecord.id)
    }

    if (connectionRecord?.autoAcceptConnection ?? this.connectionsModuleConfig.autoAcceptConnections) {
      // TODO: Allow rotation of keys used in the invitation for new ones not only when out-of-band is reusable or
      // when there are no inline services in the invitation

      // We generate routing in two scenarios:
      // 1. When the out-of-band invitation is reusable, as otherwise all connections use the same keys
      // 2. When the out-of-band invitation has no inline services, as we don't want to generate a legacy did doc from a service did
      const routing =
        outOfBandRecord.reusable || outOfBandRecord.outOfBandInvitation.getInlineServices().length === 0
          ? await this.routingService.getRouting(agentContext)
          : undefined

      const { message } = await this.connectionService.createResponse(
        agentContext,
        connectionRecord,
        outOfBandRecord,
        routing
      )
      return new OutboundMessageContext(message, {
        agentContext,
        connection: connectionRecord,
        outOfBand: outOfBandRecord,
      })
    }
  }
}
