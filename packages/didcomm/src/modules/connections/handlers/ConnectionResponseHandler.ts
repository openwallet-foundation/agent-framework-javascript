import type { DidResolverService } from '@credo-ts/core'
import type { MessageHandler, MessageHandlerInboundMessage } from '../../../handlers'
import type { OutOfBandService } from '../../oob/OutOfBandService'
import type { ConnectionsModuleConfig } from '../ConnectionsModuleConfig'
import type { ConnectionService } from '../services'

import { CredoError } from '@credo-ts/core'
import { ReturnRouteTypes } from '../../../decorators/transport/TransportDecorator'
import { OutboundMessageContext } from '../../../models'
import { ConnectionResponseMessage } from '../messages'
import { DidExchangeRole } from '../models'

export class ConnectionResponseHandler implements MessageHandler {
  private connectionService: ConnectionService
  private outOfBandService: OutOfBandService
  private didResolverService: DidResolverService
  private connectionsModuleConfig: ConnectionsModuleConfig

  public supportedMessages = [ConnectionResponseMessage]

  public constructor(
    connectionService: ConnectionService,
    outOfBandService: OutOfBandService,
    didResolverService: DidResolverService,
    connectionsModuleConfig: ConnectionsModuleConfig
  ) {
    this.connectionService = connectionService
    this.outOfBandService = outOfBandService
    this.didResolverService = didResolverService
    this.connectionsModuleConfig = connectionsModuleConfig
  }

  public async handle(messageContext: MessageHandlerInboundMessage<ConnectionResponseHandler>) {
    const { recipientKey, senderKey, message } = messageContext

    if (!recipientKey || !senderKey) {
      throw new CredoError('Unable to process connection response without senderKey or recipientKey')
    }

    // Query by both role and thread id to allow connecting to self
    const connectionRecord = await this.connectionService.getByRoleAndThreadId(
      messageContext.agentContext,
      DidExchangeRole.Requester,
      message.threadId
    )
    if (!connectionRecord) {
      throw new CredoError(`Connection for thread ID ${message.threadId} not found!`)
    }

    if (!connectionRecord.did) {
      throw new CredoError(`Connection record ${connectionRecord.id} has no 'did'`)
    }

    const ourDidDocument = await this.didResolverService.resolveDidDocument(
      messageContext.agentContext,
      connectionRecord.did
    )
    if (!ourDidDocument) {
      throw new CredoError(`Did document for did ${connectionRecord.did} was not resolved!`)
    }

    // Validate if recipient key is included in recipient keys of the did document resolved by
    // connection record did
    if (!ourDidDocument.recipientKeys.find((key) => key.fingerprint === recipientKey.fingerprint)) {
      throw new CredoError(`Recipient key ${recipientKey.fingerprint} not found in did document recipient keys.`)
    }

    const outOfBandRecord =
      connectionRecord.outOfBandId &&
      (await this.outOfBandService.findById(messageContext.agentContext, connectionRecord.outOfBandId))

    if (!outOfBandRecord) {
      throw new CredoError(`Out-of-band record ${connectionRecord.outOfBandId} was not found.`)
    }

    messageContext.connection = connectionRecord
    const connection = await this.connectionService.processResponse(messageContext, outOfBandRecord)

    // TODO: should we only send ping message in case of autoAcceptConnection or always?
    // In AATH we have a separate step to send the ping. So for now we'll only do it
    // if auto accept is enable
    if (connection.autoAcceptConnection ?? this.connectionsModuleConfig.autoAcceptConnections) {
      const { message } = await this.connectionService.createTrustPing(messageContext.agentContext, connection, {
        responseRequested: false,
      })

      // Disable return routing as we don't want to receive a response for this message over the same channel
      // This has led to long timeouts as not all clients actually close an http socket if there is no response message
      message.setReturnRouting(ReturnRouteTypes.none)
      return new OutboundMessageContext(message, { agentContext: messageContext.agentContext, connection })
    }
  }
}
