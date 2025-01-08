import type { MessageHandler } from '../../../handlers'
import type { InboundMessageContext } from '../../../models'
import type { OutOfBandService } from '../OutOfBandService'

import { OutboundMessageContext } from '../../../models'
import { HandshakeReuseMessage } from '../messages/HandshakeReuseMessage'

export class HandshakeReuseHandler implements MessageHandler {
  public supportedMessages = [HandshakeReuseMessage]
  private outOfBandService: OutOfBandService

  public constructor(outOfBandService: OutOfBandService) {
    this.outOfBandService = outOfBandService
  }

  public async handle(messageContext: InboundMessageContext<HandshakeReuseMessage>) {
    const connectionRecord = messageContext.assertReadyConnection()
    const handshakeReuseAcceptedMessage = await this.outOfBandService.processHandshakeReuse(messageContext)

    return new OutboundMessageContext(handshakeReuseAcceptedMessage, {
      agentContext: messageContext.agentContext,
      connection: connectionRecord,
    })
  }
}
