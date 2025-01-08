import type { MessageHandler } from '../../../handlers'
import type { InboundMessageContext } from '../../../models'
import type { OutOfBandService } from '../OutOfBandService'

import { HandshakeReuseAcceptedMessage } from '../messages/HandshakeReuseAcceptedMessage'

export class HandshakeReuseAcceptedHandler implements MessageHandler {
  public supportedMessages = [HandshakeReuseAcceptedMessage]
  private outOfBandService: OutOfBandService

  public constructor(outOfBandService: OutOfBandService) {
    this.outOfBandService = outOfBandService
  }

  public async handle(messageContext: InboundMessageContext<HandshakeReuseAcceptedMessage>) {
    messageContext.assertReadyConnection()

    await this.outOfBandService.processHandshakeReuseAccepted(messageContext)
  }
}
