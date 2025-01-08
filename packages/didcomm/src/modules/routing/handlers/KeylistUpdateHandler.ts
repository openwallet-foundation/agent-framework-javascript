import type { MessageHandler, MessageHandlerInboundMessage } from '../../../handlers'
import type { MediatorService } from '../services/MediatorService'

import { OutboundMessageContext } from '../../../models'
import { KeylistUpdateMessage } from '../messages'

export class KeylistUpdateHandler implements MessageHandler {
  private mediatorService: MediatorService
  public supportedMessages = [KeylistUpdateMessage]

  public constructor(mediatorService: MediatorService) {
    this.mediatorService = mediatorService
  }

  public async handle(messageContext: MessageHandlerInboundMessage<KeylistUpdateHandler>) {
    const connection = messageContext.assertReadyConnection()

    const response = await this.mediatorService.processKeylistUpdateRequest(messageContext)
    return new OutboundMessageContext(response, {
      agentContext: messageContext.agentContext,
      connection,
    })
  }
}
