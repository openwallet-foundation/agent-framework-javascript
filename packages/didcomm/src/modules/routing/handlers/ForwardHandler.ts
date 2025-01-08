import type { MessageHandler, MessageHandlerInboundMessage } from '../../../handlers'
import type { MediatorService } from '../services'

import { ForwardMessage } from '../messages'

export class ForwardHandler implements MessageHandler {
  private mediatorService: MediatorService
  public supportedMessages = [ForwardMessage]

  public constructor(mediatorService: MediatorService) {
    this.mediatorService = mediatorService
  }

  public async handle(messageContext: MessageHandlerInboundMessage<ForwardHandler>) {
    await this.mediatorService.processForwardMessage(messageContext)
  }
}
