import type { MessageHandler, MessageHandlerInboundMessage } from '../../../handlers'
import type { BasicMessageService } from '../services/BasicMessageService'

import { BasicMessage } from '../messages'

export class BasicMessageHandler implements MessageHandler {
  private basicMessageService: BasicMessageService
  public supportedMessages = [BasicMessage]

  public constructor(basicMessageService: BasicMessageService) {
    this.basicMessageService = basicMessageService
  }

  public async handle(messageContext: MessageHandlerInboundMessage<BasicMessageHandler>) {
    const connection = messageContext.assertReadyConnection()
    await this.basicMessageService.save(messageContext, connection)
  }
}
