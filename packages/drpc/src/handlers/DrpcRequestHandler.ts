import type { DrpcService } from '../services/DrpcService'
import type { MessageHandler, MessageHandlerInboundMessage } from '@credo-ts/didcomm'

import { DrpcRequestMessage } from '../messages'

export class DrpcRequestHandler implements MessageHandler {
  private drpcMessageService: DrpcService
  public supportedMessages = [DrpcRequestMessage]

  public constructor(drpcMessageService: DrpcService) {
    this.drpcMessageService = drpcMessageService
  }

  public async handle(messageContext: MessageHandlerInboundMessage<DrpcRequestHandler>) {
    await this.drpcMessageService.receiveRequest(messageContext)
  }
}
