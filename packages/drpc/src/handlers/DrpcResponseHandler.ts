import type { DrpcService } from '../services/DrpcService'
import type { MessageHandler, MessageHandlerInboundMessage } from '@credo-ts/didcomm'

import { DrpcResponseMessage } from '../messages'

export class DrpcResponseHandler implements MessageHandler {
  private drpcMessageService: DrpcService
  public supportedMessages = [DrpcResponseMessage]

  public constructor(drpcMessageService: DrpcService) {
    this.drpcMessageService = drpcMessageService
  }

  public async handle(messageContext: MessageHandlerInboundMessage<DrpcResponseHandler>) {
    await this.drpcMessageService.receiveResponse(messageContext)
  }
}
