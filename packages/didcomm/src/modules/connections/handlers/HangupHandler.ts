import type { MessageHandler, MessageHandlerInboundMessage } from '../../../handlers'
import type { DidRotateService } from '../services'

import { HangupMessage } from '../messages'

export class HangupHandler implements MessageHandler {
  private didRotateService: DidRotateService
  public supportedMessages = [HangupMessage]

  public constructor(didRotateService: DidRotateService) {
    this.didRotateService = didRotateService
  }

  public async handle(inboundMessage: MessageHandlerInboundMessage<HangupHandler>) {
    await this.didRotateService.processHangup(inboundMessage)
  }
}
