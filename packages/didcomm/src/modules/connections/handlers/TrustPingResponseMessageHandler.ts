import type { MessageHandler, MessageHandlerInboundMessage } from '../../../handlers'
import type { TrustPingService } from '../services'

import { TrustPingResponseMessage } from '../messages'

export class TrustPingResponseMessageHandler implements MessageHandler {
  private trustPingService: TrustPingService
  public supportedMessages = [TrustPingResponseMessage]

  public constructor(trustPingService: TrustPingService) {
    this.trustPingService = trustPingService
  }

  public async handle(inboundMessage: MessageHandlerInboundMessage<TrustPingResponseMessageHandler>) {
    return this.trustPingService.processPingResponse(inboundMessage)
  }
}
