import type { MessageHandler, MessageHandlerInboundMessage } from '../../../../../handlers'
import type { V1MessagePickupProtocol } from '../V1MessagePickupProtocol'

import { V1BatchPickupMessage } from '../messages'

export class V1BatchPickupHandler implements MessageHandler {
  private messagePickupService: V1MessagePickupProtocol
  public supportedMessages = [V1BatchPickupMessage]

  public constructor(messagePickupService: V1MessagePickupProtocol) {
    this.messagePickupService = messagePickupService
  }

  public async handle(messageContext: MessageHandlerInboundMessage<V1BatchPickupHandler>) {
    messageContext.assertReadyConnection()

    return this.messagePickupService.processBatchPickup(messageContext)
  }
}
