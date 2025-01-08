import type { MessageHandler } from '../../../../../handlers'
import type { InboundMessageContext } from '../../../../../models'
import type { V2MessagePickupProtocol } from '../V2MessagePickupProtocol'

import { V2DeliveryRequestMessage } from '../messages'

export class V2DeliveryRequestHandler implements MessageHandler {
  public supportedMessages = [V2DeliveryRequestMessage]
  private messagePickupService: V2MessagePickupProtocol

  public constructor(messagePickupService: V2MessagePickupProtocol) {
    this.messagePickupService = messagePickupService
  }

  public async handle(messageContext: InboundMessageContext<V2DeliveryRequestMessage>) {
    messageContext.assertReadyConnection()
    return this.messagePickupService.processDeliveryRequest(messageContext)
  }
}
