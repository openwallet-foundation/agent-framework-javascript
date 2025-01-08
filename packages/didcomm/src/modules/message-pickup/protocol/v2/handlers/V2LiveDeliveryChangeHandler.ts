import type { MessageHandler } from '../../../../../handlers'
import type { InboundMessageContext } from '../../../../../models'
import type { V2MessagePickupProtocol } from '../V2MessagePickupProtocol'

import { V2LiveDeliveryChangeMessage } from '../messages'

export class V2LiveDeliveryChangeHandler implements MessageHandler {
  public supportedMessages = [V2LiveDeliveryChangeMessage]
  private messagePickupService: V2MessagePickupProtocol

  public constructor(messagePickupService: V2MessagePickupProtocol) {
    this.messagePickupService = messagePickupService
  }

  public async handle(messageContext: InboundMessageContext<V2LiveDeliveryChangeMessage>) {
    messageContext.assertReadyConnection()
    return this.messagePickupService.processLiveDeliveryChange(messageContext)
  }
}
