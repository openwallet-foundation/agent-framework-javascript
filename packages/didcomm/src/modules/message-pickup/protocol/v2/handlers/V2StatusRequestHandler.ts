import type { MessageHandler } from '../../../../../handlers'
import type { InboundMessageContext } from '../../../../../models'
import type { V2MessagePickupProtocol } from '../V2MessagePickupProtocol'

import { V2StatusRequestMessage } from '../messages'

export class V2StatusRequestHandler implements MessageHandler {
  public supportedMessages = [V2StatusRequestMessage]
  private messagePickupService: V2MessagePickupProtocol

  public constructor(messagePickupService: V2MessagePickupProtocol) {
    this.messagePickupService = messagePickupService
  }

  public async handle(messageContext: InboundMessageContext<V2StatusRequestMessage>) {
    messageContext.assertReadyConnection()
    return this.messagePickupService.processStatusRequest(messageContext)
  }
}
