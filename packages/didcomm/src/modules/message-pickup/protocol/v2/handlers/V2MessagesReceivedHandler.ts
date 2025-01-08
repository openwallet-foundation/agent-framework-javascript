import type { MessageHandler } from '../../../../../handlers'
import type { InboundMessageContext } from '../../../../../models'
import type { V2MessagePickupProtocol } from '../V2MessagePickupProtocol'

import { V2MessagesReceivedMessage } from '../messages'

export class V2MessagesReceivedHandler implements MessageHandler {
  public supportedMessages = [V2MessagesReceivedMessage]
  private messagePickupService: V2MessagePickupProtocol

  public constructor(messagePickupService: V2MessagePickupProtocol) {
    this.messagePickupService = messagePickupService
  }

  public async handle(messageContext: InboundMessageContext<V2MessagesReceivedMessage>) {
    messageContext.assertReadyConnection()
    return this.messagePickupService.processMessagesReceived(messageContext)
  }
}
