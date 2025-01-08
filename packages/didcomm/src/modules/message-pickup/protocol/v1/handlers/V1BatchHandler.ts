import type { MessageHandler, MessageHandlerInboundMessage } from '../../../../../handlers'
import type { V1MessagePickupProtocol } from '../V1MessagePickupProtocol'

import { OutboundMessageContext } from '../../../../../models'
import { V1BatchMessage } from '../messages'

export class V1BatchHandler implements MessageHandler {
  public supportedMessages = [V1BatchMessage]
  private messagePickupProtocol: V1MessagePickupProtocol

  public constructor(messagePickupProtocol: V1MessagePickupProtocol) {
    this.messagePickupProtocol = messagePickupProtocol
  }

  public async handle(messageContext: MessageHandlerInboundMessage<V1BatchHandler>) {
    const connection = messageContext.assertReadyConnection()
    const batchRequestMessage = await this.messagePickupProtocol.processBatch(messageContext)

    if (batchRequestMessage) {
      return new OutboundMessageContext(batchRequestMessage, {
        agentContext: messageContext.agentContext,
        connection,
      })
    }
  }
}
