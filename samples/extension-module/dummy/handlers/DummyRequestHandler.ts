import type { DummyService } from '../services'
import type { MessageHandler, MessageHandlerInboundMessage } from '@credo-ts/didcomm'

import { getOutboundMessageContext } from '@credo-ts/didcomm'

import { DummyRequestMessage } from '../messages'

export class DummyRequestHandler implements MessageHandler {
  public supportedMessages = [DummyRequestMessage]
  private dummyService: DummyService

  public constructor(dummyService: DummyService) {
    this.dummyService = dummyService
  }

  public async handle(inboundMessage: MessageHandlerInboundMessage<DummyRequestHandler>) {
    const connectionRecord = inboundMessage.assertReadyConnection()
    const responseMessage = await this.dummyService.processRequest(inboundMessage)

    if (responseMessage) {
      return getOutboundMessageContext(inboundMessage.agentContext, {
        connectionRecord,
        message: responseMessage,
      })
    }
  }
}
