import type { DummyService } from '../services'
import type { MessageHandler, MessageHandlerInboundMessage } from '@credo-ts/didcomm'

import { DummyResponseMessage } from '../messages'

export class DummyResponseHandler implements MessageHandler {
  public supportedMessages = [DummyResponseMessage]
  private dummyService: DummyService

  public constructor(dummyService: DummyService) {
    this.dummyService = dummyService
  }

  public async handle(inboundMessage: MessageHandlerInboundMessage<DummyResponseHandler>) {
    inboundMessage.assertReadyConnection()

    await this.dummyService.processResponse(inboundMessage)
  }
}
