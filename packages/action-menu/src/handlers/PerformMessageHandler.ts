import type { ActionMenuService } from '../services'
import type { MessageHandler, MessageHandlerInboundMessage } from '@credo-ts/didcomm'

import { PerformMessage } from '../messages'

/**
 * @internal
 */
export class PerformMessageHandler implements MessageHandler {
  private actionMenuService: ActionMenuService
  public supportedMessages = [PerformMessage]

  public constructor(actionMenuService: ActionMenuService) {
    this.actionMenuService = actionMenuService
  }

  public async handle(inboundMessage: MessageHandlerInboundMessage<PerformMessageHandler>) {
    inboundMessage.assertReadyConnection()

    await this.actionMenuService.processPerform(inboundMessage)
  }
}
