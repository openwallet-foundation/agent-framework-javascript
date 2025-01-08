import type { ActionMenuService } from '../services'
import type { MessageHandler, MessageHandlerInboundMessage } from '@credo-ts/didcomm'

import { MenuMessage } from '../messages'

/**
 * @internal
 */
export class MenuMessageHandler implements MessageHandler {
  private actionMenuService: ActionMenuService
  public supportedMessages = [MenuMessage]

  public constructor(actionMenuService: ActionMenuService) {
    this.actionMenuService = actionMenuService
  }

  public async handle(inboundMessage: MessageHandlerInboundMessage<MenuMessageHandler>) {
    inboundMessage.assertReadyConnection()

    await this.actionMenuService.processMenu(inboundMessage)
  }
}
