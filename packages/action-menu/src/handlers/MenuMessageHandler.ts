import type { ActionMenuService } from '../services'
import type { Handler, HandlerInboundMessage } from '@aries-framework/core'

import { MenuMessage } from '../messages'

/**
 * @internal
 */
export class MenuMessageHandler implements Handler {
  private actionMenuService: ActionMenuService
  public supportedMessages = [MenuMessage]

  public constructor(actionMenuService: ActionMenuService) {
    this.actionMenuService = actionMenuService
  }

  public async handle(inboundMessage: HandlerInboundMessage<MenuMessageHandler>) {
    inboundMessage.assertReadyConnection()

    await this.actionMenuService.processMenu(inboundMessage)
  }
}
