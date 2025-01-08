import type { ActionMenuService } from '../services'
import type { MessageHandler, MessageHandlerInboundMessage } from '@credo-ts/didcomm'

import { ActionMenuProblemReportMessage } from '../messages'

/**
 * @internal
 */
export class ActionMenuProblemReportHandler implements MessageHandler {
  private actionMenuService: ActionMenuService
  public supportedMessages = [ActionMenuProblemReportMessage]

  public constructor(actionMenuService: ActionMenuService) {
    this.actionMenuService = actionMenuService
  }

  public async handle(messageContext: MessageHandlerInboundMessage<ActionMenuProblemReportHandler>) {
    await this.actionMenuService.processProblemReport(messageContext)
  }
}
