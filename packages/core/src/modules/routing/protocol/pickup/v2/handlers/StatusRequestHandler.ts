import type { Handler } from '../../../../../../agent/Handler'
import type { InboundMessageContext } from '../../../../../../agent/models/InboundMessageContext'
import type { V2MessagePickupService } from '../V2MessagePickupService'

import { StatusRequestMessage } from '../messages'

export class StatusRequestHandler implements Handler {
  public supportedMessages = [StatusRequestMessage]
  private messagePickupService: V2MessagePickupService

  public constructor(messagePickupService: V2MessagePickupService) {
    this.messagePickupService = messagePickupService
  }

  public async handle(messageContext: InboundMessageContext<StatusRequestMessage>) {
    messageContext.assertReadyConnection()
    return this.messagePickupService.processStatusRequest(messageContext)
  }
}
