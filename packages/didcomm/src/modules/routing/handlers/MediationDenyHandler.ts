import type { MessageHandler, MessageHandlerInboundMessage } from '../../../handlers'
import type { MediationRecipientService } from '../services'

import { MediationDenyMessage } from '../messages'

export class MediationDenyHandler implements MessageHandler {
  private mediationRecipientService: MediationRecipientService
  public supportedMessages = [MediationDenyMessage]

  public constructor(mediationRecipientService: MediationRecipientService) {
    this.mediationRecipientService = mediationRecipientService
  }

  public async handle(messageContext: MessageHandlerInboundMessage<MediationDenyHandler>) {
    messageContext.assertReadyConnection()

    await this.mediationRecipientService.processMediationDeny(messageContext)
  }
}
