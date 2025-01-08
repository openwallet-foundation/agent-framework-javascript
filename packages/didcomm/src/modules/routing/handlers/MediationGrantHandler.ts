import type { MessageHandler, MessageHandlerInboundMessage } from '../../../handlers'
import type { MediationRecipientService } from '../services/MediationRecipientService'

import { MediationGrantMessage } from '../messages'

export class MediationGrantHandler implements MessageHandler {
  private mediationRecipientService: MediationRecipientService
  public supportedMessages = [MediationGrantMessage]

  public constructor(mediationRecipientService: MediationRecipientService) {
    this.mediationRecipientService = mediationRecipientService
  }

  public async handle(messageContext: MessageHandlerInboundMessage<MediationGrantHandler>) {
    messageContext.assertReadyConnection()

    await this.mediationRecipientService.processMediationGrant(messageContext)
  }
}
