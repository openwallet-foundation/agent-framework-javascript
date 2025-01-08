import type { MessageHandler, MessageHandlerInboundMessage } from '../../../handlers'
import type { MediationRecipientService } from '../services'

import { KeylistUpdateResponseMessage } from '../messages'

export class KeylistUpdateResponseHandler implements MessageHandler {
  public mediationRecipientService: MediationRecipientService
  public supportedMessages = [KeylistUpdateResponseMessage]

  public constructor(mediationRecipientService: MediationRecipientService) {
    this.mediationRecipientService = mediationRecipientService
  }

  public async handle(messageContext: MessageHandlerInboundMessage<KeylistUpdateResponseHandler>) {
    messageContext.assertReadyConnection()

    return await this.mediationRecipientService.processKeylistUpdateResults(messageContext)
  }
}
