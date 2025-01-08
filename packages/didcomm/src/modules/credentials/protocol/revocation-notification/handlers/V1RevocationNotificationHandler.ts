import type { MessageHandler, MessageHandlerInboundMessage } from '../../../../../handlers'
import type { RevocationNotificationService } from '../services'

import { V1RevocationNotificationMessage } from '../messages/V1RevocationNotificationMessage'

export class V1RevocationNotificationHandler implements MessageHandler {
  private revocationService: RevocationNotificationService
  public supportedMessages = [V1RevocationNotificationMessage]

  public constructor(revocationService: RevocationNotificationService) {
    this.revocationService = revocationService
  }

  public async handle(messageContext: MessageHandlerInboundMessage<V1RevocationNotificationHandler>) {
    await this.revocationService.v1ProcessRevocationNotification(messageContext)
  }
}
