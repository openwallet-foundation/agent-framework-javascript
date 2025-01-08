import type { MessageHandler, MessageHandlerInboundMessage } from '../../../../../handlers'
import type { V1DiscoverFeaturesService } from '../V1DiscoverFeaturesService'

import { OutboundMessageContext } from '../../../../../models'
import { V1QueryMessage } from '../messages'

export class V1QueryMessageHandler implements MessageHandler {
  private discoverFeaturesService: V1DiscoverFeaturesService
  public supportedMessages = [V1QueryMessage]

  public constructor(discoverFeaturesService: V1DiscoverFeaturesService) {
    this.discoverFeaturesService = discoverFeaturesService
  }

  public async handle(inboundMessage: MessageHandlerInboundMessage<V1QueryMessageHandler>) {
    const connection = inboundMessage.assertReadyConnection()

    const discloseMessage = await this.discoverFeaturesService.processQuery(inboundMessage)

    if (discloseMessage) {
      return new OutboundMessageContext(discloseMessage.message, {
        agentContext: inboundMessage.agentContext,
        connection,
      })
    }
  }
}
