import type { Handler, HandlerInboundMessage } from '../../../../../agent/Handler'
import type { V1DiscoverFeaturesService } from '../V1DiscoverFeaturesService'

import { OutboundMessageContext } from '../../../../../agent/models'
import { V1QueryMessage } from '../messages'

export class V1QueryMessageHandler implements Handler {
  private discoverFeaturesService: V1DiscoverFeaturesService
  public supportedMessages = [V1QueryMessage]

  public constructor(discoverFeaturesService: V1DiscoverFeaturesService) {
    this.discoverFeaturesService = discoverFeaturesService
  }

  public async handle(inboundMessage: HandlerInboundMessage<V1QueryMessageHandler>) {
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
