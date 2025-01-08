import type { MessageHandler, MessageHandlerInboundMessage } from '../../../../../handlers'
import type { V2DiscoverFeaturesService } from '../V2DiscoverFeaturesService'

import { OutboundMessageContext } from '../../../../../models'
import { V2QueriesMessage } from '../messages'

export class V2QueriesMessageHandler implements MessageHandler {
  private discoverFeaturesService: V2DiscoverFeaturesService
  public supportedMessages = [V2QueriesMessage]

  public constructor(discoverFeaturesService: V2DiscoverFeaturesService) {
    this.discoverFeaturesService = discoverFeaturesService
  }

  public async handle(inboundMessage: MessageHandlerInboundMessage<V2QueriesMessageHandler>) {
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
