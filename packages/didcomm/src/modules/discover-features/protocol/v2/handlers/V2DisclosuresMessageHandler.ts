import type { MessageHandler, MessageHandlerInboundMessage } from '../../../../../handlers'
import type { V2DiscoverFeaturesService } from '../V2DiscoverFeaturesService'

import { V2DisclosuresMessage } from '../messages'

export class V2DisclosuresMessageHandler implements MessageHandler {
  private discoverFeaturesService: V2DiscoverFeaturesService
  public supportedMessages = [V2DisclosuresMessage]

  public constructor(discoverFeaturesService: V2DiscoverFeaturesService) {
    this.discoverFeaturesService = discoverFeaturesService
  }

  public async handle(inboundMessage: MessageHandlerInboundMessage<V2DisclosuresMessageHandler>) {
    await this.discoverFeaturesService.processDisclosure(inboundMessage)
  }
}
