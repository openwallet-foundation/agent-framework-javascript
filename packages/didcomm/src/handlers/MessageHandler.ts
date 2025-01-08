import type { ConstructableAgentMessage } from '../AgentMessage'
import type { InboundMessageContext, OutboundMessageContext } from '../models'

export interface MessageHandler {
  readonly supportedMessages: readonly ConstructableAgentMessage[]

  handle(messageContext: InboundMessageContext): Promise<OutboundMessageContext | void>
}

/**
 * Provides exact typing for the AgentMessage in the message context in the `handle` function
 * of a handler. It takes all possible types from `supportedMessageTypes`
 *
 * @example
 * async handle(messageContext: MessageHandlerInboundMessage<BasicMessageHandler>) {}
 */
export type MessageHandlerInboundMessage<H extends MessageHandler> = InboundMessageContext<
  InstanceType<H['supportedMessages'][number]>
>
