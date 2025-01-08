import type { AgentContext } from '@credo-ts/core'
import type { AgentMessage } from '../../../../AgentMessage'
import type { AgentMessageReceivedEvent } from '../../../../Events'
import type { FeatureRegistry } from '../../../../FeatureRegistry'
import type { MessageHandlerRegistry } from '../../../../MessageHandlerRegistry'
import type { InboundMessageContext } from '../../../../models'
import type { MessagePickupCompletedEvent } from '../../MessagePickupEvents'
import type { MessagePickupRepository } from '../../storage/MessagePickupRepository'
import type {
  DeliverMessagesProtocolOptions,
  DeliverMessagesProtocolReturnType,
  PickupMessagesProtocolOptions,
  PickupMessagesProtocolReturnType,
  SetLiveDeliveryModeProtocolReturnType,
} from '../MessagePickupProtocolOptions'

import { EventEmitter, InjectionSymbols, CredoError, injectable } from '@credo-ts/core'

import { AgentEventTypes } from '../../../../Events'
import { Protocol, OutboundMessageContext } from '../../../../models'
import { MessagePickupEventTypes } from '../../MessagePickupEvents'
import { MessagePickupModuleConfig } from '../../MessagePickupModuleConfig'
import { BaseMessagePickupProtocol } from '../BaseMessagePickupProtocol'

import { V1BatchHandler, V1BatchPickupHandler } from './handlers'
import { V1BatchMessage, BatchMessageMessage, V1BatchPickupMessage } from './messages'

@injectable()
export class V1MessagePickupProtocol extends BaseMessagePickupProtocol {
  /**
   * The version of the message pickup protocol this class supports
   */
  public readonly version = 'v1' as const

  /**
   * Registers the protocol implementation (handlers, feature registry) on the agent.
   */
  public register(messageHandlerRegistry: MessageHandlerRegistry, featureRegistry: FeatureRegistry): void {
    messageHandlerRegistry.registerMessageHandlers([new V1BatchPickupHandler(this), new V1BatchHandler(this)])

    featureRegistry.register(
      new Protocol({
        id: 'https://didcomm.org/messagepickup/1.0',
        roles: ['message_holder', 'recipient', 'batch_sender', 'batch_recipient'],
      })
    )
  }

  public async createPickupMessage(
    agentContext: AgentContext,
    options: PickupMessagesProtocolOptions
  ): Promise<PickupMessagesProtocolReturnType<AgentMessage>> {
    const { connectionRecord, batchSize } = options
    connectionRecord.assertReady()

    const config = agentContext.dependencyManager.resolve(MessagePickupModuleConfig)
    const message = new V1BatchPickupMessage({
      batchSize: batchSize ?? config.maximumBatchSize,
    })

    return { message }
  }

  public async createDeliveryMessage(
    agentContext: AgentContext,
    options: DeliverMessagesProtocolOptions
  ): Promise<DeliverMessagesProtocolReturnType<AgentMessage> | void> {
    const { connectionRecord, batchSize, messages } = options
    connectionRecord.assertReady()

    const pickupMessageQueue = agentContext.dependencyManager.resolve<MessagePickupRepository>(
      InjectionSymbols.MessagePickupRepository
    )

    const messagesToDeliver =
      messages ??
      (await pickupMessageQueue.takeFromQueue({
        connectionId: connectionRecord.id,
        limit: batchSize, // TODO: Define as config parameter for message holder side
        deleteMessages: true,
      }))

    const batchMessages = messagesToDeliver.map(
      (msg) =>
        new BatchMessageMessage({
          id: msg.id,
          message: msg.encryptedMessage,
        })
    )

    if (messagesToDeliver.length > 0) {
      const message = new V1BatchMessage({
        messages: batchMessages,
      })

      return { message }
    }
  }

  public async setLiveDeliveryMode(): Promise<SetLiveDeliveryModeProtocolReturnType<AgentMessage>> {
    throw new CredoError('Live Delivery mode not supported in Message Pickup V1 protocol')
  }

  public async processBatchPickup(messageContext: InboundMessageContext<V1BatchPickupMessage>) {
    // Assert ready connection
    const connection = messageContext.assertReadyConnection()

    const { message } = messageContext

    const pickupMessageQueue = messageContext.agentContext.dependencyManager.resolve<MessagePickupRepository>(
      InjectionSymbols.MessagePickupRepository
    )

    const messages = await pickupMessageQueue.takeFromQueue({
      connectionId: connection.id,
      limit: message.batchSize,
      deleteMessages: true,
    })

    const batchMessages = messages.map(
      (msg) =>
        new BatchMessageMessage({
          id: msg.id,
          message: msg.encryptedMessage,
        })
    )

    const batchMessage = new V1BatchMessage({
      messages: batchMessages,
      threadId: message.threadId,
    })

    return new OutboundMessageContext(batchMessage, { agentContext: messageContext.agentContext, connection })
  }

  public async processBatch(messageContext: InboundMessageContext<V1BatchMessage>) {
    const { message: batchMessage, agentContext } = messageContext
    const { messages } = batchMessage

    const connection = messageContext.assertReadyConnection()

    const eventEmitter = messageContext.agentContext.dependencyManager.resolve(EventEmitter)

    messages.forEach((message) => {
      eventEmitter.emit<AgentMessageReceivedEvent>(messageContext.agentContext, {
        type: AgentEventTypes.AgentMessageReceived,
        payload: {
          message: message.message,
          contextCorrelationId: messageContext.agentContext.contextCorrelationId,
        },
      })
    })

    // A Batch message without messages at all means that we are done with the
    // message pickup process (Note: this is not optimal since we'll always doing an extra
    // Batch Pickup. However, it is safer and should be faster than waiting an entire loop
    // interval to retrieve more messages)
    if (messages.length === 0) {
      eventEmitter.emit<MessagePickupCompletedEvent>(messageContext.agentContext, {
        type: MessagePickupEventTypes.MessagePickupCompleted,
        payload: {
          connection,
          threadId: batchMessage.threadId,
        },
      })
      return null
    }

    return (await this.createPickupMessage(agentContext, { connectionRecord: connection })).message
  }
}
