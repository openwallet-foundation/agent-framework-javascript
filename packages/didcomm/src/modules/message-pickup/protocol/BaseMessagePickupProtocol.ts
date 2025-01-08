import type { MessagePickupProtocol } from './MessagePickupProtocol'
import type {
  DeliverMessagesProtocolOptions,
  DeliverMessagesProtocolReturnType,
  PickupMessagesProtocolOptions,
  PickupMessagesProtocolReturnType,
  SetLiveDeliveryModeProtocolOptions,
  SetLiveDeliveryModeProtocolReturnType,
} from './MessagePickupProtocolOptions'
import type { AgentContext } from '@credo-ts/core'
import type { AgentMessage } from '../../../AgentMessage'
import type { FeatureRegistry } from '../../../FeatureRegistry'
import type { MessageHandlerRegistry } from '../../../MessageHandlerRegistry'

/**
 * Base implementation of the MessagePickupProtocol that can be used as a foundation for implementing
 * the MessagePickupProtocol interface.
 */
export abstract class BaseMessagePickupProtocol implements MessagePickupProtocol {
  public abstract readonly version: string

  public abstract createPickupMessage(
    agentContext: AgentContext,
    options: PickupMessagesProtocolOptions
  ): Promise<PickupMessagesProtocolReturnType<AgentMessage>>

  public abstract createDeliveryMessage(
    agentContext: AgentContext,
    options: DeliverMessagesProtocolOptions
  ): Promise<DeliverMessagesProtocolReturnType<AgentMessage> | void>

  public abstract setLiveDeliveryMode(
    agentContext: AgentContext,
    options: SetLiveDeliveryModeProtocolOptions
  ): Promise<SetLiveDeliveryModeProtocolReturnType<AgentMessage>>

  public abstract register(messageHandlerRegistry: MessageHandlerRegistry, featureRegistry: FeatureRegistry): void
}
