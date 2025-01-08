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

export interface MessagePickupProtocol {
  readonly version: string

  createPickupMessage(
    agentContext: AgentContext,
    options: PickupMessagesProtocolOptions
  ): Promise<PickupMessagesProtocolReturnType<AgentMessage>>

  createDeliveryMessage(
    agentContext: AgentContext,
    options: DeliverMessagesProtocolOptions
  ): Promise<DeliverMessagesProtocolReturnType<AgentMessage> | void>

  setLiveDeliveryMode(
    agentContext: AgentContext,
    options: SetLiveDeliveryModeProtocolOptions
  ): Promise<SetLiveDeliveryModeProtocolReturnType<AgentMessage>>

  register(messageHandlerRegistry: MessageHandlerRegistry, featureRegistry: FeatureRegistry): void
}
