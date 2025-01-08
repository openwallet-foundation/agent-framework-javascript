import type { AgentMessage } from '../../../AgentMessage'
import type { ConnectionRecord } from '../../connections/repository'
import type { QueuedMessage } from '../storage'

export interface PickupMessagesProtocolOptions {
  connectionRecord: ConnectionRecord
  recipientDid?: string
  batchSize?: number
}

export interface DeliverMessagesProtocolOptions {
  connectionRecord: ConnectionRecord
  messages?: QueuedMessage[]
  recipientKey?: string
  batchSize?: number
}

export interface SetLiveDeliveryModeProtocolOptions {
  connectionRecord: ConnectionRecord
  liveDelivery: boolean
}

export type PickupMessagesProtocolReturnType<MessageType extends AgentMessage> = {
  message: MessageType
}

export type DeliverMessagesProtocolReturnType<MessageType extends AgentMessage> = {
  message: MessageType
}

export type SetLiveDeliveryModeProtocolReturnType<MessageType extends AgentMessage> = {
  message: MessageType
}
