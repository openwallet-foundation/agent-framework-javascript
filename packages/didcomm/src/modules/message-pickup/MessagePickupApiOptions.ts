import type { MessagePickupProtocol } from './protocol/MessagePickupProtocol'
import type { QueuedMessage } from './storage'
import type { EncryptedMessage } from '../../types'

/**
 * Get the supported protocol versions based on the provided message pickup protocols
 */
export type MessagePickupProtocolVersionType<MPPs extends MessagePickupProtocol[]> = MPPs[number]['version']

export interface QueueMessageOptions {
  connectionId: string
  recipientDids: string[]
  message: EncryptedMessage
}

export interface DeliverMessagesFromQueueOptions {
  pickupSessionId: string
  recipientDid?: string
  batchSize?: number
}

export interface DeliverMessagesOptions {
  pickupSessionId: string
  messages: QueuedMessage[]
}

export interface PickupMessagesOptions<MPPs extends MessagePickupProtocol[] = MessagePickupProtocol[]> {
  connectionId: string
  protocolVersion: MessagePickupProtocolVersionType<MPPs>
  recipientDid?: string
  batchSize?: number
  awaitCompletion?: boolean
  awaitCompletionTimeoutMs?: number
}

export interface SetLiveDeliveryModeOptions<MPPs extends MessagePickupProtocol[] = MessagePickupProtocol[]> {
  connectionId: string
  protocolVersion: MessagePickupProtocolVersionType<MPPs>
  liveDelivery: boolean
}

export type QueueMessageReturnType = void

export type PickupMessagesReturnType = void

export type DeliverMessagesReturnType = void

export type DeliverMessagesFromQueueReturnType = void

export type SetLiveDeliveryModeReturnType = void
