import type { AgentMessage } from './AgentMessage'
import type { TransportSession } from './TransportService'
import type { OutboundMessageContext, OutboundMessageSendStatus } from './models'
import type { ConnectionRecord } from './modules/connections/repository'
import type { EncryptedMessage } from './types'
import type { BaseEvent } from '@credo-ts/core'

export enum AgentEventTypes {
  AgentMessageReceived = 'AgentMessageReceived',
  AgentMessageProcessed = 'AgentMessageProcessed',
  AgentMessageSent = 'AgentMessageSent',
}

export interface AgentMessageReceivedEvent extends BaseEvent {
  type: typeof AgentEventTypes.AgentMessageReceived
  payload: {
    message: unknown
    connection?: ConnectionRecord
    contextCorrelationId?: string
    receivedAt?: Date
    session?: TransportSession
  }
}

export interface AgentMessageProcessedEvent extends BaseEvent {
  type: typeof AgentEventTypes.AgentMessageProcessed
  payload: {
    message: AgentMessage
    connection?: ConnectionRecord
    receivedAt?: Date
    encryptedMessage?: EncryptedMessage
  }
}

export interface AgentMessageSentEvent extends BaseEvent {
  type: typeof AgentEventTypes.AgentMessageSent
  payload: {
    message: OutboundMessageContext
    status: OutboundMessageSendStatus
  }
}
