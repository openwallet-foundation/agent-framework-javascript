import type { TrustPingMessage, TrustPingResponseMessage } from './messages'
import type { ConnectionRecord } from './repository'
import type { BaseEvent } from '@credo-ts/core'

export enum TrustPingEventTypes {
  TrustPingReceivedEvent = 'TrustPingReceivedEvent',
  TrustPingResponseReceivedEvent = 'TrustPingResponseReceivedEvent',
}

export interface TrustPingReceivedEvent extends BaseEvent {
  type: typeof TrustPingEventTypes.TrustPingReceivedEvent
  payload: {
    connectionRecord: ConnectionRecord
    message: TrustPingMessage
  }
}

export interface TrustPingResponseReceivedEvent extends BaseEvent {
  type: typeof TrustPingEventTypes.TrustPingResponseReceivedEvent
  payload: {
    connectionRecord: ConnectionRecord
    message: TrustPingResponseMessage
  }
}
