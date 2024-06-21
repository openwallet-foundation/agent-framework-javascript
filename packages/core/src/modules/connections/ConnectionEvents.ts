import type { DidExchangeState } from './models'
import type { ConnectionRecord } from './repository/ConnectionRecord'
import type { BaseEvent } from '../../agent/Events'

export enum ConnectionEventTypes {
  ConnectionStateChanged = 'ConnectionStateChanged',
  ConnectionDidRotated = 'ConnectionDidRotated',
}

export interface ConnectionStateChangedEvent extends BaseEvent {
  type: typeof ConnectionEventTypes.ConnectionStateChanged
  payload: {
    connectionRecord: ConnectionRecord
    previousState: DidExchangeState | null
  }
}

export interface ConnectionDidRotatedEvent extends BaseEvent {
  type: typeof ConnectionEventTypes.ConnectionDidRotated
  payload: {
    connectionRecord: ConnectionRecord

    ourDid?: {
      from: string
      to: string
    }
    theirDid?: {
      from: string
      to: string
    }
  }
}
