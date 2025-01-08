import type { OutOfBandState } from './OutOfBandState'
import type { BaseEvent } from '@credo-ts/core'
import type { ConnectionRecord } from '../../connections'
import type { OutOfBandRecord } from '../repository'

export enum OutOfBandEventTypes {
  OutOfBandStateChanged = 'OutOfBandStateChanged',
  HandshakeReused = 'HandshakeReused',
}

export interface OutOfBandStateChangedEvent extends BaseEvent {
  type: typeof OutOfBandEventTypes.OutOfBandStateChanged
  payload: {
    outOfBandRecord: OutOfBandRecord
    previousState: OutOfBandState | null
  }
}

export interface HandshakeReusedEvent extends BaseEvent {
  type: typeof OutOfBandEventTypes.HandshakeReused
  payload: {
    // We need the thread id (can be multiple reuse happening at the same time)
    reuseThreadId: string
    outOfBandRecord: OutOfBandRecord
    connectionRecord: ConnectionRecord
  }
}
