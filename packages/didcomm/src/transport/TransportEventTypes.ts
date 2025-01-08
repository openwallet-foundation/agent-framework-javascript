import type { BaseEvent } from '@credo-ts/core'
import type { TransportSession } from '../TransportService'

export enum TransportEventTypes {
  OutboundWebSocketClosedEvent = 'OutboundWebSocketClosedEvent',
  OutboundWebSocketOpenedEvent = 'OutboundWebSocketOpenedEvent',
  TransportSessionSaved = 'TransportSessionSaved',
  TransportSessionRemoved = 'TransportSessionRemoved',
}

export interface OutboundWebSocketClosedEvent extends BaseEvent {
  type: TransportEventTypes.OutboundWebSocketClosedEvent
  payload: {
    socketId: string
    connectionId?: string
  }
}

export interface OutboundWebSocketOpenedEvent extends BaseEvent {
  type: TransportEventTypes.OutboundWebSocketOpenedEvent
  payload: {
    socketId: string
    connectionId?: string
  }
}

export interface TransportSessionSavedEvent extends BaseEvent {
  type: typeof TransportEventTypes.TransportSessionSaved
  payload: {
    session: TransportSession
  }
}

export interface TransportSessionRemovedEvent extends BaseEvent {
  type: typeof TransportEventTypes.TransportSessionRemoved
  payload: {
    session: TransportSession
  }
}
