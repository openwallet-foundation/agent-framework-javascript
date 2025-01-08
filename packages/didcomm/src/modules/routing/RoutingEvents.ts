import type { KeylistUpdate } from './messages/KeylistUpdateMessage'
import type { MediationState } from './models/MediationState'
import type { MediationRecord } from './repository/MediationRecord'
import type { BaseEvent } from '@credo-ts/core'
import type { Routing } from '../../models'

export enum RoutingEventTypes {
  MediationStateChanged = 'MediationStateChanged',
  RecipientKeylistUpdated = 'RecipientKeylistUpdated',
  RoutingCreatedEvent = 'RoutingCreatedEvent',
}

export interface RoutingCreatedEvent extends BaseEvent {
  type: typeof RoutingEventTypes.RoutingCreatedEvent
  payload: {
    routing: Routing
  }
}

export interface MediationStateChangedEvent extends BaseEvent {
  type: typeof RoutingEventTypes.MediationStateChanged
  payload: {
    mediationRecord: MediationRecord
    previousState: MediationState | null
  }
}

export interface KeylistUpdatedEvent extends BaseEvent {
  type: typeof RoutingEventTypes.RecipientKeylistUpdated
  payload: {
    mediationRecord: MediationRecord
    keylist: KeylistUpdate[]
  }
}
