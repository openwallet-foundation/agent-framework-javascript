import type { ProofState } from './models/ProofState'
import type { ProofExchangeRecord } from './repository'
import type { BaseEvent } from '@credo-ts/core'

export enum ProofEventTypes {
  ProofStateChanged = 'ProofStateChanged',
}

export interface ProofStateChangedEvent extends BaseEvent {
  type: typeof ProofEventTypes.ProofStateChanged
  payload: {
    proofRecord: ProofExchangeRecord
    previousState: ProofState | null
  }
}
