import { DidExchangeState } from './DidExchangeState'

/**
 * Connection states as defined in RFC 0160.
 *
 * @see https://github.com/hyperledger/aries-rfcs/blob/master/features/0160-connection-protocol/README.md#states
 */
export enum ConnectionState {
  Null = 'null',
  Invited = 'invited',
  Requested = 'requested',
  Responded = 'responded',
  Complete = 'complete',
}

export function rfc0160StateFromDidExchangeState(didExchangeState: DidExchangeState) {
  const stateMapping = {
    [DidExchangeState.Start]: ConnectionState.Null,
    [DidExchangeState.Abandoned]: ConnectionState.Null,
    [DidExchangeState.InvitationReceived]: ConnectionState.Invited,
    [DidExchangeState.InvitationSent]: ConnectionState.Invited,
    [DidExchangeState.RequestReceived]: ConnectionState.Requested,
    [DidExchangeState.RequestSent]: ConnectionState.Requested,
    [DidExchangeState.ResponseReceived]: ConnectionState.Responded,
    [DidExchangeState.ResponseSent]: ConnectionState.Responded,
    [DidExchangeState.Completed]: ConnectionState.Complete,
  }

  return stateMapping[didExchangeState]
}
