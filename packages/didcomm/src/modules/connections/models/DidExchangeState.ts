/**
 * Connection states as defined in RFC 0023.
 *
 * @see https://github.com/hyperledger/aries-rfcs/blob/main/features/0023-did-exchange/README.md#state-machine-tables
 */
export enum DidExchangeState {
  Start = 'start',
  InvitationSent = 'invitation-sent',
  InvitationReceived = 'invitation-received',
  RequestSent = 'request-sent',
  RequestReceived = 'request-received',
  ResponseSent = 'response-sent',
  ResponseReceived = 'response-received',
  Abandoned = 'abandoned',
  Completed = 'completed',
}
