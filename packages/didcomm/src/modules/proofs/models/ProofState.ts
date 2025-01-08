/**
 * Present Proof protocol states as defined in RFC 0037
 *
 * @see https://github.com/hyperledger/aries-rfcs/tree/master/features/0037-present-proof#states
 */
export enum ProofState {
  ProposalSent = 'proposal-sent',
  ProposalReceived = 'proposal-received',
  RequestSent = 'request-sent',
  RequestReceived = 'request-received',
  PresentationSent = 'presentation-sent',
  PresentationReceived = 'presentation-received',
  Declined = 'declined',
  Abandoned = 'abandoned',
  Done = 'done',
}
