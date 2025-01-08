/**
 * Enum values should be sorted based on order of preference. Values will be
 * included in this order when creating out of band invitations.
 */
export enum HandshakeProtocol {
  DidExchange = 'https://didcomm.org/didexchange/1.x',
  Connections = 'https://didcomm.org/connections/1.x',
}
