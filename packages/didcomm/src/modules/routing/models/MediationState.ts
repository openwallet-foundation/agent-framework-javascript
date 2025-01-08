/**
 * Mediation states based on the flow defined in RFC 0211.
 *
 * @see https://github.com/hyperledger/aries-rfcs/tree/master/features/0211-route-coordination/README.md
 */
export enum MediationState {
  Requested = 'requested',
  Granted = 'granted',
  Denied = 'denied',
}
