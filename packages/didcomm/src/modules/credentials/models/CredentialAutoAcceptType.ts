/**
 * Typing of the state for auto acceptance
 */
export enum AutoAcceptCredential {
  /** Always auto accepts the credential no matter if it changed in subsequent steps */
  Always = 'always',

  /** Needs one acceptation and the rest will be automated if nothing changes */
  ContentApproved = 'contentApproved',

  /** Never auto accept a credential */
  Never = 'never',
}
