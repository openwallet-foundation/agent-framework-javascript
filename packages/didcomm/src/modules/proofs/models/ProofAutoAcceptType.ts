/**
 * Typing of the state for auto acceptance
 */
export enum AutoAcceptProof {
  // Always auto accepts the proof no matter if it changed in subsequent steps
  Always = 'always',

  // Needs one acceptation and the rest will be automated if nothing changes
  ContentApproved = 'contentApproved',

  // DEFAULT: Never auto accept a proof
  Never = 'never',
}
