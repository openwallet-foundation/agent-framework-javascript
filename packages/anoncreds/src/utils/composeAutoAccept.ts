import { AutoAcceptCredential, AutoAcceptProof } from '@credo-ts/didcomm'

/**
 * Returns the credential auto accept config based on priority:
 *	- The record config takes first priority
 *	- Otherwise the agent config
 *	- Otherwise {@link AutoAcceptCredential.Never} is returned
 */
export function composeCredentialAutoAccept(recordConfig?: AutoAcceptCredential, agentConfig?: AutoAcceptCredential) {
  return recordConfig ?? agentConfig ?? AutoAcceptCredential.Never
}

/**
 * Returns the proof auto accept config based on priority:
 *	- The record config takes first priority
 *	- Otherwise the agent config
 *	- Otherwise {@link AutoAcceptProof.Never} is returned
 */
export function composeProofAutoAccept(recordConfig?: AutoAcceptProof, agentConfig?: AutoAcceptProof) {
  return recordConfig ?? agentConfig ?? AutoAcceptProof.Never
}
