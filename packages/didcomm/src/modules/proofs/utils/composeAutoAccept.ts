import { AutoAcceptProof } from '../models'

/**
 * Returns the proof auto accept config based on priority:
 *	- The record config takes first priority
 *	- Otherwise the agent config
 *	- Otherwise {@link AutoAcceptProof.Never} is returned
 */
export function composeAutoAccept(recordConfig?: AutoAcceptProof, agentConfig?: AutoAcceptProof) {
  return recordConfig ?? agentConfig ?? AutoAcceptProof.Never
}
