import type { ProofExchangeRecord } from './repository'
import type { AgentContext } from '../../agent/context/AgentContext'

import { injectable } from '../../plugins'

import { ProofService } from './ProofService'
import { AutoAcceptProof } from './models/ProofAutoAcceptType'

/**
 * This class handles all the automation with all the messages in the present proof protocol
 * Every function returns `true` if it should automate the flow and `false` if not
 */
@injectable()
export class ProofResponseCoordinator {
  private proofService: ProofService

  public constructor(proofService: ProofService) {
    this.proofService = proofService
  }

  /**
   * Returns the proof auto accept config based on priority:
   *	- The record config takes first priority
   *	- Otherwise the agent config
   *	- Otherwise {@link AutoAcceptProof.Never} is returned
   */
  private static composeAutoAccept(
    recordConfig: AutoAcceptProof | undefined,
    agentConfig: AutoAcceptProof | undefined
  ) {
    return recordConfig ?? agentConfig ?? AutoAcceptProof.Never
  }

  /**
   * Checks whether it should automatically respond to a proposal
   */
  public async shouldAutoRespondToProposal(agentContext: AgentContext, proofRecord: ProofExchangeRecord) {
    const autoAccept = ProofResponseCoordinator.composeAutoAccept(
      proofRecord.autoAcceptProof,
      agentContext.config.autoAcceptProofs
    )

    if (autoAccept === AutoAcceptProof.Always) {
      return true
    }

    if (autoAccept === AutoAcceptProof.ContentApproved) {
      return this.proofService.shouldAutoRespondToProposal(agentContext, proofRecord)
    }

    return false
  }

  /**
   * Checks whether it should automatically respond to a request
   */
  public async shouldAutoRespondToRequest(agentContext: AgentContext, proofRecord: ProofExchangeRecord) {
    const autoAccept = ProofResponseCoordinator.composeAutoAccept(
      proofRecord.autoAcceptProof,
      agentContext.config.autoAcceptProofs
    )

    if (autoAccept === AutoAcceptProof.Always) {
      return true
    }

    if (autoAccept === AutoAcceptProof.ContentApproved) {
      return this.proofService.shouldAutoRespondToRequest(agentContext, proofRecord)
    }

    return false
  }

  /**
   * Checks whether it should automatically respond to a presentation of proof
   */
  public async shouldAutoRespondToPresentation(agentContext: AgentContext, proofRecord: ProofExchangeRecord) {
    const autoAccept = ProofResponseCoordinator.composeAutoAccept(
      proofRecord.autoAcceptProof,
      agentContext.config.autoAcceptProofs
    )

    if (autoAccept === AutoAcceptProof.Always) {
      return true
    }

    if (autoAccept === AutoAcceptProof.ContentApproved) {
      return this.proofService.shouldAutoRespondToPresentation(agentContext, proofRecord)
    }

    return false
  }
}
