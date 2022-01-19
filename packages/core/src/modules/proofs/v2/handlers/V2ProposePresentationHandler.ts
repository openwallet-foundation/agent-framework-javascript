import type { AgentConfig } from '../../../../agent/AgentConfig'
import type { Handler, HandlerInboundMessage } from '../../../../agent/Handler'
import type { ProofResponseCoordinator } from '../../ProofResponseCoordinator'
import type { ProofRecord } from '../../repository'
import type { V2ProofService } from '../V2ProofService'
import type { AcceptProposalOptions, ProofRequestAsResponse } from '../interface'

import { createOutboundMessage } from '../../../../agent/helpers'
import { ProofProtocolVersion } from '../../ProofProtocolVersion'
import { V2ProposalPresentationMessage } from '../messages/V2ProposalPresentationMessage'

export class V2ProposePresentationHandler implements Handler {
  private proofService: V2ProofService
  private agentConfig: AgentConfig
  private proofResponseCoordinator: ProofResponseCoordinator
  public supportedMessages = [V2ProposalPresentationMessage]

  public constructor(
    proofService: V2ProofService,
    agentConfig: AgentConfig,
    proofResponseCoordinator: ProofResponseCoordinator
  ) {
    this.proofService = proofService
    this.agentConfig = agentConfig
    this.proofResponseCoordinator = proofResponseCoordinator
  }

  public async handle(messageContext: HandlerInboundMessage<V2ProposePresentationHandler>) {
    const proofRecord = await this.proofService.processProposal(messageContext)

    if (this.proofResponseCoordinator.shouldAutoRespondToProposal(proofRecord)) {
      return this.createRequest(proofRecord, messageContext)
    }
  }

  private async createRequest(
    proofRecord: ProofRecord,
    messageContext: HandlerInboundMessage<V2ProposePresentationHandler>
  ) {
    this.agentConfig.logger.info(
      `Automatically sending request with autoAccept on ${this.agentConfig.autoAcceptProofs}`
    )

    if (!messageContext.connection) {
      this.agentConfig.logger.error('No connection on the messageContext')
      return
    }
    if (!proofRecord.proposalMessage) {
      this.agentConfig.logger.error(`Proof record with id ${proofRecord.id} is missing required credential proposal`)
      return
    }

    const acceptProposal: AcceptProposalOptions = {
      protocolVersion: ProofProtocolVersion.V2_0,
      proofFormats: {
        indy: {
          proofRequestOptions: {
            name: 'proof-request',
            version: '1.0',
          },
          presentationProposal: proofRecord.proposalMessage?.presentationProposal,
        },
      },
      proofRecordId: proofRecord.id,
    }

    const proofRequest = await this.proofService.createProofRequestFromProposal(acceptProposal)

    const proofRequestAsResponse: ProofRequestAsResponse = {
      proofRecord,
      proofRequest,
    }
    const { message } = await this.proofService.createRequestAsResponse(proofRequestAsResponse)

    return createOutboundMessage(messageContext.connection, message)
  }
}
