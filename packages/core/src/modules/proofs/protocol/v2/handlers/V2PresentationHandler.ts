import type { AgentConfig } from '../../../../../agent/AgentConfig'
import type { MessageHandler, MessageHandlerInboundMessage } from '../../../../../agent/MessageHandler'
import type { DidCommMessageRepository } from '../../../../../storage'
import type { ProofResponseCoordinator } from '../../../ProofResponseCoordinator'
import type { ProofExchangeRecord } from '../../../repository'
import type { V2ProofService } from '../V2ProofService'

import { OutboundMessageContext } from '../../../../../agent/models'
import { V2PresentationMessage, V2RequestPresentationMessage } from '../messages'

export class V2PresentationHandler implements MessageHandler {
  private proofService: V2ProofService
  private agentConfig: AgentConfig
  private proofResponseCoordinator: ProofResponseCoordinator
  private didCommMessageRepository: DidCommMessageRepository
  public supportedMessages = [V2PresentationMessage]

  public constructor(
    proofService: V2ProofService,
    agentConfig: AgentConfig,
    proofResponseCoordinator: ProofResponseCoordinator,
    didCommMessageRepository: DidCommMessageRepository
  ) {
    this.proofService = proofService
    this.agentConfig = agentConfig
    this.proofResponseCoordinator = proofResponseCoordinator
    this.didCommMessageRepository = didCommMessageRepository
  }

  public async handle(messageContext: MessageHandlerInboundMessage<V2PresentationHandler>) {
    const proofRecord = await this.proofService.processPresentation(messageContext)

    const shouldAutoRespond = await this.proofResponseCoordinator.shouldAutoRespondToPresentation(
      messageContext.agentContext,
      proofRecord
    )

    if (shouldAutoRespond) {
      return await this.createAck(proofRecord, messageContext)
    }
  }

  private async createAck(
    record: ProofExchangeRecord,
    messageContext: MessageHandlerInboundMessage<V2PresentationHandler>
  ) {
    this.agentConfig.logger.info(
      `Automatically sending acknowledgement with autoAccept on ${this.agentConfig.autoAcceptProofs}`
    )

    const { message, proofRecord } = await this.proofService.createAck(messageContext.agentContext, {
      proofRecord: record,
    })

    const requestMessage = await this.didCommMessageRepository.findAgentMessage(messageContext.agentContext, {
      associatedRecordId: proofRecord.id,
      messageClass: V2RequestPresentationMessage,
    })

    const presentationMessage = await this.didCommMessageRepository.findAgentMessage(messageContext.agentContext, {
      associatedRecordId: proofRecord.id,
      messageClass: V2PresentationMessage,
    })

    if (messageContext.connection) {
      return new OutboundMessageContext(message, {
        agentContext: messageContext.agentContext,
        connection: messageContext.connection,
        associatedRecord: proofRecord,
      })
    } else if (requestMessage?.service && presentationMessage?.service) {
      const recipientService = presentationMessage?.service
      const ourService = requestMessage?.service

      return new OutboundMessageContext(message, {
        agentContext: messageContext.agentContext,
        serviceParams: {
          service: recipientService.resolvedDidCommService,
          senderKey: ourService.resolvedDidCommService.recipientKeys[0],
        },
      })
    }

    this.agentConfig.logger.error(`Could not automatically create presentation ack`)
  }
}
