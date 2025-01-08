import type { MessageHandler, MessageHandlerInboundMessage } from '../../../../../handlers'
import type { ProofExchangeRecord } from '../../../repository'
import type { V2ProofProtocol } from '../V2ProofProtocol'

import { getOutboundMessageContext } from '../../../../../getOutboundMessageContext'
import { DidCommMessageRepository, DidCommMessageRole } from '../../../../../repository'
import { V2PresentationMessage, V2RequestPresentationMessage } from '../messages'

export class V2PresentationHandler implements MessageHandler {
  private proofProtocol: V2ProofProtocol
  public supportedMessages = [V2PresentationMessage]

  public constructor(proofProtocol: V2ProofProtocol) {
    this.proofProtocol = proofProtocol
  }

  public async handle(messageContext: MessageHandlerInboundMessage<V2PresentationHandler>) {
    const proofRecord = await this.proofProtocol.processPresentation(messageContext)

    const shouldAutoRespond = await this.proofProtocol.shouldAutoRespondToPresentation(messageContext.agentContext, {
      proofRecord,
      presentationMessage: messageContext.message,
    })

    if (shouldAutoRespond) {
      return await this.acceptPresentation(proofRecord, messageContext)
    }
  }

  private async acceptPresentation(
    proofRecord: ProofExchangeRecord,
    messageContext: MessageHandlerInboundMessage<V2PresentationHandler>
  ) {
    messageContext.agentContext.config.logger.info(`Automatically sending acknowledgement with autoAccept`)

    const { message } = await this.proofProtocol.acceptPresentation(messageContext.agentContext, {
      proofRecord,
    })

    const didCommMessageRepository = messageContext.agentContext.dependencyManager.resolve(DidCommMessageRepository)
    const requestMessage = await didCommMessageRepository.getAgentMessage(messageContext.agentContext, {
      associatedRecordId: proofRecord.id,
      messageClass: V2RequestPresentationMessage,
      role: DidCommMessageRole.Sender,
    })

    return getOutboundMessageContext(messageContext.agentContext, {
      connectionRecord: messageContext.connection,
      message,
      associatedRecord: proofRecord,
      lastReceivedMessage: messageContext.message,
      lastSentMessage: requestMessage,
    })
  }
}
