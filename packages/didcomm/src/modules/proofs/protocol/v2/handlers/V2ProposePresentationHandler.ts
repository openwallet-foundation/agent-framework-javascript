import type { MessageHandler, MessageHandlerInboundMessage } from '../../../../../handlers'
import type { ProofExchangeRecord } from '../../../repository/ProofExchangeRecord'
import type { V2ProofProtocol } from '../V2ProofProtocol'

import { OutboundMessageContext } from '../../../../../models'
import { V2ProposePresentationMessage } from '../messages/V2ProposePresentationMessage'

export class V2ProposePresentationHandler implements MessageHandler {
  private proofProtocol: V2ProofProtocol
  public supportedMessages = [V2ProposePresentationMessage]

  public constructor(proofProtocol: V2ProofProtocol) {
    this.proofProtocol = proofProtocol
  }

  public async handle(messageContext: MessageHandlerInboundMessage<V2ProposePresentationHandler>) {
    const proofRecord = await this.proofProtocol.processProposal(messageContext)

    const shouldAutoRespond = await this.proofProtocol.shouldAutoRespondToProposal(messageContext.agentContext, {
      proofRecord,
      proposalMessage: messageContext.message,
    })

    if (shouldAutoRespond) {
      return this.acceptProposal(proofRecord, messageContext)
    }
  }
  private async acceptProposal(
    proofRecord: ProofExchangeRecord,
    messageContext: MessageHandlerInboundMessage<V2ProposePresentationHandler>
  ) {
    messageContext.agentContext.config.logger.info(`Automatically sending request with autoAccept`)

    if (!messageContext.connection) {
      messageContext.agentContext.config.logger.error('No connection on the messageContext, aborting auto accept')
      return
    }

    const { message } = await this.proofProtocol.acceptProposal(messageContext.agentContext, { proofRecord })

    return new OutboundMessageContext(message, {
      agentContext: messageContext.agentContext,
      connection: messageContext.connection,
      associatedRecord: proofRecord,
    })
  }
}
