import type { MessageHandler, MessageHandlerInboundMessage } from '../../../../../handlers'
import type { ProofExchangeRecord } from '../../../repository/ProofExchangeRecord'
import type { V2ProofProtocol } from '../V2ProofProtocol'

import { getOutboundMessageContext } from '../../../../../getOutboundMessageContext'
import { V2RequestPresentationMessage } from '../messages/V2RequestPresentationMessage'

export class V2RequestPresentationHandler implements MessageHandler {
  private proofProtocol: V2ProofProtocol
  public supportedMessages = [V2RequestPresentationMessage]

  public constructor(proofProtocol: V2ProofProtocol) {
    this.proofProtocol = proofProtocol
  }

  public async handle(messageContext: MessageHandlerInboundMessage<V2RequestPresentationHandler>) {
    const proofRecord = await this.proofProtocol.processRequest(messageContext)

    const shouldAutoRespond = await this.proofProtocol.shouldAutoRespondToRequest(messageContext.agentContext, {
      proofRecord,
      requestMessage: messageContext.message,
    })

    messageContext.agentContext.config.logger.debug(`Should auto respond to request: ${shouldAutoRespond}`)

    if (shouldAutoRespond) {
      return await this.acceptRequest(proofRecord, messageContext)
    }
  }

  private async acceptRequest(
    proofRecord: ProofExchangeRecord,
    messageContext: MessageHandlerInboundMessage<V2RequestPresentationHandler>
  ) {
    messageContext.agentContext.config.logger.info(`Automatically sending presentation with autoAccept`)

    const { message } = await this.proofProtocol.acceptRequest(messageContext.agentContext, {
      proofRecord,
    })

    return getOutboundMessageContext(messageContext.agentContext, {
      message,
      lastReceivedMessage: messageContext.message,
      associatedRecord: proofRecord,
      connectionRecord: messageContext.connection,
    })
  }
}
