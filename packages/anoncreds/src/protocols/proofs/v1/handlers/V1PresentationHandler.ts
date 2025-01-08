import type { V1ProofProtocol } from '../V1ProofProtocol'
import type { MessageHandler, MessageHandlerInboundMessage, ProofExchangeRecord } from '@credo-ts/didcomm'

import { CredoError } from '@credo-ts/core'
import { getOutboundMessageContext } from '@credo-ts/didcomm'

import { V1PresentationMessage } from '../messages'

export class V1PresentationHandler implements MessageHandler {
  private proofProtocol: V1ProofProtocol
  public supportedMessages = [V1PresentationMessage]

  public constructor(proofProtocol: V1ProofProtocol) {
    this.proofProtocol = proofProtocol
  }

  public async handle(messageContext: MessageHandlerInboundMessage<V1PresentationHandler>) {
    const proofRecord = await this.proofProtocol.processPresentation(messageContext)

    const shouldAutoRespond = await this.proofProtocol.shouldAutoRespondToPresentation(messageContext.agentContext, {
      presentationMessage: messageContext.message,
      proofRecord,
    })

    if (shouldAutoRespond) {
      return await this.acceptPresentation(proofRecord, messageContext)
    }
  }

  private async acceptPresentation(
    proofRecord: ProofExchangeRecord,
    messageContext: MessageHandlerInboundMessage<V1PresentationHandler>
  ) {
    messageContext.agentContext.config.logger.info(`Automatically sending acknowledgement with autoAccept`)

    const requestMessage = await this.proofProtocol.findRequestMessage(messageContext.agentContext, proofRecord.id)
    if (!requestMessage) {
      throw new CredoError(`No request message found for proof record with id '${proofRecord.id}'`)
    }

    const { message } = await this.proofProtocol.acceptPresentation(messageContext.agentContext, {
      proofRecord,
    })

    return getOutboundMessageContext(messageContext.agentContext, {
      message,
      lastReceivedMessage: messageContext.message,
      lastSentMessage: requestMessage,
      associatedRecord: proofRecord,
      connectionRecord: messageContext.connection,
    })
  }
}
