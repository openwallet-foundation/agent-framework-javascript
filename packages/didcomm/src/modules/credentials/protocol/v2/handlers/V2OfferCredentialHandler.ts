import type { MessageHandler, MessageHandlerInboundMessage } from '../../../../../handlers'
import type { InboundMessageContext } from '../../../../../models'
import type { CredentialExchangeRecord } from '../../../repository/CredentialExchangeRecord'
import type { V2CredentialProtocol } from '../V2CredentialProtocol'

import { getOutboundMessageContext } from '../../../../../getOutboundMessageContext'
import { V2OfferCredentialMessage } from '../messages/V2OfferCredentialMessage'

export class V2OfferCredentialHandler implements MessageHandler {
  private credentialProtocol: V2CredentialProtocol

  public supportedMessages = [V2OfferCredentialMessage]

  public constructor(credentialProtocol: V2CredentialProtocol) {
    this.credentialProtocol = credentialProtocol
  }

  public async handle(messageContext: InboundMessageContext<V2OfferCredentialMessage>) {
    const credentialRecord = await this.credentialProtocol.processOffer(messageContext)

    const shouldAutoRespond = await this.credentialProtocol.shouldAutoRespondToOffer(messageContext.agentContext, {
      credentialRecord,
      offerMessage: messageContext.message,
    })
    if (shouldAutoRespond) {
      return await this.acceptOffer(credentialRecord, messageContext)
    }
  }

  private async acceptOffer(
    credentialRecord: CredentialExchangeRecord,
    messageContext: MessageHandlerInboundMessage<V2OfferCredentialHandler>
  ) {
    messageContext.agentContext.config.logger.info(`Automatically sending request with autoAccept`)

    const { message } = await this.credentialProtocol.acceptOffer(messageContext.agentContext, { credentialRecord })

    return getOutboundMessageContext(messageContext.agentContext, {
      connectionRecord: messageContext.connection,
      message,
      associatedRecord: credentialRecord,
      lastReceivedMessage: messageContext.message,
    })
  }
}
