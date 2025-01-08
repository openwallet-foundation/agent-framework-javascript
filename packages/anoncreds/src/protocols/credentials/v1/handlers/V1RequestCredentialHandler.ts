import type { V1CredentialProtocol } from '../V1CredentialProtocol'
import type { CredentialExchangeRecord, MessageHandler, MessageHandlerInboundMessage } from '@credo-ts/didcomm'

import { CredoError } from '@credo-ts/core'
import { getOutboundMessageContext } from '@credo-ts/didcomm'

import { V1RequestCredentialMessage } from '../messages'

export class V1RequestCredentialHandler implements MessageHandler {
  private credentialProtocol: V1CredentialProtocol
  public supportedMessages = [V1RequestCredentialMessage]

  public constructor(credentialProtocol: V1CredentialProtocol) {
    this.credentialProtocol = credentialProtocol
  }

  public async handle(messageContext: MessageHandlerInboundMessage<V1RequestCredentialHandler>) {
    const credentialRecord = await this.credentialProtocol.processRequest(messageContext)

    const shouldAutoRespond = await this.credentialProtocol.shouldAutoRespondToRequest(messageContext.agentContext, {
      credentialRecord,
      requestMessage: messageContext.message,
    })

    if (shouldAutoRespond) {
      return await this.acceptRequest(credentialRecord, messageContext)
    }
  }

  private async acceptRequest(
    credentialRecord: CredentialExchangeRecord,
    messageContext: MessageHandlerInboundMessage<V1RequestCredentialHandler>
  ) {
    messageContext.agentContext.config.logger.info(`Automatically sending credential with autoAccept`)

    const offerMessage = await this.credentialProtocol.findOfferMessage(
      messageContext.agentContext,
      credentialRecord.id
    )
    if (!offerMessage) {
      throw new CredoError(`Could not find offer message for credential record with id ${credentialRecord.id}`)
    }

    const { message } = await this.credentialProtocol.acceptRequest(messageContext.agentContext, {
      credentialRecord,
    })

    return getOutboundMessageContext(messageContext.agentContext, {
      connectionRecord: messageContext.connection,
      message,
      associatedRecord: credentialRecord,
      lastReceivedMessage: messageContext.message,
      lastSentMessage: offerMessage,
    })
  }
}
