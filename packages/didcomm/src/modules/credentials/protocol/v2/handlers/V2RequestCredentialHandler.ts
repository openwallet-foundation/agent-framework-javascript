import type { MessageHandler } from '../../../../../handlers'
import type { InboundMessageContext } from '../../../../../models'
import type { CredentialExchangeRecord } from '../../../repository'
import type { V2CredentialProtocol } from '../V2CredentialProtocol'

import { CredoError } from '@credo-ts/core'
import { getOutboundMessageContext } from '../../../../../getOutboundMessageContext'
import { V2RequestCredentialMessage } from '../messages/V2RequestCredentialMessage'

export class V2RequestCredentialHandler implements MessageHandler {
  private credentialProtocol: V2CredentialProtocol

  public supportedMessages = [V2RequestCredentialMessage]

  public constructor(credentialProtocol: V2CredentialProtocol) {
    this.credentialProtocol = credentialProtocol
  }

  public async handle(messageContext: InboundMessageContext<V2RequestCredentialMessage>) {
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
    messageContext: InboundMessageContext<V2RequestCredentialMessage>
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
