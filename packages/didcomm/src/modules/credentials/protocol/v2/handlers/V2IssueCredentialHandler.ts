import type { MessageHandler, MessageHandlerInboundMessage } from '../../../../../handlers'
import type { InboundMessageContext } from '../../../../../models'
import type { CredentialExchangeRecord } from '../../../repository/CredentialExchangeRecord'
import type { V2CredentialProtocol } from '../V2CredentialProtocol'

import { CredoError } from '@credo-ts/core'
import { getOutboundMessageContext } from '../../../../../getOutboundMessageContext'
import { V2IssueCredentialMessage } from '../messages/V2IssueCredentialMessage'

export class V2IssueCredentialHandler implements MessageHandler {
  private credentialProtocol: V2CredentialProtocol
  public supportedMessages = [V2IssueCredentialMessage]

  public constructor(credentialProtocol: V2CredentialProtocol) {
    this.credentialProtocol = credentialProtocol
  }

  public async handle(messageContext: InboundMessageContext<V2IssueCredentialMessage>) {
    const credentialRecord = await this.credentialProtocol.processCredential(messageContext)

    const shouldAutoRespond = await this.credentialProtocol.shouldAutoRespondToCredential(messageContext.agentContext, {
      credentialRecord,
      credentialMessage: messageContext.message,
    })

    if (shouldAutoRespond) {
      return await this.acceptCredential(credentialRecord, messageContext)
    }
  }

  private async acceptCredential(
    credentialRecord: CredentialExchangeRecord,
    messageContext: MessageHandlerInboundMessage<V2IssueCredentialHandler>
  ) {
    messageContext.agentContext.config.logger.info(`Automatically sending acknowledgement with autoAccept`)
    const { message } = await this.credentialProtocol.acceptCredential(messageContext.agentContext, {
      credentialRecord,
    })

    const requestMessage = await this.credentialProtocol.findRequestMessage(
      messageContext.agentContext,
      credentialRecord.id
    )
    if (!requestMessage) {
      throw new CredoError(`No request message found for credential record with id '${credentialRecord.id}'`)
    }

    return getOutboundMessageContext(messageContext.agentContext, {
      connectionRecord: messageContext.connection,
      message,
      associatedRecord: credentialRecord,
      lastReceivedMessage: messageContext.message,
      lastSentMessage: requestMessage,
    })
  }
}
