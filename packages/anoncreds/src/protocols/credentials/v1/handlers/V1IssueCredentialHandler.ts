import type { V1CredentialProtocol } from '../V1CredentialProtocol'
import type { MessageHandler, MessageHandlerInboundMessage, CredentialExchangeRecord } from '@credo-ts/didcomm'

import { CredoError } from '@credo-ts/core'
import { getOutboundMessageContext } from '@credo-ts/didcomm'

import { V1IssueCredentialMessage } from '../messages'

export class V1IssueCredentialHandler implements MessageHandler {
  private credentialProtocol: V1CredentialProtocol

  public supportedMessages = [V1IssueCredentialMessage]

  public constructor(credentialProtocol: V1CredentialProtocol) {
    this.credentialProtocol = credentialProtocol
  }

  public async handle(messageContext: MessageHandlerInboundMessage<V1IssueCredentialHandler>) {
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
    messageContext: MessageHandlerInboundMessage<V1IssueCredentialHandler>
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
