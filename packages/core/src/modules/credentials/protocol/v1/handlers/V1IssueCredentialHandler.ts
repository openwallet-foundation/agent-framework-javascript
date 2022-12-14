import type { Handler, HandlerInboundMessage } from '../../../../../agent/Handler'
import type { CredentialExchangeRecord } from '../../../repository/CredentialExchangeRecord'
import type { V1CredentialProtocol } from '../V1CredentialProtocol'

import { OutboundMessageContext } from '../../../../../agent/models'
import { DidCommMessageRepository } from '../../../../../storage'
import { V1IssueCredentialMessage, V1RequestCredentialMessage } from '../messages'

export class V1IssueCredentialHandler implements Handler {
  private credentialProtocol: V1CredentialProtocol

  public supportedMessages = [V1IssueCredentialMessage]

  public constructor(credentialProtocol: V1CredentialProtocol) {
    this.credentialProtocol = credentialProtocol
  }

  public async handle(messageContext: HandlerInboundMessage<V1IssueCredentialHandler>) {
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
    messageContext: HandlerInboundMessage<V1IssueCredentialHandler>
  ) {
    messageContext.agentContext.config.logger.info(`Automatically sending acknowledgement with autoAccept`)
    const { message } = await this.credentialProtocol.acceptCredential(messageContext.agentContext, {
      credentialRecord,
    })

    const didCommMessageRepository = messageContext.agentContext.dependencyManager.resolve(DidCommMessageRepository)
    const requestMessage = await didCommMessageRepository.getAgentMessage(messageContext.agentContext, {
      associatedRecordId: credentialRecord.id,
      messageClass: V1RequestCredentialMessage,
    })

    if (messageContext.connection) {
      return new OutboundMessageContext(message, {
        agentContext: messageContext.agentContext,
        connection: messageContext.connection,
        associatedRecord: credentialRecord,
      })
    } else if (messageContext.message.service && requestMessage.service) {
      const recipientService = messageContext.message.service
      const ourService = requestMessage.service

      return new OutboundMessageContext(message, {
        agentContext: messageContext.agentContext,
        serviceParams: {
          service: recipientService.resolvedDidCommService,
          senderKey: ourService.resolvedDidCommService.recipientKeys[0],
        },
      })
    }

    messageContext.agentContext.config.logger.error(`Could not automatically create credential ack`)
  }
}
