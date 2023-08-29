import type { MessageHandler, MessageHandlerInboundMessage } from '../../../../../agent/MessageHandler'
import type { InboundMessageContext } from '../../../../../agent/models/InboundMessageContext'
import type { CredentialExchangeRecord } from '../../../repository/CredentialExchangeRecord'
import type { V3CredentialProtocol } from '../V3CredentialProtocol'

import { OutboundMessageContext } from '../../../../../agent/models'
import { V3ProposeCredentialMessage } from '../messages/V3ProposeCredentialMessage'

export class V3ProposeCredentialHandler implements MessageHandler {
  private credentialProtocol: V3CredentialProtocol

  public supportedMessages = [V3ProposeCredentialMessage]

  public constructor(credentialProtocol: V3CredentialProtocol) {
    this.credentialProtocol = credentialProtocol
  }

  public async handle(messageContext: InboundMessageContext<V3ProposeCredentialMessage>) {
    const credentialRecord = await this.credentialProtocol.processProposal(messageContext)

    const shouldAutoRespond = await this.credentialProtocol.shouldAutoRespondToProposal(messageContext.agentContext, {
      credentialRecord,
      proposalMessage: messageContext.message,
    })

    if (shouldAutoRespond) {
      return await this.acceptProposal(credentialRecord, messageContext)
    }
  }

  private async acceptProposal(
    credentialRecord: CredentialExchangeRecord,
    messageContext: MessageHandlerInboundMessage<V3ProposeCredentialHandler>
  ) {
    messageContext.agentContext.config.logger.info(`Automatically sending offer with autoAccept`)

    if (!messageContext.connection) {
      messageContext.agentContext.config.logger.error('No connection on the messageContext, aborting auto accept')
      return
    }

    const { message } = await this.credentialProtocol.acceptProposal(messageContext.agentContext, { credentialRecord })

    return new OutboundMessageContext(message, {
      agentContext: messageContext.agentContext,
      connection: messageContext.connection,
      associatedRecord: credentialRecord,
    })
  }
}
