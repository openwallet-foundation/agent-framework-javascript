import type { MessageHandler, MessageHandlerInboundMessage } from '../../../../../handlers'
import type { InboundMessageContext } from '../../../../../models'
import type { CredentialExchangeRecord } from '../../../repository/CredentialExchangeRecord'
import type { V2CredentialProtocol } from '../V2CredentialProtocol'

import { OutboundMessageContext } from '../../../../../models'
import { V2ProposeCredentialMessage } from '../messages/V2ProposeCredentialMessage'

export class V2ProposeCredentialHandler implements MessageHandler {
  private credentialProtocol: V2CredentialProtocol

  public supportedMessages = [V2ProposeCredentialMessage]

  public constructor(credentialProtocol: V2CredentialProtocol) {
    this.credentialProtocol = credentialProtocol
  }

  public async handle(messageContext: InboundMessageContext<V2ProposeCredentialMessage>) {
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
    messageContext: MessageHandlerInboundMessage<V2ProposeCredentialHandler>
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
