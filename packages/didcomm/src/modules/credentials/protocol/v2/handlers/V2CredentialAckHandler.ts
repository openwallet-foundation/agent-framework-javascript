import type { MessageHandler, MessageHandlerInboundMessage } from '../../../../../handlers'
import type { V2CredentialProtocol } from '../V2CredentialProtocol'

import { V2CredentialAckMessage } from '../messages/V2CredentialAckMessage'

export class V2CredentialAckHandler implements MessageHandler {
  private credentialProtocol: V2CredentialProtocol
  public supportedMessages = [V2CredentialAckMessage]

  public constructor(credentialProtocol: V2CredentialProtocol) {
    this.credentialProtocol = credentialProtocol
  }

  public async handle(messageContext: MessageHandlerInboundMessage<V2CredentialAckHandler>) {
    await this.credentialProtocol.processAck(messageContext)
  }
}
