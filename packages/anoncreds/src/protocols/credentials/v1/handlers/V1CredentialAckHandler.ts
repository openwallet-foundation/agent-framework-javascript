import type { V1CredentialProtocol } from '../V1CredentialProtocol'
import type { MessageHandler, MessageHandlerInboundMessage } from '@credo-ts/didcomm'

import { V1CredentialAckMessage } from '../messages'

export class V1CredentialAckHandler implements MessageHandler {
  private credentialProtocol: V1CredentialProtocol
  public supportedMessages = [V1CredentialAckMessage]

  public constructor(credentialProtocol: V1CredentialProtocol) {
    this.credentialProtocol = credentialProtocol
  }

  public async handle(messageContext: MessageHandlerInboundMessage<V1CredentialAckHandler>) {
    await this.credentialProtocol.processAck(messageContext)
  }
}
