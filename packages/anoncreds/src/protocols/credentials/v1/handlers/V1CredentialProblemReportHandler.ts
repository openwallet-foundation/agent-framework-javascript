import type { V1CredentialProtocol } from '../V1CredentialProtocol'

import { V1CredentialProblemReportMessage } from '../messages'
import { MessageHandler, MessageHandlerInboundMessage } from '@aries-framework/core'

export class V1CredentialProblemReportHandler implements MessageHandler {
  private credentialProtocol: V1CredentialProtocol
  public supportedMessages = [V1CredentialProblemReportMessage]

  public constructor(credentialProtocol: V1CredentialProtocol) {
    this.credentialProtocol = credentialProtocol
  }

  public async handle(messageContext: MessageHandlerInboundMessage<V1CredentialProblemReportHandler>) {
    await this.credentialProtocol.processProblemReport(messageContext)
  }
}