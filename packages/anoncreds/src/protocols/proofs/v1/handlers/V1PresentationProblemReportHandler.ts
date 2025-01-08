import type { V1ProofProtocol } from '../V1ProofProtocol'
import type { MessageHandler, MessageHandlerInboundMessage } from '@credo-ts/didcomm'

import { V1PresentationProblemReportMessage } from '../messages/V1PresentationProblemReportMessage'

export class V1PresentationProblemReportHandler implements MessageHandler {
  private proofProtocol: V1ProofProtocol
  public supportedMessages = [V1PresentationProblemReportMessage]

  public constructor(proofProtocol: V1ProofProtocol) {
    this.proofProtocol = proofProtocol
  }

  public async handle(messageContext: MessageHandlerInboundMessage<V1PresentationProblemReportHandler>) {
    await this.proofProtocol.processProblemReport(messageContext)
  }
}
