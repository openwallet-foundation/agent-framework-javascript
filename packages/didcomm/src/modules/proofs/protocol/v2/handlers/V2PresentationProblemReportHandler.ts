import type { MessageHandler, MessageHandlerInboundMessage } from '../../../../../handlers'
import type { V2ProofProtocol } from '../V2ProofProtocol'

import { V2PresentationProblemReportMessage } from '../messages'

export class V2PresentationProblemReportHandler implements MessageHandler {
  private proofService: V2ProofProtocol
  public supportedMessages = [V2PresentationProblemReportMessage]

  public constructor(proofService: V2ProofProtocol) {
    this.proofService = proofService
  }

  public async handle(messageContext: MessageHandlerInboundMessage<V2PresentationProblemReportHandler>) {
    await this.proofService.processProblemReport(messageContext)
  }
}
