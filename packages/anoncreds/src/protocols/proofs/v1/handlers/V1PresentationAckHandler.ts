import type { V1ProofProtocol } from '../V1ProofProtocol'
import type { MessageHandler, MessageHandlerInboundMessage } from '@credo-ts/didcomm'

import { V1PresentationAckMessage } from '../messages'

export class V1PresentationAckHandler implements MessageHandler {
  private proofProtocol: V1ProofProtocol
  public supportedMessages = [V1PresentationAckMessage]

  public constructor(proofProtocol: V1ProofProtocol) {
    this.proofProtocol = proofProtocol
  }

  public async handle(messageContext: MessageHandlerInboundMessage<V1PresentationAckHandler>) {
    await this.proofProtocol.processAck(messageContext)
  }
}
