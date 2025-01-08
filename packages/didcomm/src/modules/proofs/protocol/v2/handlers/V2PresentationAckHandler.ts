import type { MessageHandler, MessageHandlerInboundMessage } from '../../../../../handlers'
import type { ProofProtocol } from '../../ProofProtocol'

import { V2PresentationAckMessage } from '../messages'

export class V2PresentationAckHandler implements MessageHandler {
  private proofProtocol: ProofProtocol
  public supportedMessages = [V2PresentationAckMessage]

  public constructor(proofProtocol: ProofProtocol) {
    this.proofProtocol = proofProtocol
  }

  public async handle(messageContext: MessageHandlerInboundMessage<V2PresentationAckHandler>) {
    await this.proofProtocol.processAck(messageContext)
  }
}
