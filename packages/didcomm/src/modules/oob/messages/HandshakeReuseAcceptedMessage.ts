import { AgentMessage } from '../../../AgentMessage'
import { IsValidMessageType, parseMessageType } from '../../../util/messageType'

export interface HandshakeReuseAcceptedMessageOptions {
  id?: string
  threadId: string
  parentThreadId: string
}

export class HandshakeReuseAcceptedMessage extends AgentMessage {
  public constructor(options: HandshakeReuseAcceptedMessageOptions) {
    super()

    if (options) {
      this.id = options.id ?? this.generateId()
      this.setThread({
        threadId: options.threadId,
        parentThreadId: options.parentThreadId,
      })
    }
  }

  @IsValidMessageType(HandshakeReuseAcceptedMessage.type)
  public readonly type = HandshakeReuseAcceptedMessage.type.messageTypeUri
  public static readonly type = parseMessageType('https://didcomm.org/out-of-band/1.1/handshake-reuse-accepted')
}
