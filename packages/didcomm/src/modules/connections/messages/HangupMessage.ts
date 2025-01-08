import { AgentMessage } from '../../../AgentMessage'
import { IsValidMessageType, parseMessageType } from '../../../util/messageType'

export interface HangupMessageOptions {
  id?: string
}

/**
 * This message is sent by the rotating_party to inform the observing_party that they are done
 * with the relationship and will no longer be responding.
 *
 * @see https://github.com/hyperledger/aries-rfcs/tree/main/features/0794-did-rotate#hangup
 */
export class HangupMessage extends AgentMessage {
  /**
   * Create new HangupMessage instance.
   * @param options
   */
  public constructor(options: HangupMessageOptions) {
    super()

    if (options) {
      this.id = options.id || this.generateId()
    }
  }

  @IsValidMessageType(HangupMessage.type)
  public readonly type = HangupMessage.type.messageTypeUri
  public static readonly type = parseMessageType('https://didcomm.org/did-rotate/1.0/hangup')
}
