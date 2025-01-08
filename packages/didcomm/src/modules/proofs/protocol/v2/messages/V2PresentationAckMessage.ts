import { AckMessage } from '../../../../../messages'
import { IsValidMessageType, parseMessageType } from '../../../../../util/messageType'

export class V2PresentationAckMessage extends AckMessage {
  @IsValidMessageType(V2PresentationAckMessage.type)
  public readonly type = V2PresentationAckMessage.type.messageTypeUri
  public static readonly type = parseMessageType('https://didcomm.org/present-proof/2.0/ack')
}
