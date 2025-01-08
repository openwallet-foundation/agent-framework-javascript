import { AgentMessage } from '../../../AgentMessage'
import { IsValidMessageType, parseMessageType } from '../../../util/messageType'

export interface MediationDenyMessageOptions {
  id: string
}

/**
 * This message serves as notification of the mediator denying the recipient's request for mediation.
 *
 * @see https://github.com/hyperledger/aries-rfcs/blob/master/features/0211-route-coordination/README.md#mediation-deny
 */
export class MediationDenyMessage extends AgentMessage {
  public constructor(options: MediationDenyMessageOptions) {
    super()

    if (options) {
      this.id = options.id
    }
  }

  @IsValidMessageType(MediationDenyMessage.type)
  public readonly type = MediationDenyMessage.type.messageTypeUri
  public static readonly type = parseMessageType('https://didcomm.org/coordinate-mediation/1.0/mediate-deny')
}
