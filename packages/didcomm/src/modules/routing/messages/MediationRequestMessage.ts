import { AgentMessage } from '../../../AgentMessage'
import { IsValidMessageType, parseMessageType } from '../../../util/messageType'

export interface MediationRequestMessageOptions {
  sentTime?: Date
  id?: string
  locale?: string
}

/**
 * This message serves as a request from the recipient to the mediator, asking for the permission (and routing information)
 * to publish the endpoint as a mediator.
 *
 * @see https://github.com/hyperledger/aries-rfcs/blob/master/features/0211-route-coordination/README.md#mediation-request
 */
export class MediationRequestMessage extends AgentMessage {
  /**
   * Create new BasicMessage instance.
   * sentTime will be assigned to new Date if not passed, id will be assigned to uuid/v4 if not passed
   * @param options
   */
  public constructor(options: MediationRequestMessageOptions) {
    super()

    if (options) {
      this.id = options.id || this.generateId()
      this.addLocale(options.locale || 'en')
    }
  }

  @IsValidMessageType(MediationRequestMessage.type)
  public readonly type = MediationRequestMessage.type.messageTypeUri
  public static readonly type = parseMessageType('https://didcomm.org/coordinate-mediation/1.0/mediate-request')
}
