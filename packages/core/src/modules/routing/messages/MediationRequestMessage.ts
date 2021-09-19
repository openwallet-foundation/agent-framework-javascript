import { Expose, Type } from 'class-transformer'
import { Equals, IsDate } from 'class-validator'

import { AgentMessage } from '../../../agent/AgentMessage'

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
      this.sentTime = options.sentTime || new Date()
      this.addLocale(options.locale || 'en')
    }
  }

  @Equals(MediationRequestMessage.type)
  public readonly type = MediationRequestMessage.type
  public static readonly type = 'https://didcomm.org/coordinate-mediation/1.0/mediate-request'

  @Expose({ name: 'sent_time' })
  @Type(() => Date)
  @IsDate()
  public sentTime!: Date
}
