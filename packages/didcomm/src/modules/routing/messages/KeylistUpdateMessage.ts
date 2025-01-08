import { Expose, Type } from 'class-transformer'
import { IsArray, ValidateNested, IsString, IsEnum, IsInstance } from 'class-validator'

import { AgentMessage } from '../../../AgentMessage'
import { IsValidMessageType, parseMessageType } from '../../../util/messageType'

export enum KeylistUpdateAction {
  add = 'add',
  remove = 'remove',
}

export interface KeylistUpdateOptions {
  recipientKey: string
  action: KeylistUpdateAction
}

export class KeylistUpdate {
  public constructor(options: KeylistUpdateOptions) {
    if (options) {
      this.recipientKey = options.recipientKey
      this.action = options.action
    }
  }

  @IsString()
  @Expose({ name: 'recipient_key' })
  public recipientKey!: string

  @IsEnum(KeylistUpdateAction)
  public action!: KeylistUpdateAction
}

export interface KeylistUpdateMessageOptions {
  id?: string
  updates: KeylistUpdate[]
}

/**
 * Used to notify the mediator of keys in use by the recipient.
 *
 * @see https://github.com/hyperledger/aries-rfcs/blob/master/features/0211-route-coordination/README.md#keylist-update
 */
export class KeylistUpdateMessage extends AgentMessage {
  public constructor(options: KeylistUpdateMessageOptions) {
    super()

    if (options) {
      this.id = options.id || this.generateId()
      this.updates = options.updates
    }
  }

  @IsValidMessageType(KeylistUpdateMessage.type)
  public readonly type = KeylistUpdateMessage.type.messageTypeUri
  public static readonly type = parseMessageType('https://didcomm.org/coordinate-mediation/1.0/keylist-update')

  @Type(() => KeylistUpdate)
  @IsArray()
  @ValidateNested()
  @IsInstance(KeylistUpdate, { each: true })
  public updates!: KeylistUpdate[]
}
