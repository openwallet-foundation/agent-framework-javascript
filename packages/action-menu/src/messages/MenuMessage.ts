import type { ActionMenuOptionOptions } from '../models'

import { AgentMessage, IsValidMessageType, parseMessageType } from '@credo-ts/didcomm'
import { Expose, Type } from 'class-transformer'
import { IsInstance, IsOptional, IsString } from 'class-validator'

import { ActionMenuOption } from '../models'

/**
 * @internal
 */
export interface MenuMessageOptions {
  id?: string
  title: string
  description: string
  errorMessage?: string
  options: ActionMenuOptionOptions[]
  threadId?: string
}

/**
 * @internal
 */
export class MenuMessage extends AgentMessage {
  public constructor(options: MenuMessageOptions) {
    super()

    if (options) {
      this.id = options.id ?? this.generateId()
      this.title = options.title
      this.description = options.description
      this.errorMessage = options.errorMessage
      this.options = options.options.map((p) => new ActionMenuOption(p))
      if (options.threadId) {
        this.setThread({
          threadId: options.threadId,
        })
      }
    }
  }

  @IsValidMessageType(MenuMessage.type)
  public readonly type = MenuMessage.type.messageTypeUri
  public static readonly type = parseMessageType('https://didcomm.org/action-menu/1.0/menu')

  @IsString()
  public title!: string

  @IsString()
  public description!: string

  @Expose({ name: 'errormsg' })
  @IsString()
  @IsOptional()
  public errorMessage?: string

  @IsInstance(ActionMenuOption, { each: true })
  @Type(() => ActionMenuOption)
  public options!: ActionMenuOption[]
}
