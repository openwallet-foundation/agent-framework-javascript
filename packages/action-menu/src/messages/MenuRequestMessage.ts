import { AgentMessage, IsValidMessageType, parseMessageType } from '@credo-ts/didcomm'

/**
 * @internal
 */
export interface MenuRequestMessageOptions {
  id?: string
}

/**
 * @internal
 */
export class MenuRequestMessage extends AgentMessage {
  public constructor(options: MenuRequestMessageOptions) {
    super()

    if (options) {
      this.id = options.id ?? this.generateId()
    }
  }

  @IsValidMessageType(MenuRequestMessage.type)
  public readonly type = MenuRequestMessage.type.messageTypeUri
  public static readonly type = parseMessageType('https://didcomm.org/action-menu/1.0/menu-request')
}
