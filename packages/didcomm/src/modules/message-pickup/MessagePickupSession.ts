import type { MessagePickupProtocolVersionType } from './MessagePickupApiOptions'
import type { MessagePickupProtocol } from './protocol/MessagePickupProtocol'

export enum MessagePickupSessionRole {
  Recipient = 'Recipient',
  MessageHolder = 'MessageHolder',
}
export type MessagePickupSession<MPPs extends MessagePickupProtocol[] = MessagePickupProtocol[]> = {
  id: string
  connectionId: string
  protocolVersion: MessagePickupProtocolVersionType<MPPs>
  role: MessagePickupSessionRole
}
