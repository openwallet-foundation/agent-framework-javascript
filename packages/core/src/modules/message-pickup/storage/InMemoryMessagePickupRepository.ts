import type { MessagePickupRepository } from './MessagePickupRepository'
import type {
  AddMessageOptions,
  GetAvailableMessageCountOptions,
  RemoveMessagesOptions,
  TakeFromQueueOptions,
} from './MessagePickupRepositoryOptions'
import type { QueuedMessage } from './QueuedMessage'

import { InjectionSymbols } from '../../../constants'
import { Logger } from '../../../logger'
import { injectable, inject } from '../../../plugins'
import { uuid } from '../../../utils/uuid'

interface InMemoryQueuedMessage extends QueuedMessage {
  connectionId: string
  recipientKeys: string[]
  state: 'pending' | 'sending'
}

@injectable()
export class InMemoryMessagePickupRepository implements MessagePickupRepository {
  private logger: Logger
  private messages: InMemoryQueuedMessage[]

  public constructor(@inject(InjectionSymbols.Logger) logger: Logger) {
    this.logger = logger
    this.messages = []
  }

  public getAvailableMessageCount(options: GetAvailableMessageCountOptions): number | Promise<number> {
    const { connectionId, recipientKey } = options

    const messages = this.messages.filter(
      (msg) =>
        msg.connectionId === connectionId &&
        (recipientKey === undefined || msg.recipientKeys.includes(recipientKey)) &&
        msg.state === 'pending'
    )
    return messages.length
  }

  public takeFromQueue(options: TakeFromQueueOptions): QueuedMessage[] {
    const { connectionId, recipientKey, limit, deleteMessages } = options

    let messages = this.messages.filter(
      (msg) =>
        msg.connectionId === connectionId &&
        msg.state === 'pending' &&
        (recipientKey === undefined || msg.recipientKeys.includes(recipientKey))
    )

    const messagesToTake = limit ?? messages.length

    messages = messages.slice(0, messagesToTake)

    this.logger.debug(`Taking ${messagesToTake} messages from queue for connection ${connectionId}`)

    // Mark taken messages in order to prevent them of being retrieved again
    messages.forEach((msg) => {
      const index = this.messages.findIndex((item) => item.id === msg.id)
      if (index !== -1) this.messages[index].state = 'sending'
    })

    if (deleteMessages) {
      this.removeMessages({ connectionId, messageIds: messages.map((msg) => msg.id) })
    }

    return messages
  }

  public addMessage(options: AddMessageOptions) {
    const { connectionId, recipientKeys, payload } = options

    const id = uuid()
    this.messages.push({
      id,
      connectionId,
      encryptedMessage: payload,
      recipientKeys,
      state: 'pending',
    })

    return id
  }

  public removeMessages(options: RemoveMessagesOptions) {
    const { messageIds } = options

    for (const messageId of messageIds) {
      const messageIndex = this.messages.findIndex((item) => item.id === messageId)
      if (messageIndex > -1) this.messages.splice(messageIndex, 1)
    }
  }
}
