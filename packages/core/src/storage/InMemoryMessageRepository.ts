import type { Logger } from '../logger'
import type { EncryptedMessage } from '../types'
import type { MessageRepository } from './MessageRepository'

import { AgentConfig } from '../agent/AgentConfig'
import { injectable } from '../plugins'

@injectable()
export class InMemoryMessageRepository implements MessageRepository {
  private logger: Logger
  private messages: { [key: string]: EncryptedMessage[] } = {}

  public constructor(agentConfig: AgentConfig) {
    this.logger = agentConfig.logger
  }

  public getAvailableMessageCount(connectionId: string): number | Promise<number> {
    return this.messages[connectionId] ? this.messages[connectionId].length : 0
  }

  public takeFromQueue(connectionId: string, limit?: number, keepMessages?: boolean) {
    if (!this.messages[connectionId]) {
      return []
    }

    const messagesToTake = limit ?? this.messages[connectionId].length
    this.logger.debug(`Taking ${messagesToTake} messages from queue for connection ${connectionId}`)

    return keepMessages
      ? this.messages[connectionId].slice(0, messagesToTake)
      : this.messages[connectionId].splice(0, messagesToTake)
  }

  public add(connectionId: string, payload: EncryptedMessage) {
    if (!this.messages[connectionId]) {
      this.messages[connectionId] = []
    }

    this.messages[connectionId].push(payload)
  }
}
