import type { AgentContext } from '../../../agent'
import type { InboundMessageContext } from '../../../agent/models/InboundMessageContext'
import type { Query, QueryOptions } from '../../../storage/StorageService'
import type { ConnectionRecord } from '../../connections/repository/ConnectionRecord'
import type { BasicMessageStateChangedEvent } from '../BasicMessageEvents'

import { EventEmitter } from '../../../agent/EventEmitter'
import { injectable } from '../../../plugins'
import { BasicMessageEventTypes } from '../BasicMessageEvents'
import { BasicMessageRole } from '../BasicMessageRole'
import { BasicMessage } from '../messages'
import { BasicMessageRecord, BasicMessageRepository } from '../repository'

@injectable()
export class BasicMessageService {
  private basicMessageRepository: BasicMessageRepository
  private eventEmitter: EventEmitter

  public constructor(basicMessageRepository: BasicMessageRepository, eventEmitter: EventEmitter) {
    this.basicMessageRepository = basicMessageRepository
    this.eventEmitter = eventEmitter
  }

  public async createMessage(
    agentContext: AgentContext,
    message: string,
    connectionRecord: ConnectionRecord,
    parentThreadId?: string
  ) {
    const basicMessage = new BasicMessage({ content: message })

    // If no parentThreadid is defined, there is no need to explicitly send a thread decorator
    if (parentThreadId) {
      basicMessage.setThread({ parentThreadId })
    }

    const basicMessageRecord = new BasicMessageRecord({
      sentTime: basicMessage.sentTime.toISOString(),
      content: basicMessage.content,
      connectionId: connectionRecord.id,
      role: BasicMessageRole.Sender,
      threadId: basicMessage.threadId,
      parentThreadId,
    })

    await this.basicMessageRepository.save(agentContext, basicMessageRecord)
    this.emitStateChangedEvent(agentContext, basicMessageRecord, basicMessage)

    return { message: basicMessage, record: basicMessageRecord }
  }

  /**
   * @todo use connection from message context
   */
  public async save({ message, agentContext }: InboundMessageContext<BasicMessage>, connection: ConnectionRecord) {
    const basicMessageRecord = new BasicMessageRecord({
      sentTime: message.sentTime.toISOString(),
      content: message.content,
      connectionId: connection.id,
      role: BasicMessageRole.Receiver,
      threadId: message.threadId,
      parentThreadId: message.thread?.parentThreadId,
    })

    await this.basicMessageRepository.save(agentContext, basicMessageRecord)
    this.emitStateChangedEvent(agentContext, basicMessageRecord, message)
  }

  private emitStateChangedEvent(
    agentContext: AgentContext,
    basicMessageRecord: BasicMessageRecord,
    basicMessage: BasicMessage
  ) {
    this.eventEmitter.emit<BasicMessageStateChangedEvent>(agentContext, {
      type: BasicMessageEventTypes.BasicMessageStateChanged,
      payload: { message: basicMessage, basicMessageRecord: basicMessageRecord.clone() },
    })
  }

  public async findAllByQuery(
    agentContext: AgentContext,
    query: Query<BasicMessageRecord>,
    queryOptions?: QueryOptions
  ) {
    return this.basicMessageRepository.findByQuery(agentContext, query, queryOptions)
  }

  public async getById(agentContext: AgentContext, basicMessageRecordId: string) {
    return this.basicMessageRepository.getById(agentContext, basicMessageRecordId)
  }

  public async getByThreadId(agentContext: AgentContext, threadId: string) {
    return this.basicMessageRepository.getSingleByQuery(agentContext, { threadId })
  }

  public async findAllByParentThreadId(agentContext: AgentContext, parentThreadId: string) {
    return this.basicMessageRepository.findByQuery(agentContext, { parentThreadId })
  }

  public async deleteById(agentContext: AgentContext, basicMessageRecordId: string) {
    const basicMessageRecord = await this.getById(agentContext, basicMessageRecordId)
    return this.basicMessageRepository.delete(agentContext, basicMessageRecord)
  }
}
