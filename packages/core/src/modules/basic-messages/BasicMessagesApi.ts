import type { BasicMessageRecord } from './repository/BasicMessageRecord'
import type { Query, QueryOptions } from '../../storage/StorageService'

import { AgentContext } from '../../agent'
import { MessageHandlerRegistry } from '../../agent/MessageHandlerRegistry'
import { MessageSender } from '../../agent/MessageSender'
import { OutboundMessageContext } from '../../agent/models'
import { injectable } from '../../plugins'
import { ConnectionService } from '../connections'

import { BasicMessageHandler } from './handlers'
import { BasicMessageService } from './services'

@injectable()
export class BasicMessagesApi {
  private basicMessageService: BasicMessageService
  private messageSender: MessageSender
  private connectionService: ConnectionService
  private agentContext: AgentContext

  public constructor(
    messageHandlerRegistry: MessageHandlerRegistry,
    basicMessageService: BasicMessageService,
    messageSender: MessageSender,
    connectionService: ConnectionService,
    agentContext: AgentContext
  ) {
    this.basicMessageService = basicMessageService
    this.messageSender = messageSender
    this.connectionService = connectionService
    this.agentContext = agentContext
    this.registerMessageHandlers(messageHandlerRegistry)
  }

  /**
   * Send a message to an active connection
   *
   * @param connectionId Connection Id
   * @param message Message contents
   * @throws {RecordNotFoundError} If connection is not found
   * @throws {MessageSendingError} If message is undeliverable
   * @returns the created record
   */
  public async sendMessage(connectionId: string, message: string, parentThreadId?: string) {
    const connection = await this.connectionService.getById(this.agentContext, connectionId)

    const { message: basicMessage, record: basicMessageRecord } = await this.basicMessageService.createMessage(
      this.agentContext,
      message,
      connection,
      parentThreadId
    )
    const outboundMessageContext = new OutboundMessageContext(basicMessage, {
      agentContext: this.agentContext,
      connection,
      associatedRecord: basicMessageRecord,
    })

    await this.messageSender.sendMessage(outboundMessageContext)
    return basicMessageRecord
  }

  /**
   * Retrieve all basic messages matching a given query
   *
   * @param query The query
   * @param queryOptions The query options
   * @returns array containing all matching records
   */
  public async findAllByQuery(query: Query<BasicMessageRecord>, queryOptions?: QueryOptions) {
    return this.basicMessageService.findAllByQuery(this.agentContext, query, queryOptions)
  }

  /**
   * Retrieve a basic message record by id
   *
   * @param basicMessageRecordId The basic message record id
   * @throws {RecordNotFoundError} If no record is found
   * @return The basic message record
   *
   */
  public async getById(basicMessageRecordId: string) {
    return this.basicMessageService.getById(this.agentContext, basicMessageRecordId)
  }

  /**
   * Retrieve a basic message record by thread id
   *
   * @param threadId The thread id
   * @throws {RecordNotFoundError} If no record is found
   * @throws {RecordDuplicateError} If multiple records are found
   * @returns The connection record
   */
  public async getByThreadId(basicMessageRecordId: string) {
    return this.basicMessageService.getByThreadId(this.agentContext, basicMessageRecordId)
  }

  /**
   * Delete a basic message record by id
   *
   * @param connectionId the basic message record id
   * @throws {RecordNotFoundError} If no record is found
   */
  public async deleteById(basicMessageRecordId: string) {
    await this.basicMessageService.deleteById(this.agentContext, basicMessageRecordId)
  }

  private registerMessageHandlers(messageHandlerRegistry: MessageHandlerRegistry) {
    messageHandlerRegistry.registerMessageHandler(new BasicMessageHandler(this.basicMessageService))
  }
}
