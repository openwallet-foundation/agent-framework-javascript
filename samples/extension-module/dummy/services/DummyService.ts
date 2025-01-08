import type { DummyStateChangedEvent } from './DummyEvents'
import type { Query, QueryOptions, AgentContext } from '@credo-ts/core'
import type { ConnectionRecord, InboundMessageContext } from '@credo-ts/didcomm'

import { injectable, EventEmitter } from '@credo-ts/core'

import { DummyModuleConfig } from '../DummyModuleConfig'
import { DummyRequestMessage, DummyResponseMessage } from '../messages'
import { DummyRecord } from '../repository/DummyRecord'
import { DummyRepository } from '../repository/DummyRepository'
import { DummyState } from '../repository/DummyState'

import { DummyEventTypes } from './DummyEvents'

@injectable()
export class DummyService {
  private dummyRepository: DummyRepository
  private eventEmitter: EventEmitter
  private dummyModuleConfig: DummyModuleConfig

  public constructor(
    dummyModuleConfig: DummyModuleConfig,
    dummyRepository: DummyRepository,
    eventEmitter: EventEmitter
  ) {
    this.dummyModuleConfig = dummyModuleConfig
    this.dummyRepository = dummyRepository
    this.eventEmitter = eventEmitter
  }

  /**
   * Create a {@link DummyRequestMessage}.
   *
   * @param connectionRecord The connection for which to create the dummy request
   * @returns Object containing dummy request message and associated dummy record
   *
   */
  public async createRequest(agentContext: AgentContext, connectionRecord: ConnectionRecord) {
    // Create message
    const message = new DummyRequestMessage({})

    // Create record
    const record = new DummyRecord({
      connectionId: connectionRecord.id,
      threadId: message.threadId,
      state: DummyState.Init,
    })

    await this.dummyRepository.save(agentContext, record)

    this.emitStateChangedEvent(agentContext, record, null)

    return { record, message }
  }

  /**
   * Create a dummy response message for the specified dummy record.
   *
   * @param record the dummy record for which to create a dummy response
   * @returns outbound message containing dummy response
   */
  public async createResponse(agentContext: AgentContext, record: DummyRecord) {
    const responseMessage = new DummyResponseMessage({
      threadId: record.threadId,
    })

    return responseMessage
  }

  /**
   * Process a received {@link DummyRequestMessage}.
   *
   * @param messageContext The message context containing a dummy request message
   * @returns dummy record associated with the dummy request message
   *
   */
  public async processRequest(messageContext: InboundMessageContext<DummyRequestMessage>) {
    const connectionRecord = messageContext.assertReadyConnection()

    // Create record
    const record = new DummyRecord({
      connectionId: connectionRecord.id,
      threadId: messageContext.message.threadId,
      state: DummyState.RequestReceived,
    })

    await this.dummyRepository.save(messageContext.agentContext, record)

    this.emitStateChangedEvent(messageContext.agentContext, record, null)

    if (this.dummyModuleConfig.autoAcceptRequests) {
      return await this.createResponse(messageContext.agentContext, record)
    }
  }

  /**
   * Process a received {@link DummyResponseMessage}.
   *
   * @param messageContext The message context containing a dummy response message
   * @returns dummy record associated with the dummy response message
   *
   */
  public async processResponse(messageContext: InboundMessageContext<DummyResponseMessage>) {
    const { message } = messageContext

    const connection = messageContext.assertReadyConnection()

    // Dummy record already exists
    const record = await this.findByThreadAndConnectionId(messageContext.agentContext, message.threadId, connection.id)

    if (record) {
      // Check current state
      record.assertState(DummyState.RequestSent)

      await this.updateState(messageContext.agentContext, record, DummyState.ResponseReceived)
    } else {
      throw new Error(`Dummy record not found with threadId ${message.threadId}`)
    }

    return record
  }

  /**
   * Retrieve all dummy records
   *
   * @returns List containing all dummy records
   */
  public getAll(agentContext: AgentContext): Promise<DummyRecord[]> {
    return this.dummyRepository.getAll(agentContext)
  }

  /**
   * Retrieve dummy records by query
   *
   * @returns List containing all dummy records matching query
   */
  public findAllByQuery(
    agentContext: AgentContext,
    query: Query<DummyRecord>,
    queryOptions?: QueryOptions
  ): Promise<DummyRecord[]> {
    return this.dummyRepository.findByQuery(agentContext, query, queryOptions)
  }

  /**
   * Retrieve a dummy record by id
   *
   * @param dummyRecordId The dummy record id
   * @throws {RecordNotFoundError} If no record is found
   * @return The dummy record
   *
   */
  public getById(agentContext: AgentContext, dummyRecordId: string): Promise<DummyRecord> {
    return this.dummyRepository.getById(agentContext, dummyRecordId)
  }

  /**
   * Retrieve a dummy record by connection id and thread id
   *
   * @param connectionId The connection id
   * @param threadId The thread id
   * @throws {RecordNotFoundError} If no record is found
   * @throws {RecordDuplicateError} If multiple records are found
   * @returns The dummy record
   */
  public async findByThreadAndConnectionId(
    agentContext: AgentContext,
    threadId: string,
    connectionId?: string
  ): Promise<DummyRecord | null> {
    return this.dummyRepository.findSingleByQuery(agentContext, { threadId, connectionId })
  }

  /**
   * Update the record to a new state and emit an state changed event. Also updates the record
   * in storage.
   *
   * @param dummyRecord The record to update the state for
   * @param newState The state to update to
   *
   */
  public async updateState(agentContext: AgentContext, dummyRecord: DummyRecord, newState: DummyState) {
    const previousState = dummyRecord.state
    dummyRecord.state = newState
    await this.dummyRepository.update(agentContext, dummyRecord)

    this.emitStateChangedEvent(agentContext, dummyRecord, previousState)
  }

  private emitStateChangedEvent(
    agentContext: AgentContext,
    dummyRecord: DummyRecord,
    previousState: DummyState | null
  ) {
    this.eventEmitter.emit<DummyStateChangedEvent>(agentContext, {
      type: DummyEventTypes.StateChanged,
      payload: {
        // we need to clone the dummy record to avoid mutating records after they're emitted in an event
        dummyRecord: dummyRecord.clone(),
        previousState: previousState,
      },
    })
  }
}
