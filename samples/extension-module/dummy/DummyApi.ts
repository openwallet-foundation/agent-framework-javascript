import type { DummyRecord } from './repository/DummyRecord'
import type { Query, QueryOptions } from '@credo-ts/core'

import { AgentContext, injectable } from '@credo-ts/core'
import { getOutboundMessageContext, ConnectionService, MessageSender } from '@credo-ts/didcomm'

import { DummyState } from './repository'
import { DummyService } from './services'

@injectable()
export class DummyApi {
  private messageSender: MessageSender
  private dummyService: DummyService
  private connectionService: ConnectionService
  private agentContext: AgentContext

  public constructor(
    messageSender: MessageSender,
    dummyService: DummyService,
    connectionService: ConnectionService,
    agentContext: AgentContext
  ) {
    this.messageSender = messageSender
    this.dummyService = dummyService
    this.connectionService = connectionService
    this.agentContext = agentContext
  }

  /**
   * Send a Dummy Request
   *
   * @param connection record of the target responder (must be active)
   * @returns created Dummy Record
   */
  public async request(connectionId: string) {
    const connection = await this.connectionService.getById(this.agentContext, connectionId)
    const { record, message } = await this.dummyService.createRequest(this.agentContext, connection)

    await this.messageSender.sendMessage(
      await getOutboundMessageContext(this.agentContext, {
        message,
        associatedRecord: record,
        connectionRecord: connection,
      })
    )

    await this.dummyService.updateState(this.agentContext, record, DummyState.RequestSent)

    return record
  }

  /**
   * Respond a Dummy Request
   *
   * @param record Dummy record
   * @returns Updated dummy record
   */
  public async respond(dummyId: string) {
    const record = await this.dummyService.getById(this.agentContext, dummyId)
    const connection = await this.connectionService.getById(this.agentContext, record.connectionId)

    const message = await this.dummyService.createResponse(this.agentContext, record)

    await this.messageSender.sendMessage(
      await getOutboundMessageContext(this.agentContext, {
        message,
        associatedRecord: record,
        connectionRecord: connection,
      })
    )

    await this.dummyService.updateState(this.agentContext, record, DummyState.ResponseSent)

    return record
  }

  /**
   * Retrieve all dummy records
   *
   * @returns List containing all records
   */
  public getAll(): Promise<DummyRecord[]> {
    return this.dummyService.getAll(this.agentContext)
  }

  /**
   * Retrieve all dummy records
   *
   * @returns List containing all records
   */
  public findAllByQuery(query: Query<DummyRecord>, queryOptions?: QueryOptions): Promise<DummyRecord[]> {
    return this.dummyService.findAllByQuery(this.agentContext, query, queryOptions)
  }
}
