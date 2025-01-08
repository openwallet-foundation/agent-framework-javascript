import type { DrpcRequestStateChangedEvent } from '../DrpcRequestEvents'
import type { DrpcResponseStateChangedEvent } from '../DrpcResponseEvents'
import type { DrpcRequest, DrpcResponse } from '../messages'
import type { AgentContext, Query, QueryOptions } from '@credo-ts/core'
import type { InboundMessageContext } from '@credo-ts/didcomm'

import { EventEmitter, injectable } from '@credo-ts/core'

import { DrpcRequestEventTypes } from '../DrpcRequestEvents'
import { DrpcResponseEventTypes } from '../DrpcResponseEvents'
import { DrpcRequestMessage, DrpcResponseMessage } from '../messages'
import { DrpcRole, DrpcState, isValidDrpcRequest, isValidDrpcResponse } from '../models'
import { DrpcRecord, DrpcRepository } from '../repository'

@injectable()
export class DrpcService {
  private drpcMessageRepository: DrpcRepository
  private eventEmitter: EventEmitter

  public constructor(drpcMessageRepository: DrpcRepository, eventEmitter: EventEmitter) {
    this.drpcMessageRepository = drpcMessageRepository
    this.eventEmitter = eventEmitter
  }

  public async createRequestMessage(agentContext: AgentContext, request: DrpcRequest, connectionId: string) {
    const drpcMessage = new DrpcRequestMessage({ request })

    const drpcMessageRecord = new DrpcRecord({
      request,
      connectionId,
      state: DrpcState.RequestSent,
      threadId: drpcMessage.threadId,
      role: DrpcRole.Client,
    })

    await this.drpcMessageRepository.save(agentContext, drpcMessageRecord)
    this.emitStateChangedEvent(agentContext, drpcMessageRecord)

    return { requestMessage: drpcMessage, record: drpcMessageRecord }
  }

  public async createResponseMessage(agentContext: AgentContext, response: DrpcResponse, drpcRecord: DrpcRecord) {
    const drpcMessage = new DrpcResponseMessage({ response, threadId: drpcRecord.threadId })

    drpcRecord.assertState(DrpcState.RequestReceived)

    drpcRecord.response = response
    drpcRecord.request = undefined

    await this.updateState(agentContext, drpcRecord, DrpcState.Completed)

    return { responseMessage: drpcMessage, record: drpcRecord }
  }

  public createRequestListener(
    callback: (params: { drpcMessageRecord: DrpcRecord; removeListener: () => void }) => void | Promise<void>
  ) {
    const listener = async (event: DrpcRequestStateChangedEvent) => {
      const { drpcMessageRecord } = event.payload
      await callback({
        drpcMessageRecord,
        removeListener: () => this.eventEmitter.off(DrpcRequestEventTypes.DrpcRequestStateChanged, listener),
      })
    }
    this.eventEmitter.on(DrpcRequestEventTypes.DrpcRequestStateChanged, listener)

    return () => {
      this.eventEmitter.off(DrpcRequestEventTypes.DrpcRequestStateChanged, listener)
    }
  }

  public createResponseListener(
    callback: (params: { drpcMessageRecord: DrpcRecord; removeListener: () => void }) => void | Promise<void>
  ) {
    const listener = async (event: DrpcResponseStateChangedEvent) => {
      const { drpcMessageRecord } = event.payload
      await callback({
        drpcMessageRecord,
        removeListener: () => this.eventEmitter.off(DrpcResponseEventTypes.DrpcResponseStateChanged, listener),
      })
    }
    this.eventEmitter.on(DrpcResponseEventTypes.DrpcResponseStateChanged, listener)
    return () => {
      this.eventEmitter.off(DrpcResponseEventTypes.DrpcResponseStateChanged, listener)
    }
  }

  public async receiveResponse(messageContext: InboundMessageContext<DrpcResponseMessage>) {
    const connection = messageContext.assertReadyConnection()
    const drpcMessageRecord = await this.findByThreadAndConnectionId(
      messageContext.agentContext,
      connection.id,
      messageContext.message.threadId
    )

    if (!drpcMessageRecord) {
      throw new Error('DRPC message record not found')
    }

    drpcMessageRecord.assertRole(DrpcRole.Client)
    drpcMessageRecord.assertState(DrpcState.RequestSent)
    drpcMessageRecord.response = messageContext.message.response
    drpcMessageRecord.request = undefined

    await this.updateState(messageContext.agentContext, drpcMessageRecord, DrpcState.Completed)
    return drpcMessageRecord
  }

  public async receiveRequest(messageContext: InboundMessageContext<DrpcRequestMessage>) {
    const connection = messageContext.assertReadyConnection()
    const record = await this.findByThreadAndConnectionId(
      messageContext.agentContext,
      connection.id,
      messageContext.message.threadId
    )

    if (record) {
      throw new Error('DRPC message record already exists')
    }
    const drpcMessageRecord = new DrpcRecord({
      request: messageContext.message.request,
      connectionId: connection.id,
      role: DrpcRole.Server,
      state: DrpcState.RequestReceived,
      threadId: messageContext.message.id,
    })

    await this.drpcMessageRepository.save(messageContext.agentContext, drpcMessageRecord)
    this.emitStateChangedEvent(messageContext.agentContext, drpcMessageRecord)
    return drpcMessageRecord
  }

  private emitStateChangedEvent(agentContext: AgentContext, drpcMessageRecord: DrpcRecord) {
    if (
      drpcMessageRecord.request &&
      (isValidDrpcRequest(drpcMessageRecord.request) ||
        (Array.isArray(drpcMessageRecord.request) &&
          drpcMessageRecord.request.length > 0 &&
          isValidDrpcRequest(drpcMessageRecord.request[0])))
    ) {
      this.eventEmitter.emit<DrpcRequestStateChangedEvent>(agentContext, {
        type: DrpcRequestEventTypes.DrpcRequestStateChanged,
        payload: { drpcMessageRecord: drpcMessageRecord.clone() },
      })
    } else if (
      drpcMessageRecord.response &&
      (isValidDrpcResponse(drpcMessageRecord.response) ||
        (Array.isArray(drpcMessageRecord.response) &&
          drpcMessageRecord.response.length > 0 &&
          isValidDrpcResponse(drpcMessageRecord.response[0])))
    ) {
      this.eventEmitter.emit<DrpcResponseStateChangedEvent>(agentContext, {
        type: DrpcResponseEventTypes.DrpcResponseStateChanged,
        payload: { drpcMessageRecord: drpcMessageRecord.clone() },
      })
    }
  }

  private async updateState(agentContext: AgentContext, drpcRecord: DrpcRecord, newState: DrpcState) {
    drpcRecord.state = newState
    await this.drpcMessageRepository.update(agentContext, drpcRecord)

    this.emitStateChangedEvent(agentContext, drpcRecord)
  }

  public findByThreadAndConnectionId(
    agentContext: AgentContext,
    connectionId: string,
    threadId: string
  ): Promise<DrpcRecord | null> {
    return this.drpcMessageRepository.findSingleByQuery(agentContext, {
      connectionId,
      threadId,
    })
  }

  public async findAllByQuery(agentContext: AgentContext, query: Query<DrpcRecord>, queryOptions?: QueryOptions) {
    return this.drpcMessageRepository.findByQuery(agentContext, query, queryOptions)
  }

  public async getById(agentContext: AgentContext, drpcMessageRecordId: string) {
    return this.drpcMessageRepository.getById(agentContext, drpcMessageRecordId)
  }

  public async deleteById(agentContext: AgentContext, drpcMessageRecordId: string) {
    const drpcMessageRecord = await this.getById(agentContext, drpcMessageRecordId)
    return this.drpcMessageRepository.delete(agentContext, drpcMessageRecord)
  }
}
