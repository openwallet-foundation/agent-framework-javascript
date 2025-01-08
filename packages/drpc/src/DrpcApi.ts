import type { DrpcRequest, DrpcResponse, DrpcRequestMessage, DrpcResponseMessage } from './messages'
import type { DrpcRecord } from './repository/DrpcRecord'
import type { ConnectionRecord } from '@credo-ts/didcomm'

import { AgentContext, injectable } from '@credo-ts/core'
import { MessageHandlerRegistry, MessageSender, OutboundMessageContext, ConnectionService } from '@credo-ts/didcomm'

import { DrpcRequestHandler, DrpcResponseHandler } from './handlers'
import { DrpcRole } from './models'
import { DrpcService } from './services'

@injectable()
export class DrpcApi {
  private drpcMessageService: DrpcService
  private messageSender: MessageSender
  private connectionService: ConnectionService
  private agentContext: AgentContext

  public constructor(
    messageHandlerRegistry: MessageHandlerRegistry,
    drpcMessageService: DrpcService,
    messageSender: MessageSender,
    connectionService: ConnectionService,
    agentContext: AgentContext
  ) {
    this.drpcMessageService = drpcMessageService
    this.messageSender = messageSender
    this.connectionService = connectionService
    this.agentContext = agentContext
    this.registerMessageHandlers(messageHandlerRegistry)
  }

  /**
   * sends the request object to the connection and returns a function that will resolve to the response
   * @param connectionId the connection to send the request to
   * @param request the request object
   * @returns curried function that waits for the response with an optional timeout in seconds
   */
  public async sendRequest(
    connectionId: string,
    request: DrpcRequest
  ): Promise<() => Promise<DrpcResponse | undefined>> {
    const connection = await this.connectionService.getById(this.agentContext, connectionId)
    const { requestMessage: drpcMessage, record: drpcMessageRecord } =
      await this.drpcMessageService.createRequestMessage(this.agentContext, request, connection.id)
    const messageId = drpcMessage.id
    await this.sendMessage(connection, drpcMessage, drpcMessageRecord)
    return async (timeout?: number) => {
      return await this.recvResponse(messageId, timeout)
    }
  }

  /**
   * Listen for a response that has a thread id matching the provided messageId
   * @param messageId the id to match the response to
   * @param timeoutMs the time in milliseconds to wait for a response
   * @returns the response object
   */
  private async recvResponse(messageId: string, timeoutMs?: number): Promise<DrpcResponse | undefined> {
    return new Promise((resolve) => {
      const listener = ({
        drpcMessageRecord,
        removeListener,
      }: {
        drpcMessageRecord: DrpcRecord
        removeListener: () => void
      }) => {
        const response = drpcMessageRecord.response
        if (drpcMessageRecord.threadId === messageId) {
          removeListener()
          resolve(response)
        }
      }

      const cancelListener = this.drpcMessageService.createResponseListener(listener)
      if (timeoutMs) {
        const handle = setTimeout(() => {
          clearTimeout(handle)
          cancelListener()
          resolve(undefined)
        }, timeoutMs)
      }
    })
  }

  /**
   * Listen for a request and returns the request object and a function to send the response
   * @param timeoutMs the time in seconds to wait for a request
   * @returns the request object and a function to send the response
   */
  public async recvRequest(timeoutMs?: number): Promise<
    | {
        request: DrpcRequest
        sendResponse: (response: DrpcResponse) => Promise<void>
      }
    | undefined
  > {
    return new Promise((resolve) => {
      const listener = ({
        drpcMessageRecord,
        removeListener,
      }: {
        drpcMessageRecord: DrpcRecord
        removeListener: () => void
      }) => {
        const request = drpcMessageRecord.request
        if (request && drpcMessageRecord.role === DrpcRole.Server) {
          removeListener()
          resolve({
            sendResponse: async (response: DrpcResponse) => {
              await this.sendResponse({
                connectionId: drpcMessageRecord.connectionId,
                threadId: drpcMessageRecord.threadId,
                response,
              })
            },
            request,
          })
        }
      }

      const cancelListener = this.drpcMessageService.createRequestListener(listener)

      if (timeoutMs) {
        const handle = setTimeout(() => {
          clearTimeout(handle)
          cancelListener()
          resolve(undefined)
        }, timeoutMs)
      }
    })
  }

  /**
   * Sends a drpc response to a connection
   * @param connectionId the connection id to use
   * @param threadId the thread id to respond to
   * @param response the drpc response object to send
   */
  private async sendResponse(options: {
    connectionId: string
    threadId: string
    response: DrpcResponse
  }): Promise<void> {
    const connection = await this.connectionService.getById(this.agentContext, options.connectionId)
    const drpcMessageRecord = await this.drpcMessageService.findByThreadAndConnectionId(
      this.agentContext,
      options.connectionId,
      options.threadId
    )
    if (!drpcMessageRecord) {
      throw new Error(`No request found for threadId ${options.threadId}`)
    }
    const { responseMessage, record } = await this.drpcMessageService.createResponseMessage(
      this.agentContext,
      options.response,
      drpcMessageRecord
    )
    await this.sendMessage(connection, responseMessage, record)
  }

  private async sendMessage(
    connection: ConnectionRecord,
    message: DrpcRequestMessage | DrpcResponseMessage,
    messageRecord: DrpcRecord
  ): Promise<void> {
    const outboundMessageContext = new OutboundMessageContext(message, {
      agentContext: this.agentContext,
      connection,
      associatedRecord: messageRecord,
    })
    await this.messageSender.sendMessage(outboundMessageContext)
  }

  private registerMessageHandlers(messageHandlerRegistry: MessageHandlerRegistry) {
    messageHandlerRegistry.registerMessageHandler(new DrpcRequestHandler(this.drpcMessageService))
    messageHandlerRegistry.registerMessageHandler(new DrpcResponseHandler(this.drpcMessageService))
  }
}
