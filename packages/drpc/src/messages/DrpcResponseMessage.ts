import type { DrpcErrorCode } from '../models'

import { IsValidMessageType, parseMessageType, AgentMessage } from '@credo-ts/didcomm'
import { Expose } from 'class-transformer'

import { IsValidDrpcResponse } from '../models'

export type DrpcResponse = DrpcResponseObject | (DrpcResponseObject | Record<string, never>)[] | Record<string, never>

export interface DrpcResponseError {
  code: DrpcErrorCode
  message: string
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  data?: any
}

export interface DrpcResponseObject {
  jsonrpc: string
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  result?: any
  error?: DrpcResponseError
  id: string | number | null
}

export class DrpcResponseMessage extends AgentMessage {
  public constructor(options: { response: DrpcResponse; threadId: string }) {
    super()
    if (options) {
      this.id = this.generateId()
      this.response = options.response
      this.setThread({ threadId: options.threadId })
    }
  }

  @IsValidMessageType(DrpcResponseMessage.type)
  public readonly type = DrpcResponseMessage.type.messageTypeUri
  public static readonly type = parseMessageType('https://didcomm.org/drpc/1.0/response')

  @Expose({ name: 'response' })
  @IsValidDrpcResponse()
  public response!: DrpcResponse
}
