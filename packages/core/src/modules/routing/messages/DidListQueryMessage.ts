import type { DIDCommV2MessageParams } from '../../../agent/didcomm'

import { Type } from 'class-transformer'
import { IsNotEmpty, IsObject, IsString, ValidateNested } from 'class-validator'

import { DIDCommV2Message } from '../../../agent/didcomm'
import { IsValidMessageType, parseMessageType } from '../../../utils/messageType'
import { PaginationQuery } from '../../common/pagination'

export class DidListQuery {
  @IsObject()
  @ValidateNested()
  @Type(() => PaginationQuery)
  public paginate!: PaginationQuery
}

export type DidListQueryMessageOptions = {
  body: DidListQuery
} & DIDCommV2MessageParams

export class DidListQueryMessage extends DIDCommV2Message {
  public constructor(options: DidListQueryMessageOptions) {
    super()

    if (options) {
      this.body = options.body
    }
  }

  @IsString()
  @IsNotEmpty()
  public from!: string

  @IsObject()
  @ValidateNested()
  @Type(() => DidListQuery)
  public body!: DidListQuery

  @IsValidMessageType(DidListQueryMessage.type)
  public readonly type = DidListQueryMessage.type.messageTypeUri
  public static readonly type = parseMessageType('https://didcomm.org/coordinate-mediation/2.0/keylist-query')
}
