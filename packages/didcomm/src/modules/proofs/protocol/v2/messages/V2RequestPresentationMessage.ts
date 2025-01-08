import { Expose, Type } from 'class-transformer'
import { IsArray, IsBoolean, IsInstance, IsOptional, IsString, ValidateNested } from 'class-validator'

import { utils } from '@credo-ts/core'
import { AgentMessage } from '../../../../../AgentMessage'
import { Attachment } from '../../../../../decorators/attachment/Attachment'
import { IsValidMessageType, parseMessageType } from '../../../../../util/messageType'
import { ProofFormatSpec } from '../../../models/ProofFormatSpec'

export interface V2RequestPresentationMessageOptions {
  id?: string
  comment?: string
  goalCode?: string
  goal?: string
  presentMultiple?: boolean
  willConfirm?: boolean
  formats: ProofFormatSpec[]
  requestAttachments: Attachment[]
}

export class V2RequestPresentationMessage extends AgentMessage {
  public constructor(options: V2RequestPresentationMessageOptions) {
    super()

    if (options) {
      this.formats = []
      this.requestAttachments = []
      this.id = options.id ?? utils.uuid()
      this.comment = options.comment
      this.goal = options.goal
      this.goalCode = options.goalCode
      this.willConfirm = options.willConfirm ?? true
      this.presentMultiple = options.presentMultiple ?? false
      this.requestAttachments = options.requestAttachments
      this.formats = options.formats
    }
  }

  @IsValidMessageType(V2RequestPresentationMessage.type)
  public readonly type = V2RequestPresentationMessage.type.messageTypeUri
  public static readonly type = parseMessageType('https://didcomm.org/present-proof/2.0/request-presentation')

  @IsString()
  @IsOptional()
  public comment?: string

  @Expose({ name: 'goal_code' })
  @IsString()
  @IsOptional()
  public goalCode?: string

  @IsString()
  @IsOptional()
  public goal?: string

  @Expose({ name: 'will_confirm' })
  @IsBoolean()
  public willConfirm = false

  @Expose({ name: 'present_multiple' })
  @IsBoolean()
  public presentMultiple = false

  @Expose({ name: 'formats' })
  @Type(() => ProofFormatSpec)
  @IsArray()
  @ValidateNested({ each: true })
  @IsInstance(ProofFormatSpec, { each: true })
  public formats!: ProofFormatSpec[]

  @Expose({ name: 'request_presentations~attach' })
  @Type(() => Attachment)
  @IsArray()
  @ValidateNested({ each: true })
  @IsInstance(Attachment, { each: true })
  public requestAttachments!: Attachment[]

  public getRequestAttachmentById(id: string): Attachment | undefined {
    return this.requestAttachments.find((attachment) => attachment.id === id)
  }
}
