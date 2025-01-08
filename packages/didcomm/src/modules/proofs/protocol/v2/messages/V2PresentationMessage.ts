import { Expose, Type } from 'class-transformer'
import { IsArray, IsBoolean, IsInstance, IsOptional, IsString, ValidateNested } from 'class-validator'

import { utils } from '@credo-ts/core'
import { AgentMessage } from '../../../../../AgentMessage'
import { Attachment } from '../../../../../decorators/attachment/Attachment'
import { IsValidMessageType, parseMessageType } from '../../../../../util/messageType'
import { ProofFormatSpec } from '../../../models/ProofFormatSpec'

export interface V2PresentationMessageOptions {
  id?: string
  comment?: string
  goalCode?: string
  goal?: string
  lastPresentation?: boolean
  presentationAttachments: Attachment[]
  formats: ProofFormatSpec[]
}

export class V2PresentationMessage extends AgentMessage {
  public constructor(options: V2PresentationMessageOptions) {
    super()

    if (options) {
      this.formats = []
      this.presentationAttachments = []
      this.id = options.id ?? utils.uuid()
      this.comment = options.comment
      this.goalCode = options.goalCode
      this.goal = options.goal
      this.lastPresentation = options.lastPresentation ?? true

      this.formats = options.formats
      this.presentationAttachments = options.presentationAttachments
    }
  }

  @IsValidMessageType(V2PresentationMessage.type)
  public readonly type = V2PresentationMessage.type.messageTypeUri
  public static readonly type = parseMessageType('https://didcomm.org/present-proof/2.0/presentation')

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

  @Expose({ name: 'last_presentation' })
  @IsBoolean()
  public lastPresentation = true

  @Expose({ name: 'formats' })
  @Type(() => ProofFormatSpec)
  @IsArray()
  @ValidateNested({ each: true })
  @IsInstance(ProofFormatSpec, { each: true })
  public formats!: ProofFormatSpec[]

  @Expose({ name: 'presentations~attach' })
  @Type(() => Attachment)
  @IsArray()
  @ValidateNested({ each: true })
  @IsInstance(Attachment, { each: true })
  public presentationAttachments!: Attachment[]

  public getPresentationAttachmentById(id: string): Attachment | undefined {
    return this.presentationAttachments.find((attachment) => attachment.id === id)
  }
}
