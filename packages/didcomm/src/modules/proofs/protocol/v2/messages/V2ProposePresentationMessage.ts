import { Expose, Type } from 'class-transformer'
import { IsArray, IsInstance, IsOptional, IsString, ValidateNested } from 'class-validator'

import { utils } from '@credo-ts/core'
import { AgentMessage } from '../../../../../AgentMessage'
import { Attachment } from '../../../../../decorators/attachment/Attachment'
import { IsValidMessageType, parseMessageType } from '../../../../../util/messageType'
import { ProofFormatSpec } from '../../../models/ProofFormatSpec'

export interface V2ProposePresentationMessageOptions {
  id?: string
  comment?: string
  goalCode?: string
  goal?: string
  proposalAttachments: Attachment[]
  formats: ProofFormatSpec[]
}

export class V2ProposePresentationMessage extends AgentMessage {
  public constructor(options: V2ProposePresentationMessageOptions) {
    super()

    if (options) {
      this.formats = []
      this.proposalAttachments = []
      this.id = options.id ?? utils.uuid()
      this.comment = options.comment
      this.goalCode = options.goalCode
      this.goal = options.goal
      this.formats = options.formats
      this.proposalAttachments = options.proposalAttachments
    }
  }

  @IsValidMessageType(V2ProposePresentationMessage.type)
  public readonly type = V2ProposePresentationMessage.type.messageTypeUri
  public static readonly type = parseMessageType('https://didcomm.org/present-proof/2.0/propose-presentation')

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

  @Type(() => ProofFormatSpec)
  @IsArray()
  @ValidateNested({ each: true })
  @IsInstance(ProofFormatSpec, { each: true })
  public formats!: ProofFormatSpec[]

  @Expose({ name: 'proposals~attach' })
  @Type(() => Attachment)
  @IsArray()
  @ValidateNested({ each: true })
  @IsInstance(Attachment, { each: true })
  public proposalAttachments!: Attachment[]

  public getProposalAttachmentById(id: string): Attachment | undefined {
    return this.proposalAttachments.find((attachment) => attachment.id === id)
  }
}
