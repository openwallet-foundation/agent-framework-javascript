import { Expose, Type } from 'class-transformer'
import { IsArray, IsInstance, IsOptional, IsString, ValidateNested } from 'class-validator'

import { AgentMessage } from '../../../../../AgentMessage'
import { Attachment } from '../../../../../decorators/attachment/Attachment'
import { IsValidMessageType, parseMessageType } from '../../../../../util/messageType'
import { CredentialFormatSpec } from '../../../models'

import { V2CredentialPreview } from './V2CredentialPreview'

export interface V2ProposeCredentialMessageOptions {
  id?: string
  formats: CredentialFormatSpec[]
  proposalAttachments: Attachment[]
  comment?: string
  goalCode?: string
  goal?: string
  credentialPreview?: V2CredentialPreview
  attachments?: Attachment[]
}

export class V2ProposeCredentialMessage extends AgentMessage {
  public constructor(options: V2ProposeCredentialMessageOptions) {
    super()
    if (options) {
      this.id = options.id ?? this.generateId()
      this.comment = options.comment
      this.goalCode = options.goalCode
      this.goal = options.goal
      this.credentialPreview = options.credentialPreview
      this.formats = options.formats
      this.proposalAttachments = options.proposalAttachments
      this.appendedAttachments = options.attachments
    }
  }

  @Type(() => CredentialFormatSpec)
  @ValidateNested({ each: true })
  @IsArray()
  @IsInstance(CredentialFormatSpec, { each: true })
  public formats!: CredentialFormatSpec[]

  @IsValidMessageType(V2ProposeCredentialMessage.type)
  public readonly type = V2ProposeCredentialMessage.type.messageTypeUri
  public static readonly type = parseMessageType('https://didcomm.org/issue-credential/2.0/propose-credential')

  @Expose({ name: 'credential_preview' })
  @Type(() => V2CredentialPreview)
  @ValidateNested()
  @IsOptional()
  @IsInstance(V2CredentialPreview)
  public credentialPreview?: V2CredentialPreview

  @Expose({ name: 'filters~attach' })
  @Type(() => Attachment)
  @IsArray()
  @ValidateNested({
    each: true,
  })
  @IsInstance(Attachment, { each: true })
  public proposalAttachments!: Attachment[]

  /**
   * Human readable information about this Credential Proposal,
   * so the proposal can be evaluated by human judgment.
   */
  @IsOptional()
  @IsString()
  public comment?: string

  @Expose({ name: 'goal_code' })
  @IsString()
  @IsOptional()
  public goalCode?: string

  @IsString()
  @IsOptional()
  public goal?: string

  public getProposalAttachmentById(id: string): Attachment | undefined {
    return this.proposalAttachments.find((attachment) => attachment.id === id)
  }
}
