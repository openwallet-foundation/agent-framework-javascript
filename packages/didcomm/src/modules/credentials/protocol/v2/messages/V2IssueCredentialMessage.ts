import { Expose, Type } from 'class-transformer'
import { IsArray, IsInstance, IsOptional, IsString, ValidateNested } from 'class-validator'

import { AgentMessage } from '../../../../../AgentMessage'
import { Attachment } from '../../../../../decorators/attachment/Attachment'
import { IsValidMessageType, parseMessageType } from '../../../../../util/messageType'
import { CredentialFormatSpec } from '../../../models'

export interface V2IssueCredentialMessageOptions {
  id?: string
  comment?: string
  goalCode?: string
  goal?: string
  formats: CredentialFormatSpec[]
  credentialAttachments: Attachment[]
}

export class V2IssueCredentialMessage extends AgentMessage {
  public constructor(options: V2IssueCredentialMessageOptions) {
    super()

    if (options) {
      this.id = options.id ?? this.generateId()
      this.comment = options.comment
      this.goalCode = options.goalCode
      this.goal = options.goal
      this.formats = options.formats
      this.credentialAttachments = options.credentialAttachments
    }
  }
  @Type(() => CredentialFormatSpec)
  @ValidateNested()
  @IsArray()
  @IsInstance(CredentialFormatSpec, { each: true })
  public formats!: CredentialFormatSpec[]

  @IsValidMessageType(V2IssueCredentialMessage.type)
  public readonly type = V2IssueCredentialMessage.type.messageTypeUri
  public static readonly type = parseMessageType('https://didcomm.org/issue-credential/2.0/issue-credential')

  @IsString()
  @IsOptional()
  public comment?: string

  @Expose({ name: 'credentials~attach' })
  @Type(() => Attachment)
  @IsArray()
  @ValidateNested({
    each: true,
  })
  @IsInstance(Attachment, { each: true })
  public credentialAttachments!: Attachment[]

  @Expose({ name: 'goal_code' })
  @IsString()
  @IsOptional()
  public goalCode?: string

  @IsString()
  @IsOptional()
  public goal?: string

  public getCredentialAttachmentById(id: string): Attachment | undefined {
    return this.credentialAttachments.find((attachment) => attachment.id === id)
  }
}
