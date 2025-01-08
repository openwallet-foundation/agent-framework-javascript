import { Expose, Type } from 'class-transformer'
import { IsArray, IsInstance, IsOptional, IsString, ValidateNested } from 'class-validator'

import { AgentMessage } from '../../../../../AgentMessage'
import { Attachment } from '../../../../../decorators/attachment/Attachment'
import { IsValidMessageType, parseMessageType } from '../../../../../util/messageType'
import { CredentialFormatSpec } from '../../../models'

export interface V2RequestCredentialMessageOptions {
  id?: string
  formats: CredentialFormatSpec[]
  goalCode?: string
  goal?: string
  requestAttachments: Attachment[]
  comment?: string
  attachments?: Attachment[]
}

export class V2RequestCredentialMessage extends AgentMessage {
  public constructor(options: V2RequestCredentialMessageOptions) {
    super()
    if (options) {
      this.id = options.id ?? this.generateId()
      this.comment = options.comment
      this.goalCode = options.goalCode
      this.goal = options.goal
      this.formats = options.formats
      this.requestAttachments = options.requestAttachments
      this.appendedAttachments = options.attachments
    }
  }

  @Type(() => CredentialFormatSpec)
  @ValidateNested()
  @IsArray()
  @IsInstance(CredentialFormatSpec, { each: true })
  public formats!: CredentialFormatSpec[]

  @IsValidMessageType(V2RequestCredentialMessage.type)
  public readonly type = V2RequestCredentialMessage.type.messageTypeUri
  public static readonly type = parseMessageType('https://didcomm.org/issue-credential/2.0/request-credential')

  @Expose({ name: 'requests~attach' })
  @Type(() => Attachment)
  @IsArray()
  @ValidateNested({
    each: true,
  })
  @IsInstance(Attachment, { each: true })
  public requestAttachments!: Attachment[]

  /**
   * Human readable information about this Credential Request,
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

  public getRequestAttachmentById(id: string): Attachment | undefined {
    return this.requestAttachments.find((attachment) => attachment.id === id)
  }
}
