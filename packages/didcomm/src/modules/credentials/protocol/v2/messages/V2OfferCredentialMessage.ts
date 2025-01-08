import { Expose, Type } from 'class-transformer'
import { IsArray, IsInstance, IsOptional, IsString, ValidateNested } from 'class-validator'

import { AgentMessage } from '../../../../../AgentMessage'
import { Attachment } from '../../../../../decorators/attachment/Attachment'
import { IsValidMessageType, parseMessageType } from '../../../../../util/messageType'
import { CredentialFormatSpec } from '../../../models'

import { V2CredentialPreview } from './V2CredentialPreview'

export interface V2OfferCredentialMessageOptions {
  id?: string
  formats: CredentialFormatSpec[]
  offerAttachments: Attachment[]
  credentialPreview: V2CredentialPreview
  replacementId?: string
  comment?: string
  goalCode?: string
  goal?: string
}

export class V2OfferCredentialMessage extends AgentMessage {
  public constructor(options: V2OfferCredentialMessageOptions) {
    super()
    if (options) {
      this.id = options.id ?? this.generateId()
      this.comment = options.comment
      this.goalCode = options.goalCode
      this.goal = options.goal
      this.formats = options.formats
      this.credentialPreview = options.credentialPreview
      this.offerAttachments = options.offerAttachments
    }
  }

  @Type(() => CredentialFormatSpec)
  @ValidateNested()
  @IsArray()
  @IsInstance(CredentialFormatSpec, { each: true })
  public formats!: CredentialFormatSpec[]

  @IsValidMessageType(V2OfferCredentialMessage.type)
  public readonly type = V2OfferCredentialMessage.type.messageTypeUri
  public static readonly type = parseMessageType('https://didcomm.org/issue-credential/2.0/offer-credential')

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

  @IsOptional()
  @Expose({ name: 'credential_preview' })
  @Type(() => V2CredentialPreview)
  @ValidateNested()
  @IsInstance(V2CredentialPreview)
  public credentialPreview?: V2CredentialPreview

  @Expose({ name: 'offers~attach' })
  @Type(() => Attachment)
  @IsArray()
  @ValidateNested({
    each: true,
  })
  @IsInstance(Attachment, { each: true })
  public offerAttachments!: Attachment[]

  @Expose({ name: 'replacement_id' })
  @IsString()
  @IsOptional()
  public replacementId?: string

  public getOfferAttachmentById(id: string): Attachment | undefined {
    return this.offerAttachments.find((attachment) => attachment.id === id)
  }
}
