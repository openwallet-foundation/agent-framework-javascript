import type { LegacyIndyCredentialRequest } from '../../../../formats'

import { Attachment, AgentMessage, IsValidMessageType, parseMessageType } from '@credo-ts/didcomm'
import { Expose, Type } from 'class-transformer'
import { IsArray, IsInstance, IsOptional, IsString, ValidateNested } from 'class-validator'

export const INDY_CREDENTIAL_REQUEST_ATTACHMENT_ID = 'libindy-cred-request-0'

export interface V1RequestCredentialMessageOptions {
  id?: string
  comment?: string
  requestAttachments: Attachment[]
  attachments?: Attachment[]
}

export class V1RequestCredentialMessage extends AgentMessage {
  public readonly allowDidSovPrefix = true

  public constructor(options: V1RequestCredentialMessageOptions) {
    super()

    if (options) {
      this.id = options.id || this.generateId()
      this.comment = options.comment
      this.requestAttachments = options.requestAttachments
      this.appendedAttachments = options.attachments
    }
  }

  @IsValidMessageType(V1RequestCredentialMessage.type)
  public readonly type = V1RequestCredentialMessage.type.messageTypeUri
  public static readonly type = parseMessageType('https://didcomm.org/issue-credential/1.0/request-credential')

  @IsString()
  @IsOptional()
  public comment?: string

  @Expose({ name: 'requests~attach' })
  @Type(() => Attachment)
  @IsArray()
  @ValidateNested({
    each: true,
  })
  @IsInstance(Attachment, { each: true })
  public requestAttachments!: Attachment[]

  public get indyCredentialRequest(): LegacyIndyCredentialRequest | null {
    const attachment = this.requestAttachments.find(
      (attachment) => attachment.id === INDY_CREDENTIAL_REQUEST_ATTACHMENT_ID
    )
    // Extract proof request from attachment
    const credentialReqJson = attachment?.getDataAsJson<LegacyIndyCredentialRequest>() ?? null

    return credentialReqJson
  }

  public getRequestAttachmentById(id: string): Attachment | undefined {
    return this.requestAttachments.find((attachment) => attachment.id === id)
  }
}
