import type { AnonCredsCredentialOffer } from '../../../../models'

import { Attachment, AgentMessage, IsValidMessageType, parseMessageType } from '@credo-ts/didcomm'
import { Expose, Type } from 'class-transformer'
import { IsString, IsOptional, ValidateNested, IsInstance, IsArray } from 'class-validator'

import { V1CredentialPreview } from './V1CredentialPreview'

export const INDY_CREDENTIAL_OFFER_ATTACHMENT_ID = 'libindy-cred-offer-0'

export interface V1OfferCredentialMessageOptions {
  id?: string
  comment?: string
  offerAttachments: Attachment[]
  credentialPreview: V1CredentialPreview
  attachments?: Attachment[]
}

/**
 * Message part of Issue Credential Protocol used to continue or initiate credential exchange by issuer.
 *
 * @see https://github.com/hyperledger/aries-rfcs/blob/master/features/0036-issue-credential/README.md#offer-credential
 */
export class V1OfferCredentialMessage extends AgentMessage {
  public readonly allowDidSovPrefix = true

  public constructor(options: V1OfferCredentialMessageOptions) {
    super()

    if (options) {
      this.id = options.id || this.generateId()
      this.comment = options.comment
      this.credentialPreview = options.credentialPreview
      this.offerAttachments = options.offerAttachments
      this.appendedAttachments = options.attachments
    }
  }

  @IsValidMessageType(V1OfferCredentialMessage.type)
  public readonly type = V1OfferCredentialMessage.type.messageTypeUri
  public static readonly type = parseMessageType('https://didcomm.org/issue-credential/1.0/offer-credential')

  @IsString()
  @IsOptional()
  public comment?: string

  @Expose({ name: 'credential_preview' })
  @Type(() => V1CredentialPreview)
  @ValidateNested()
  @IsInstance(V1CredentialPreview)
  public credentialPreview!: V1CredentialPreview

  @Expose({ name: 'offers~attach' })
  @Type(() => Attachment)
  @IsArray()
  @ValidateNested({
    each: true,
  })
  @IsInstance(Attachment, { each: true })
  public offerAttachments!: Attachment[]

  public get indyCredentialOffer(): AnonCredsCredentialOffer | null {
    const attachment = this.offerAttachments.find((attachment) => attachment.id === INDY_CREDENTIAL_OFFER_ATTACHMENT_ID)

    // Extract credential offer from attachment
    const credentialOfferJson = attachment?.getDataAsJson<AnonCredsCredentialOffer>() ?? null

    return credentialOfferJson
  }

  public getOfferAttachmentById(id: string): Attachment | undefined {
    return this.offerAttachments.find((attachment) => attachment.id === id)
  }
}
