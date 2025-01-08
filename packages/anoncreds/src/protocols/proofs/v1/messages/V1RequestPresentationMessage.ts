import type { LegacyIndyProofRequest } from '../../../../formats'

import { Attachment, AgentMessage, IsValidMessageType, parseMessageType } from '@credo-ts/didcomm'
import { Expose, Type } from 'class-transformer'
import { IsArray, IsString, ValidateNested, IsOptional, IsInstance } from 'class-validator'

export interface V1RequestPresentationMessageOptions {
  id?: string
  comment?: string
  requestAttachments: Attachment[]
}

export const INDY_PROOF_REQUEST_ATTACHMENT_ID = 'libindy-request-presentation-0'

/**
 * Request Presentation Message part of Present Proof Protocol used to initiate request from verifier to prover.
 *
 * @see https://github.com/hyperledger/aries-rfcs/blob/master/features/0037-present-proof/README.md#request-presentation
 */
export class V1RequestPresentationMessage extends AgentMessage {
  public readonly allowDidSovPrefix = true

  public constructor(options: V1RequestPresentationMessageOptions) {
    super()

    if (options) {
      this.id = options.id ?? this.generateId()
      this.comment = options.comment
      this.requestAttachments = options.requestAttachments
    }
  }

  @IsValidMessageType(V1RequestPresentationMessage.type)
  public readonly type = V1RequestPresentationMessage.type.messageTypeUri
  public static readonly type = parseMessageType('https://didcomm.org/present-proof/1.0/request-presentation')

  /**
   *  Provides some human readable information about this request for a presentation.
   */
  @IsOptional()
  @IsString()
  public comment?: string

  /**
   * An array of attachments defining the acceptable formats for the presentation.
   */
  @Expose({ name: 'request_presentations~attach' })
  @Type(() => Attachment)
  @IsArray()
  @ValidateNested({
    each: true,
  })
  @IsInstance(Attachment, { each: true })
  public requestAttachments!: Attachment[]

  public get indyProofRequest(): LegacyIndyProofRequest | null {
    const attachment = this.requestAttachments.find((attachment) => attachment.id === INDY_PROOF_REQUEST_ATTACHMENT_ID)
    // Extract proof request from attachment
    return attachment?.getDataAsJson<LegacyIndyProofRequest>() ?? null
  }

  public getRequestAttachmentById(id: string): Attachment | undefined {
    return this.requestAttachments.find((attachment) => attachment.id === id)
  }
}
