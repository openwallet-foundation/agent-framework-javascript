import type { AnonCredsProof } from '../../../../models'

import { Attachment, AgentMessage, IsValidMessageType, parseMessageType } from '@credo-ts/didcomm'
import { Expose, Type } from 'class-transformer'
import { IsArray, IsString, ValidateNested, IsOptional, IsInstance } from 'class-validator'

export const INDY_PROOF_ATTACHMENT_ID = 'libindy-presentation-0'

export interface V1PresentationMessageOptions {
  id?: string
  comment?: string
  presentationAttachments: Attachment[]
  attachments?: Attachment[]
}

/**
 * Presentation Message part of Present Proof Protocol used as a response to a {@link PresentationRequestMessage | Presentation Request Message} from prover to verifier.
 * Contains signed presentations.
 *
 * @see https://github.com/hyperledger/aries-rfcs/blob/master/features/0037-present-proof/README.md#presentation
 */
export class V1PresentationMessage extends AgentMessage {
  public readonly allowDidSovPrefix = true
  public constructor(options: V1PresentationMessageOptions) {
    super()

    if (options) {
      this.id = options.id ?? this.generateId()
      this.comment = options.comment
      this.presentationAttachments = options.presentationAttachments
      this.appendedAttachments = options.attachments
    }
  }

  @IsValidMessageType(V1PresentationMessage.type)
  public readonly type = V1PresentationMessage.type.messageTypeUri
  public static readonly type = parseMessageType('https://didcomm.org/present-proof/1.0/presentation')

  /**
   *  Provides some human readable information about this request for a presentation.
   */
  @IsOptional()
  @IsString()
  public comment?: string

  /**
   * An array of attachments containing the presentation in the requested format(s).
   */
  @Expose({ name: 'presentations~attach' })
  @Type(() => Attachment)
  @IsArray()
  @ValidateNested({
    each: true,
  })
  @IsInstance(Attachment, { each: true })
  public presentationAttachments!: Attachment[]

  public get indyProof(): AnonCredsProof | null {
    const attachment =
      this.presentationAttachments.find((attachment) => attachment.id === INDY_PROOF_ATTACHMENT_ID) ?? null

    const proofJson = attachment?.getDataAsJson<AnonCredsProof>() ?? null

    return proofJson
  }

  public getPresentationAttachmentById(id: string): Attachment | undefined {
    return this.presentationAttachments.find((attachment) => attachment.id === id)
  }
}
