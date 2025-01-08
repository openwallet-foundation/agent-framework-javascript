import { AgentMessage, IsValidMessageType, parseMessageType } from '@credo-ts/didcomm'
import { Expose, Type } from 'class-transformer'
import { IsInstance, IsOptional, IsString, ValidateNested } from 'class-validator'

import { V1PresentationPreview } from '../models/V1PresentationPreview'

export interface V1ProposePresentationMessageOptions {
  id?: string
  comment?: string
  presentationProposal: V1PresentationPreview
}

/**
 * Propose Presentation Message part of Present Proof Protocol used to initiate presentation exchange by holder.
 *
 * @see https://github.com/hyperledger/aries-rfcs/blob/master/features/0037-present-proof/README.md#propose-presentation
 */
export class V1ProposePresentationMessage extends AgentMessage {
  public readonly allowDidSovPrefix = true
  public constructor(options: V1ProposePresentationMessageOptions) {
    super()

    if (options) {
      this.id = options.id ?? this.generateId()
      this.comment = options.comment
      this.presentationProposal = options.presentationProposal
    }
  }

  @IsValidMessageType(V1ProposePresentationMessage.type)
  public readonly type = V1ProposePresentationMessage.type.messageTypeUri
  public static readonly type = parseMessageType('https://didcomm.org/present-proof/1.0/propose-presentation')

  /**
   * Provides some human readable information about the proposed presentation.
   */
  @IsString()
  @IsOptional()
  public comment?: string

  /**
   * Represents the presentation example that prover wants to provide.
   */
  @Expose({ name: 'presentation_proposal' })
  @Type(() => V1PresentationPreview)
  @ValidateNested()
  @IsInstance(V1PresentationPreview)
  public presentationProposal!: V1PresentationPreview
}
