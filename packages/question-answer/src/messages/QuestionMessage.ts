import { AgentMessage, IsValidMessageType, parseMessageType } from '@credo-ts/didcomm'
import { Expose, Type } from 'class-transformer'
import { IsBoolean, IsInstance, IsOptional, IsString, ValidateNested } from 'class-validator'

import { ValidResponse } from '../models'

export class QuestionMessage extends AgentMessage {
  /**
   * Create new QuestionMessage instance.
   * @param options
   */
  public constructor(options: {
    questionText: string
    questionDetail?: string
    validResponses: ValidResponse[]
    signatureRequired?: boolean
    id?: string
    nonce?: string
  }) {
    super()

    if (options) {
      this.id = options.id || this.generateId()
      this.nonce = options.nonce
      this.questionText = options.questionText
      this.questionDetail = options.questionDetail
      this.signatureRequired = options.signatureRequired
      this.validResponses = options.validResponses
    }
  }

  @IsValidMessageType(QuestionMessage.type)
  public readonly type = QuestionMessage.type.messageTypeUri
  public static readonly type = parseMessageType('https://didcomm.org/questionanswer/1.0/question')

  @IsOptional()
  @IsString()
  public nonce?: string

  @IsOptional()
  @IsBoolean()
  @Expose({ name: 'signature_required' })
  public signatureRequired?: boolean

  @Expose({ name: 'valid_responses' })
  @Type(() => ValidResponse)
  @ValidateNested({ each: true })
  @IsInstance(ValidResponse, { each: true })
  public validResponses!: ValidResponse[]

  @Expose({ name: 'question_text' })
  @IsString()
  public questionText!: string

  @IsOptional()
  @Expose({ name: 'question_detail' })
  @IsString()
  public questionDetail?: string
}
