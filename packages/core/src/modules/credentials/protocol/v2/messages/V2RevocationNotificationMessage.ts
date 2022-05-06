import type { AckDecorator } from '../../../../../decorators/ack/AckDecorator'

import { Expose } from 'class-transformer'
import { Equals, IsOptional, IsString } from 'class-validator'

import { AgentMessage } from '../../../../../agent/AgentMessage'

export interface RevocationNotificationMessageV2Options {
  revocationFormat: string
  credentialId: string
  id?: string
  comment?: string
  pleaseAck?: AckDecorator
}

export class V2RevocationNotificationMessage extends AgentMessage {
  public constructor(options: RevocationNotificationMessageV2Options) {
    super()
    if (options) {
      this.revocationFormat = options.revocationFormat
      this.credentialId = options.credentialId
      this.id = options.id ?? this.generateId()
      this.comment = options.comment
      this.pleaseAck = options.pleaseAck
    }
  }

  @Equals(V2RevocationNotificationMessage.type)
  public readonly type = V2RevocationNotificationMessage.type
  public static readonly type = 'https://didcomm.org/revocation_notification/2.0/revoke'

  @IsString()
  @IsOptional()
  public comment?: string

  @Expose({ name: 'revocation_format' })
  @IsString()
  public revocationFormat!: string

  @Expose({ name: 'credential_id' })
  @IsString()
  public credentialId!: string
}
