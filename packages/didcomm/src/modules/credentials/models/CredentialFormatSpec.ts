import { Expose } from 'class-transformer'
import { IsString } from 'class-validator'

import { utils } from '@credo-ts/core'

export interface CredentialFormatSpecOptions {
  attachmentId?: string
  format: string
}

export class CredentialFormatSpec {
  public constructor(options: CredentialFormatSpecOptions) {
    if (options) {
      this.attachmentId = options.attachmentId ?? utils.uuid()
      this.format = options.format
    }
  }

  @Expose({ name: 'attach_id' })
  @IsString()
  public attachmentId!: string

  @IsString()
  public format!: string
}
