import { Expose } from 'class-transformer'
import { IsString } from 'class-validator'

import { utils } from '@credo-ts/core'

export interface ProofFormatSpecOptions {
  attachmentId?: string
  format: string
}

export class ProofFormatSpec {
  public constructor(options: ProofFormatSpecOptions) {
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
