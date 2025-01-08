import { Expose } from 'class-transformer'
import { IsMimeType, IsOptional, IsString } from 'class-validator'

import { JsonTransformer } from '@credo-ts/core'

export interface CredentialPreviewAttributeOptions {
  name: string
  mimeType?: string
  value: string
}

export class CredentialPreviewAttribute {
  public constructor(options: CredentialPreviewAttributeOptions) {
    if (options) {
      this.name = options.name
      this.mimeType = options.mimeType
      this.value = options.value
    }
  }

  @IsString()
  public name!: string

  @Expose({ name: 'mime-type' })
  @IsOptional()
  @IsMimeType()
  public mimeType?: string = 'text/plain'

  @IsString()
  public value!: string

  public toJSON(): Record<string, unknown> {
    return JsonTransformer.toJSON(this)
  }
}

export interface CredentialPreviewOptions {
  attributes: CredentialPreviewAttributeOptions[]
}
