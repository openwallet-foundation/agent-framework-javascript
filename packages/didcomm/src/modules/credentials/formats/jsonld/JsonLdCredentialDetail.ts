import { Expose, Type } from 'class-transformer'

import { W3cCredential } from '@credo-ts/core'

import { JsonLdCredentialDetailOptions } from './JsonLdCredentialDetailOptions'

export interface JsonLdCredentialDetailInputOptions {
  credential: W3cCredential
  options: JsonLdCredentialDetailOptions
}

/**
 * Class providing validation for the V2 json ld credential as per RFC0593 (used to sign credentials)
 *
 */
export class JsonLdCredentialDetail {
  public constructor(options: JsonLdCredentialDetailInputOptions) {
    if (options) {
      this.credential = options.credential
      this.options = options.options
    }
  }

  @Type(() => W3cCredential)
  public credential!: W3cCredential

  @Expose({ name: 'options' })
  @Type(() => JsonLdCredentialDetailOptions)
  public options!: JsonLdCredentialDetailOptions
}
