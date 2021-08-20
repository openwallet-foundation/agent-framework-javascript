import { Expose, Type } from 'class-transformer'
import { Equals, ValidateNested } from 'class-validator'

import { JsonTransformer } from '../../../utils/JsonTransformer'

export interface CredentialPreviewOptions {
  attributes: CredentialPreviewAttribute[]
}

/**
 * Credential preview inner message class.
 *
 * This is not a message but an inner object for other messages in this protocol. It is used construct a preview of the data for the credential.
 *
 * @see https://github.com/hyperledger/aries-rfcs/blob/master/features/0036-issue-credential/README.md#preview-credential
 */
export class CredentialPreview {
  public constructor(options: CredentialPreviewOptions) {
    if (options) {
      this.attributes = options.attributes
    }
  }

  @Expose({ name: '@type' })
  @Equals(CredentialPreview.type)
  public readonly type = CredentialPreview.type
  public static readonly type = 'https://didcomm.org/issue-credential/1.0/credential-preview'

  @Type(() => CredentialPreviewAttribute)
  @ValidateNested({ each: true })
  public attributes!: CredentialPreviewAttribute[]

  public toJSON(): Record<string, unknown> {
    return JsonTransformer.toJSON(this)
  }

  /**
   * Create a credential preview from a record with name and value entries.
   *
   * @example
   * const preview = CredentialPreview.fromRecord({
   *   name: "Bob",
   *   age: "20"
   * })
   */
  public static fromRecord(record: Record<string, string>) {
    const attributes = Object.entries(record).map(
      ([name, value]) =>
        new CredentialPreviewAttribute({
          name,
          mimeType: 'text/plain',
          value,
        })
    )

    return new CredentialPreview({
      attributes,
    })
  }
}

interface CredentialPreviewAttributeOptions {
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

  public name!: string

  @Expose({ name: 'mime-type' })
  public mimeType?: string = 'text/plain'

  public value!: string

  public toJSON(): Record<string, unknown> {
    return JsonTransformer.toJSON(this)
  }
}
