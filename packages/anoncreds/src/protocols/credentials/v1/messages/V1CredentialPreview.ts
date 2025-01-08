import type { CredentialPreviewOptions } from '@credo-ts/didcomm'

import { JsonTransformer } from '@credo-ts/core'
import {
  CredentialPreviewAttribute,
  IsValidMessageType,
  parseMessageType,
  replaceLegacyDidSovPrefix,
} from '@credo-ts/didcomm'
import { Expose, Transform, Type } from 'class-transformer'
import { ValidateNested, IsInstance } from 'class-validator'

/**
 * Credential preview inner message class.
 *
 * This is not a message but an inner object for other messages in this protocol. It is used construct a preview of the data for the credential.
 *
 * @see https://github.com/hyperledger/aries-rfcs/blob/master/features/0036-issue-credential/README.md#preview-credential
 */
export class V1CredentialPreview {
  public constructor(options: CredentialPreviewOptions) {
    if (options) {
      this.attributes = options.attributes.map((a) => new CredentialPreviewAttribute(a))
    }
  }

  @Expose({ name: '@type' })
  @IsValidMessageType(V1CredentialPreview.type)
  @Transform(({ value }) => replaceLegacyDidSovPrefix(value), {
    toClassOnly: true,
  })
  public readonly type = V1CredentialPreview.type.messageTypeUri
  public static readonly type = parseMessageType('https://didcomm.org/issue-credential/1.0/credential-preview')

  @Type(() => CredentialPreviewAttribute)
  @ValidateNested({ each: true })
  @IsInstance(CredentialPreviewAttribute, { each: true })
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

    return new V1CredentialPreview({
      attributes,
    })
  }
}
