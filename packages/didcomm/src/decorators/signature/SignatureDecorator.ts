import { Expose, Transform } from 'class-transformer'
import { IsString, Matches } from 'class-validator'

import { MessageTypeRegExp } from '../../BaseMessage'
import { replaceLegacyDidSovPrefix } from '../../util/messageType'

/**
 * Represents `[field]~sig` decorator
 * @see https://github.com/hyperledger/aries-rfcs/blob/master/features/0234-signature-decorator/README.md
 */
export class SignatureDecorator {
  public constructor(options: SignatureDecorator) {
    if (options) {
      this.signatureType = options.signatureType
      this.signatureData = options.signatureData
      this.signer = options.signer
      this.signature = options.signature
    }
  }

  @Expose({ name: '@type' })
  @Transform(({ value }) => replaceLegacyDidSovPrefix(value), {
    toClassOnly: true,
  })
  @Matches(MessageTypeRegExp)
  public signatureType!: string

  @Expose({ name: 'sig_data' })
  @IsString()
  public signatureData!: string

  @Expose({ name: 'signer' })
  @IsString()
  public signer!: string

  @Expose({ name: 'signature' })
  @IsString()
  public signature!: string
}
