import { Expose } from 'class-transformer'
import { Equals, IsString } from 'class-validator'

import { PublicKey } from './PublicKey'

export class RsaSig2018 extends PublicKey {
  public constructor(options: { id: string; controller: string; publicKeyPem: string }) {
    super({ ...options, type: 'RsaVerificationKey2018' })

    if (options) {
      this.value = options.publicKeyPem
    }
  }

  @Equals('RsaVerificationKey2018')
  public type = 'RsaVerificationKey2018' as const

  @Expose({ name: 'publicKeyPem' })
  @IsString()
  public value!: string
}
