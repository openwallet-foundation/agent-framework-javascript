import { Expose } from 'class-transformer'
import { Equals, IsString } from 'class-validator'

import { PublicKey } from './PublicKey'

export class EddsaSaSigSecp256k1 extends PublicKey {
  public constructor(options: { id: string; controller: string; publicKeyHex: string }) {
    super({ ...options, type: 'Secp256k1VerificationKey2018' })

    if (options) {
      this.value = options.publicKeyHex
    }
  }

  @Equals('Secp256k1VerificationKey2018')
  public type = 'Secp256k1VerificationKey2018' as const

  @Expose({ name: 'publicKeyHex' })
  @IsString()
  public value!: string
}
