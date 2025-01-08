import { Expose } from 'class-transformer'
import { Equals, IsString } from 'class-validator'

import { PublicKey } from './PublicKey'

export class Ed25119Sig2018 extends PublicKey {
  public constructor(options: { id: string; controller: string; publicKeyBase58: string }) {
    super({ ...options, type: 'Ed25519VerificationKey2018' })

    if (options) {
      this.value = options.publicKeyBase58
    }
  }

  @Equals('Ed25519VerificationKey2018')
  public type = 'Ed25519VerificationKey2018' as const

  @Expose({ name: 'publicKeyBase58' })
  @IsString()
  public value!: string
}
