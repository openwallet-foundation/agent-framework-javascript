import type { ClassConstructor } from 'class-transformer'

import { Transform, plainToInstance } from 'class-transformer'

import { Ed25119Sig2018 } from './Ed25119Sig2018'
import { EddsaSaSigSecp256k1 } from './EddsaSaSigSecp256k1'
import { PublicKey } from './PublicKey'
import { RsaSig2018 } from './RsaSig2018'

export const publicKeyTypes: { [key: string]: unknown | undefined } = {
  RsaVerificationKey2018: RsaSig2018,
  Ed25519VerificationKey2018: Ed25119Sig2018,
  Secp256k1VerificationKey2018: EddsaSaSigSecp256k1,
}

/**
 * Decorator that transforms public key json to corresonding class instances. See {@link publicKeyTypes}
 *
 * @example
 * class Example {
 *   ＠PublicKeyTransformer()
 *   private publicKey: PublicKey
 * }
 */
export function PublicKeyTransformer() {
  return Transform(
    ({ value }: { value: { type: string }[] }) => {
      return value.map((publicKeyJson) => {
        const publicKeyClass = (publicKeyTypes[publicKeyJson.type] ?? PublicKey) as ClassConstructor<PublicKey>
        const publicKey = plainToInstance<PublicKey, unknown>(publicKeyClass, publicKeyJson)

        return publicKey
      })
    },
    {
      toClassOnly: true,
    }
  )
}

export { Ed25119Sig2018, PublicKey, EddsaSaSigSecp256k1, RsaSig2018 }
