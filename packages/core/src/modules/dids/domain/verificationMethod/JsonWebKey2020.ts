import type { VerificationMethod } from './VerificationMethod'
import type { Key } from '../../../../crypto/Key'
import type { JwkJson } from '../../../../crypto/jose/jwk/Jwk'

import { getJwkFromJson, getJwkFromKey } from '../../../../crypto/jose/jwk'
import { CredoError } from '../../../../error'

export const VERIFICATION_METHOD_TYPE_JSON_WEB_KEY_2020 = 'JsonWebKey2020'

type JwkOrKey = { jwk: JwkJson; key?: never } | { key: Key; jwk?: never }
type GetJsonWebKey2020Options = {
  did: string

  verificationMethodId?: string
} & JwkOrKey

/**
 * Get a JsonWebKey2020 verification method.
 */
export function getJsonWebKey2020(options: GetJsonWebKey2020Options) {
  const jwk = options.jwk ? getJwkFromJson(options.jwk) : getJwkFromKey(options.key)
  const verificationMethodId = options.verificationMethodId ?? `${options.did}#${jwk.key.fingerprint}`

  return {
    id: verificationMethodId,
    type: VERIFICATION_METHOD_TYPE_JSON_WEB_KEY_2020,
    controller: options.did,
    publicKeyJwk: options.jwk ?? jwk.toJson(),
  }
}

/**
 * Check whether a verification method is a JsonWebKey2020 verification method.
 */
export function isJsonWebKey2020(
  verificationMethod: VerificationMethod
): verificationMethod is VerificationMethod & { type: 'JsonWebKey2020' } {
  return verificationMethod.type === VERIFICATION_METHOD_TYPE_JSON_WEB_KEY_2020
}

/**
 * Get a key from a JsonWebKey2020 verification method.
 */
export function getKeyFromJsonWebKey2020(verificationMethod: VerificationMethod & { type: 'JsonWebKey2020' }) {
  if (!verificationMethod.publicKeyJwk) {
    throw new CredoError(
      `Missing publicKeyJwk on verification method with type ${VERIFICATION_METHOD_TYPE_JSON_WEB_KEY_2020}`
    )
  }

  return getJwkFromJson(verificationMethod.publicKeyJwk).key
}
