import { KeyType } from '../../../../crypto'
import { Key } from '../../../../crypto/Key'
import { CredoError } from '../../../../error'

import { VerificationMethod } from './VerificationMethod'

export const VERIFICATION_METHOD_TYPE_ECDSA_SECP256K1_VERIFICATION_KEY_2019 = 'EcdsaSecp256k1VerificationKey2019'

type EcdsaSecp256k1VerificationKey2019 = VerificationMethod & {
  type: typeof VERIFICATION_METHOD_TYPE_ECDSA_SECP256K1_VERIFICATION_KEY_2019
}

/**
 * Get a EcdsaSecp256k1VerificationKey2019 verification method.
 */
export function getEcdsaSecp256k1VerificationKey2019({
  key,
  id,
  controller,
}: {
  id: string
  key: Key
  controller: string
}) {
  return new VerificationMethod({
    id,
    type: VERIFICATION_METHOD_TYPE_ECDSA_SECP256K1_VERIFICATION_KEY_2019,
    controller,
    publicKeyBase58: key.publicKeyBase58,
  })
}

/**
 * Check whether a verification method is a EcdsaSecp256k1VerificationKey2019 verification method.
 */
export function isEcdsaSecp256k1VerificationKey2019(
  verificationMethod: VerificationMethod
): verificationMethod is EcdsaSecp256k1VerificationKey2019 {
  return verificationMethod.type === VERIFICATION_METHOD_TYPE_ECDSA_SECP256K1_VERIFICATION_KEY_2019
}

/**
 * Get a key from a EcdsaSecp256k1VerificationKey2019 verification method.
 */
export function getKeyFromEcdsaSecp256k1VerificationKey2019(verificationMethod: EcdsaSecp256k1VerificationKey2019) {
  if (!verificationMethod.publicKeyBase58) {
    throw new CredoError('verification method is missing publicKeyBase58')
  }

  const key = Key.fromPublicKeyBase58(verificationMethod.publicKeyBase58, KeyType.K256)
  if (key.keyType !== KeyType.K256) {
    throw new CredoError(`Verification method publicKeyBase58 is for unexpected key type ${key.keyType}`)
  }

  return key
}
