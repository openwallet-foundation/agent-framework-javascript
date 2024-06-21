import type { DidDocument, VerificationMethod } from '../../dids'

import { Key, KeyType } from '../../../crypto'
import { getKeyFromVerificationMethod } from '../../dids'
import { convertPublicKeyToX25519 } from '../../dids/domain/key-type/ed25519'

/**
 * Tries to find a matching Ed25519 key to the supplied X25519 key
 * @param x25519Key X25519 key
 * @param didDocument Did document containing all the keys
 * @returns a matching Ed25519 key or `undefined` (if no matching key found)
 */
export function findMatchingEd25519Key(x25519Key: Key, didDocument: DidDocument): Key | undefined {
  if (x25519Key.keyType !== KeyType.X25519) return undefined

  const verificationMethods = didDocument.verificationMethod ?? []
  const keyAgreements = didDocument.keyAgreement ?? []
  const authentications = didDocument.authentication ?? []
  const allKeyReferences: VerificationMethod[] = [
    ...verificationMethods,
    ...authentications.filter((keyAgreement): keyAgreement is VerificationMethod => typeof keyAgreement !== 'string'),
    ...keyAgreements.filter((keyAgreement): keyAgreement is VerificationMethod => typeof keyAgreement !== 'string'),
  ]

  return allKeyReferences
    .map((keyReference) => getKeyFromVerificationMethod(didDocument.dereferenceKey(keyReference.id)))
    .filter((key) => key?.keyType === KeyType.Ed25519)
    .find((keyEd25519) => {
      const keyX25519 = Key.fromPublicKey(convertPublicKeyToX25519(keyEd25519.publicKey), KeyType.X25519)
      return keyX25519.publicKeyBase58 === x25519Key.publicKeyBase58
    })
}
