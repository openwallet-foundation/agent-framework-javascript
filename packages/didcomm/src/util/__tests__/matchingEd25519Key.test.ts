import type { VerificationMethod } from '@credo-ts/core'

import { DidDocument, Key, KeyType } from '@credo-ts/core'

import { findMatchingEd25519Key } from '../matchingEd25519Key'

describe('findMatchingEd25519Key', () => {
  const publicKeyBase58Ed25519 = 'GyYtYWU1vjwd5PFJM4VSX5aUiSV3TyZMuLBJBTQvfdF8'
  const Ed25519VerificationMethod: VerificationMethod = {
    type: 'Ed25519VerificationKey2018',
    controller: 'did:sov:WJz9mHyW9BZksioQnRsrAo',
    id: 'did:sov:WJz9mHyW9BZksioQnRsrAo#key-1',
    publicKeyBase58: publicKeyBase58Ed25519,
  }

  const publicKeyBase58X25519 = 'S3AQEEKkGYrrszT9D55ozVVX2XixYp8uynqVm4okbud'
  const X25519VerificationMethod: VerificationMethod = {
    type: 'X25519KeyAgreementKey2019',
    controller: 'did:sov:WJz9mHyW9BZksioQnRsrAo',
    id: 'did:sov:WJz9mHyW9BZksioQnRsrAo#key-agreement-1',
    publicKeyBase58: publicKeyBase58X25519,
  }

  describe('referenced verification method', () => {
    const didDocument = new DidDocument({
      context: [
        'https://w3id.org/did/v1',
        'https://w3id.org/security/suites/ed25519-2018/v1',
        'https://w3id.org/security/suites/x25519-2019/v1',
      ],
      id: 'did:sov:WJz9mHyW9BZksioQnRsrAo',
      verificationMethod: [Ed25519VerificationMethod, X25519VerificationMethod],
      authentication: [Ed25519VerificationMethod.id],
      assertionMethod: [Ed25519VerificationMethod.id],
      keyAgreement: [X25519VerificationMethod.id],
    })

    test('returns matching Ed25519 key if corresponding X25519 key supplied', () => {
      const x25519Key = Key.fromPublicKeyBase58(publicKeyBase58X25519, KeyType.X25519)
      const ed25519Key = findMatchingEd25519Key(x25519Key, didDocument)
      expect(ed25519Key?.publicKeyBase58).toBe(Ed25519VerificationMethod.publicKeyBase58)
    })

    test('returns undefined if non-corresponding X25519 key supplied', () => {
      const differentX25519Key = Key.fromPublicKeyBase58('Fbv17ZbnUSbafsiUBJbdGeC62M8v8GEscVMMcE59mRPt', KeyType.X25519)
      expect(findMatchingEd25519Key(differentX25519Key, didDocument)).toBeUndefined()
    })

    test('returns undefined if ed25519 key supplied', () => {
      const ed25519Key = Key.fromPublicKeyBase58(publicKeyBase58Ed25519, KeyType.Ed25519)
      expect(findMatchingEd25519Key(ed25519Key, didDocument)).toBeUndefined()
    })
  })

  describe('non-referenced authentication', () => {
    const didDocument = new DidDocument({
      context: [
        'https://w3id.org/did/v1',
        'https://w3id.org/security/suites/ed25519-2018/v1',
        'https://w3id.org/security/suites/x25519-2019/v1',
      ],
      id: 'did:sov:WJz9mHyW9BZksioQnRsrAo',
      authentication: [Ed25519VerificationMethod],
      assertionMethod: [Ed25519VerificationMethod],
      keyAgreement: [X25519VerificationMethod],
    })

    test('returns matching Ed25519 key if corresponding X25519 key supplied', () => {
      const x25519Key = Key.fromPublicKeyBase58(publicKeyBase58X25519, KeyType.X25519)
      const ed25519Key = findMatchingEd25519Key(x25519Key, didDocument)
      expect(ed25519Key?.publicKeyBase58).toBe(Ed25519VerificationMethod.publicKeyBase58)
    })

    test('returns undefined if non-corresponding X25519 key supplied', () => {
      const differentX25519Key = Key.fromPublicKeyBase58('Fbv17ZbnUSbafsiUBJbdGeC62M8v8GEscVMMcE59mRPt', KeyType.X25519)
      expect(findMatchingEd25519Key(differentX25519Key, didDocument)).toBeUndefined()
    })

    test('returns undefined if ed25519 key supplied', () => {
      const ed25519Key = Key.fromPublicKeyBase58(publicKeyBase58Ed25519, KeyType.Ed25519)
      expect(findMatchingEd25519Key(ed25519Key, didDocument)).toBeUndefined()
    })
  })
})
