import type { DidDocument, VerificationMethod } from '.'

import { convertPublicKeyToX25519 } from '@stablelib/ed25519'
import { varint } from 'multiformats'

import { BufferEncoder } from '../../../utils/BufferEncoder'
import { MultiBaseEncoder } from '../../../utils/MultiBaseEncoder'
import { Buffer } from '../../../utils/buffer'
import { parseDid } from '../parse'

import { DidDocumentBuilder } from './DidDocumentBuilder'

export const enum KeyType {
  ED25519 = 'ed25519',
  X25519 = 'x25519',
  BLS12381G1 = 'bls12381g1',
  BLS12381G2 = 'bls12381g2',
  BLS12381G1G2 = 'bls12381g1g2',
}

const keyTypeResolverMap: Record<KeyType, (didKey: DidKey) => DidDocument> = {
  [KeyType.ED25519]: getEd25519DidDoc,
  [KeyType.X25519]: getX25519DidDoc,
  [KeyType.BLS12381G1]: getBls12381g1DidDoc,
  [KeyType.BLS12381G2]: getBls12381g2DidDoc,
  [KeyType.BLS12381G1G2]: getBls12381g1g2DidDoc,
}

// based on https://github.com/multiformats/multicodec/blob/master/table.csv
const idPrefixMap: Record<number, KeyType> = {
  234: KeyType.BLS12381G1,
  235: KeyType.BLS12381G2,
  236: KeyType.X25519,
  237: KeyType.ED25519,
  238: KeyType.BLS12381G1G2,
}

export class DidKey {
  public readonly publicKey: Buffer
  public readonly keyType: KeyType

  public constructor(publicKey: Uint8Array, keyType: KeyType) {
    this.publicKey = Buffer.from(publicKey)
    this.keyType = keyType
  }

  public static fromDid(did: string) {
    const parsed = parseDid(did)

    if (!parsed) {
      throw new Error('Unable to parse did')
    }

    return DidKey.fromFingerprint(parsed.id)
  }

  public static fromPublicKey(publicKey: Uint8Array, keyType: KeyType) {
    return new DidKey(Buffer.from(publicKey), keyType)
  }

  public static fromPublicKeyBase58(publicKey: string, keyType: KeyType) {
    const publicKeyBytes = BufferEncoder.fromBase58(publicKey)

    return DidKey.fromPublicKey(publicKeyBytes, keyType)
  }

  public static fromFingerprint(fingerprint: string) {
    const { data } = MultiBaseEncoder.decode(fingerprint)
    const [code, byteLength] = varint.decode(data)

    const publicKey = Buffer.from(data.slice(byteLength))
    const keyType = idPrefixMap[code]

    if (!keyType) {
      throw new Error(`Unsupported key type from multicodec code '${code}'`)
    }

    return new DidKey(publicKey, keyType)
  }

  public get prefixedPublicKey() {
    const codes = Object.keys(idPrefixMap) as unknown as number[]
    const code = codes.find((key) => idPrefixMap[key] === this.keyType) as number

    // Create Uint8Array with length of the prefix bytes, then use varint to fill the prefix bytes
    const prefixBytes = varint.encodeTo(code, new Uint8Array(varint.encodingLength(code)))

    // Combine prefix with public key
    return Buffer.concat([prefixBytes, this.publicKey])
  }

  public get fingerprint() {
    return `z${BufferEncoder.toBase58(this.prefixedPublicKey)}`
  }

  public get did() {
    return `did:key:${this.fingerprint}`
  }

  public get didDocument() {
    const resolve = keyTypeResolverMap[this.keyType]

    return resolve(this)
  }

  public get publicKeyBase58() {
    return BufferEncoder.toBase58(this.publicKey)
  }

  public get keyId() {
    return `${this.did}#${this.fingerprint}`
  }
}

function getBls12381g2DidDoc(didKey: DidKey) {
  return getSignatureKeyBase(didKey, {
    id: didKey.keyId,
    type: 'Bls12381G2Key2020',
    controller: didKey.did,
    publicKeyBase58: didKey.publicKeyBase58,
  }).build()
}

function getBls12381g1g2DidDoc(didKey: DidKey) {
  const g1PublicKey = didKey.publicKey.slice(0, 48)
  const g2PublicKey = didKey.publicKey.slice(48)

  const bls12381g1Key = DidKey.fromPublicKey(g1PublicKey, KeyType.BLS12381G1)
  const bls12381g2Key = DidKey.fromPublicKey(g2PublicKey, KeyType.BLS12381G2)

  const bls12381g1KeyId = `${didKey.did}#${bls12381g1Key.fingerprint}`
  const bls12381g2KeyId = `${didKey.did}#${bls12381g2Key.fingerprint}`

  const didDocumentBuilder = new DidDocumentBuilder(didKey.did)
    // BlS12381G1
    .addVerificationMethod({
      id: bls12381g1KeyId,
      type: 'Bls12381G1Key2020',
      controller: didKey.did,
      publicKeyBase58: bls12381g1Key.publicKeyBase58,
    })
    .addAuthentication(bls12381g1KeyId)
    .addAssertionMethod(bls12381g1KeyId)
    .addCapabilityDelegation(bls12381g1KeyId)
    .addCapabilityInvocation(bls12381g1KeyId)
    // BlS12381G2
    .addVerificationMethod({
      id: bls12381g2KeyId,
      type: 'Bls12381G2Key2020',
      controller: didKey.did,
      publicKeyBase58: bls12381g2Key.publicKeyBase58,
    })
    .addAuthentication(bls12381g2KeyId)
    .addAssertionMethod(bls12381g2KeyId)
    .addCapabilityDelegation(bls12381g2KeyId)
    .addCapabilityInvocation(bls12381g2KeyId)

  return didDocumentBuilder.build()
}

function getBls12381g1DidDoc(didKey: DidKey) {
  return getSignatureKeyBase(didKey, {
    id: didKey.keyId,
    type: 'Bls12381G1Key2020',
    controller: didKey.did,
    publicKeyBase58: didKey.publicKeyBase58,
  }).build()
}

function getX25519DidDoc(didKey: DidKey) {
  const document = new DidDocumentBuilder(didKey.did)
    .addKeyAgreement({
      id: didKey.keyId,
      type: 'X25519KeyAgreementKey2019',
      controller: didKey.did,
      publicKeyBase58: didKey.publicKeyBase58,
    })
    .build()

  return document
}

function getEd25519DidDoc(didKey: DidKey) {
  const verificationMethod: VerificationMethod = {
    id: didKey.keyId,
    type: 'Ed25519VerificationKey2018',
    controller: didKey.did,
    publicKeyBase58: didKey.publicKeyBase58,
  }

  const publicKeyX25519 = convertPublicKeyToX25519(didKey.publicKey)
  const didKeyX25519 = new DidKey(publicKeyX25519, KeyType.X25519)
  const x25519Id = `${didKey.did}#${didKeyX25519.fingerprint}`

  const didDocBuilder = getSignatureKeyBase(didKey, verificationMethod)

  didDocBuilder
    .addContext('https://w3id.org/security/suites/ed25519-2018/v1')
    .addContext('https://w3id.org/security/suites/x25519-2019/v1')
    .addVerificationMethod({
      id: `${didKey.did}#${didKeyX25519.fingerprint}`,
      type: 'X25519KeyAgreementKey2019',
      controller: didKey.did,
      publicKeyBase58: didKeyX25519.publicKeyBase58,
    })
    .addKeyAgreement(x25519Id)

  return didDocBuilder.build()
}

function getSignatureKeyBase(didKey: DidKey, verificationMethod: VerificationMethod) {
  const keyId = didKey.keyId

  return new DidDocumentBuilder(didKey.did)
    .addVerificationMethod(verificationMethod)
    .addAuthentication(keyId)
    .addAssertionMethod(keyId)
    .addCapabilityDelegation(keyId)
    .addCapabilityInvocation(keyId)
}
