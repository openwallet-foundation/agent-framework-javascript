import type { WalletConfig } from '@aries-framework/core'

import {
  KeyType,
  WalletError,
  SigningProviderRegistry,
  TypedArrayEncoder,
  KeyDerivationMethod,
} from '@aries-framework/core'
import indySdk from 'indy-sdk'

import testLogger from '../../../../core/tests/logger'
import { IndySdkWallet } from '../IndySdkWallet'

// use raw key derivation method to speed up wallet creating / opening / closing between tests
const walletConfig: WalletConfig = {
  id: 'Wallet: IndySdkWalletTest',
  // generated using indy.generateWalletKey
  key: 'CwNJroKHTSSj3XvE7ZAnuKiTn2C4QkFvxEqfm5rzhNrb',
  keyDerivationMethod: KeyDerivationMethod.Raw,
}

describe('IndySdkWallet', () => {
  let indySdkWallet: IndySdkWallet

  const privateKey = TypedArrayEncoder.fromString('sample-seed')
  const message = TypedArrayEncoder.fromString('sample-message')

  beforeEach(async () => {
    indySdkWallet = new IndySdkWallet(indySdk, testLogger, new SigningProviderRegistry([]))
    await indySdkWallet.createAndOpen(walletConfig)
  })

  afterEach(async () => {
    await indySdkWallet.delete()
  })

  test('Get the wallet handle', () => {
    expect(indySdkWallet.handle).toEqual(expect.any(Number))
  })

  test('Generate Nonce', async () => {
    await expect(indySdkWallet.generateNonce()).resolves.toEqual(expect.any(String))
  })

  test('Create ed25519 keypair from private key', async () => {
    await expect(
      indySdkWallet.createKey({
        privateKey: TypedArrayEncoder.fromString('2103de41b4ae37e8e28586d84a342b67'),
        keyType: KeyType.Ed25519,
      })
    ).resolves.toMatchObject({
      keyType: KeyType.Ed25519,
    })
  })

  test('Fail to create ed25519 keypair from seed', async () => {
    await expect(indySdkWallet.createKey({ privateKey, keyType: KeyType.Ed25519 })).rejects.toThrowError(WalletError)
  })

  test('Fail to create x25519 keypair', async () => {
    await expect(indySdkWallet.createKey({ privateKey, keyType: KeyType.X25519 })).rejects.toThrowError(WalletError)
  })

  test('Create a signature with a ed25519 keypair', async () => {
    const ed25519Key = await indySdkWallet.createKey({ keyType: KeyType.Ed25519 })
    const signature = await indySdkWallet.sign({
      data: message,
      key: ed25519Key,
    })
    expect(signature.length).toStrictEqual(64)
  })

  test('Verify a signed message with a ed25519 publicKey', async () => {
    const ed25519Key = await indySdkWallet.createKey({ keyType: KeyType.Ed25519 })
    const signature = await indySdkWallet.sign({
      data: message,
      key: ed25519Key,
    })
    await expect(indySdkWallet.verify({ key: ed25519Key, data: message, signature })).resolves.toStrictEqual(true)
  })
})
