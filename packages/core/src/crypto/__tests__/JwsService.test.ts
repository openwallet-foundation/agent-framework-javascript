import type { AgentContext } from '../../agent'
import type { Key, Wallet } from '@aries-framework/core'

// eslint-disable-next-line import/no-extraneous-dependencies
import '@hyperledger/aries-askar-nodejs'

import { describeRunInNodeVersion } from '../../../../../tests/runInVersion'
import { AskarWallet } from '../../../../askar/src'
import { agentDependencies, getAgentConfig, getAgentContext } from '../../../tests/helpers'
import { DidKey } from '../../modules/dids'
import { Buffer, JsonEncoder, TypedArrayEncoder } from '../../utils'
import { JwsService } from '../JwsService'
import { KeyType } from '../KeyType'
import { JwaSignatureAlgorithm } from '../jose/jwa'
import { getJwkFromKey } from '../jose/jwk'
import { SigningProviderRegistry } from '../signing-provider'

import * as didJwsz6Mkf from './__fixtures__/didJwsz6Mkf'
import * as didJwsz6Mkv from './__fixtures__/didJwsz6Mkv'
import * as didJwszDnaey from './__fixtures__/didJwszDnaey'

describeRunInNodeVersion([18], 'JwsService', () => {
  let wallet: Wallet
  let agentContext: AgentContext
  let jwsService: JwsService
  let didJwsz6MkfKey: Key
  let didJwsz6MkvKey: Key
  let didJwszDnaeyKey: Key

  beforeAll(async () => {
    const config = getAgentConfig('JwsService')
    wallet = new AskarWallet(config.logger, new agentDependencies.FileSystem(), new SigningProviderRegistry([]))
    agentContext = getAgentContext({
      wallet,
    })
    await wallet.createAndOpen(config.walletConfig)

    jwsService = new JwsService()
    didJwsz6MkfKey = await wallet.createKey({
      privateKey: TypedArrayEncoder.fromString(didJwsz6Mkf.SEED),
      keyType: KeyType.Ed25519,
    })

    didJwsz6MkvKey = await wallet.createKey({
      privateKey: TypedArrayEncoder.fromString(didJwsz6Mkv.SEED),
      keyType: KeyType.Ed25519,
    })

    didJwszDnaeyKey = await wallet.createKey({
      privateKey: TypedArrayEncoder.fromString(didJwszDnaey.SEED),
      keyType: KeyType.P256,
    })
  })

  afterAll(async () => {
    await wallet.delete()
  })

  it('creates a jws for the payload using Ed25519 key', async () => {
    const payload = JsonEncoder.toBuffer(didJwsz6Mkf.DATA_JSON)
    const kid = new DidKey(didJwsz6MkfKey).did

    const jws = await jwsService.createJws(agentContext, {
      payload,
      key: didJwsz6MkfKey,
      header: { kid },
      protectedHeaderOptions: {
        alg: JwaSignatureAlgorithm.EdDSA,
        jwk: getJwkFromKey(didJwsz6MkfKey),
      },
    })

    expect(jws).toEqual(didJwsz6Mkf.JWS_JSON)
  })

  it('creates and verify a jws using ES256 alg and P-256 kty', async () => {
    const payload = JsonEncoder.toBuffer(didJwszDnaey.DATA_JSON)
    const kid = new DidKey(didJwszDnaeyKey).did

    const jws = await jwsService.createJws(agentContext, {
      payload,
      key: didJwszDnaeyKey,
      header: { kid },
      protectedHeaderOptions: {
        alg: JwaSignatureAlgorithm.ES256,
        jwk: getJwkFromKey(didJwszDnaeyKey),
      },
    })

    expect(jws).toEqual(didJwszDnaey.JWS_JSON)
  })

  it('creates a compact jws', async () => {
    const payload = JsonEncoder.toBuffer(didJwsz6Mkf.DATA_JSON)

    const jws = await jwsService.createJwsCompact(agentContext, {
      payload,
      key: didJwsz6MkfKey,
      protectedHeaderOptions: {
        alg: JwaSignatureAlgorithm.EdDSA,
        jwk: getJwkFromKey(didJwsz6MkfKey),
      },
    })

    expect(jws).toEqual(
      `${didJwsz6Mkf.JWS_JSON.protected}.${TypedArrayEncoder.toBase64URL(payload)}.${didJwsz6Mkf.JWS_JSON.signature}`
    )
  })

  describe('verifyJws', () => {
    it('returns true if the jws signature matches the payload', async () => {
      const payload = JsonEncoder.toBuffer(didJwsz6Mkf.DATA_JSON)

      const { isValid, signerKeys } = await jwsService.verifyJws(agentContext, {
        payload,
        jws: didJwsz6Mkf.JWS_JSON,
      })

      expect(isValid).toBe(true)
      expect(signerKeys).toEqual([didJwsz6MkfKey])
    })

    it('returns all keys that signed the jws', async () => {
      const payload = JsonEncoder.toBuffer(didJwsz6Mkf.DATA_JSON)

      const { isValid, signerKeys } = await jwsService.verifyJws(agentContext, {
        payload,
        jws: { signatures: [didJwsz6Mkf.JWS_JSON, didJwsz6Mkv.JWS_JSON] },
      })

      expect(isValid).toBe(true)
      expect(signerKeys).toEqual([didJwsz6MkfKey, didJwsz6MkvKey])
    })

    it('returns false if the jws signature does not match the payload', async () => {
      const payload = JsonEncoder.toBuffer({ ...didJwsz6Mkf.DATA_JSON, did: 'another_did' })

      const { isValid, signerKeys } = await jwsService.verifyJws(agentContext, {
        payload,
        jws: didJwsz6Mkf.JWS_JSON,
      })

      expect(isValid).toBe(false)
      expect(signerKeys).toMatchObject([])
    })

    it('throws an error if the jws signatures array does not contain a JWS', async () => {
      await expect(
        jwsService.verifyJws(agentContext, {
          payload: new Buffer([]),
          jws: { signatures: [] },
        })
      ).rejects.toThrowError('Unable to verify JWS: No entries in JWS signatures array.')
    })
  })
})
