import type { SdJwtVcHeader } from '../SdJwtVcOptions'
import type { Key } from '@aries-framework/core'

import { AskarModule } from '@aries-framework/askar'
import {
  getJwkFromKey,
  DidKey,
  DidsModule,
  KeyDidRegistrar,
  KeyDidResolver,
  utils,
  KeyType,
  Agent,
  TypedArrayEncoder,
} from '@aries-framework/core'
import { agentDependencies } from '@aries-framework/node'
import { ariesAskar } from '@hyperledger/aries-askar-nodejs'

import { SdJwtVcService } from '../SdJwtVcService'
import { SdJwtVcRepository } from '../repository'

import {
  complexSdJwtVc,
  complexSdJwtVcPresentation,
  sdJwtVcWithSingleDisclosure,
  sdJwtVcWithSingleDisclosurePresentation,
  simpleJwtVc,
  simpleJwtVcPresentation,
} from './sdjwtvc.fixtures'

const agent = new Agent({
  config: { label: 'sdjwtvcserviceagent', walletConfig: { id: utils.uuid(), key: utils.uuid() } },
  modules: {
    askar: new AskarModule({ ariesAskar }),
    dids: new DidsModule({
      resolvers: [new KeyDidResolver()],
      registrars: [new KeyDidRegistrar()],
    }),
  },
  dependencies: agentDependencies,
})

agent.context.wallet.generateNonce = jest.fn(() => Promise.resolve('salt'))
Date.prototype.getTime = jest.fn(() => 1698151532000)

jest.mock('../repository/SdJwtVcRepository')
const SdJwtVcRepositoryMock = SdJwtVcRepository as jest.Mock<SdJwtVcRepository>

describe('SdJwtVcService', () => {
  const verifierDid = 'did:key:zUC74VEqqhEHQcgv4zagSPkqFJxuNWuoBPKjJuHETEUeHLoSqWt92viSsmaWjy82y'
  let issuerDidUrl: string
  let holderDidUrl: string
  let issuerKey: Key
  let holderKey: Key
  let sdJwtVcService: SdJwtVcService

  beforeAll(async () => {
    await agent.initialize()

    issuerKey = await agent.context.wallet.createKey({
      keyType: KeyType.Ed25519,
      seed: TypedArrayEncoder.fromString('00000000000000000000000000000000'),
    })

    const issuerDidKey = new DidKey(issuerKey)
    const issuerDidDocument = issuerDidKey.didDocument
    issuerDidUrl = (issuerDidDocument.verificationMethod ?? [])[0].id
    await agent.dids.import({ didDocument: issuerDidDocument, did: issuerDidDocument.id })

    holderKey = await agent.context.wallet.createKey({
      keyType: KeyType.Ed25519,
      seed: TypedArrayEncoder.fromString('00000000000000000000000000000001'),
    })

    const holderDidKey = new DidKey(holderKey)
    const holderDidDocument = holderDidKey.didDocument
    holderDidUrl = (holderDidDocument.verificationMethod ?? [])[0].id
    await agent.dids.import({ didDocument: holderDidDocument, did: holderDidDocument.id })

    const sdJwtVcRepositoryMock = new SdJwtVcRepositoryMock()
    sdJwtVcService = new SdJwtVcService(sdJwtVcRepositoryMock)
  })

  describe('SdJwtVcService.create', () => {
    test('Create sd-jwt-vc from a basic payload without disclosures', async () => {
      const { compact, sdJwtVcRecord } = await sdJwtVcService.create(
        agent.context,
        {
          claim: 'some-claim',
          vct: 'IdentityCredential',
        },
        {
          issuerDidUrl,
          holderDidUrl,
        }
      )

      expect(compact).toStrictEqual(simpleJwtVc)

      expect(sdJwtVcRecord.sdJwtVc.header).toEqual({
        alg: 'EdDSA',
        typ: 'vc+sd-jwt',
        kid: 'z6MktqtXNG8CDUY9PrrtoStFzeCnhpMmgxYL1gikcW3BzvNW',
      })

      expect(sdJwtVcRecord.sdJwtVc.payload).toEqual({
        claim: 'some-claim',
        vct: 'IdentityCredential',
        iat: Math.floor(new Date().getTime() / 1000),
        iss: issuerDidUrl.split('#')[0],
        cnf: {
          jwk: getJwkFromKey(holderKey).toJson(),
        },
      })
    })

    test('Create sd-jwt-vc from a basic payload with a disclosure', async () => {
      const { compact, sdJwtVcRecord } = await sdJwtVcService.create(
        agent.context,
        { claim: 'some-claim', vct: 'IdentityCredential' },
        {
          issuerDidUrl,
          holderDidUrl,
          disclosureFrame: { claim: true },
        }
      )

      expect(compact).toStrictEqual(sdJwtVcWithSingleDisclosure)

      expect(sdJwtVcRecord.sdJwtVc.header).toEqual({
        alg: 'EdDSA',
        typ: 'vc+sd-jwt',
        kid: 'z6MktqtXNG8CDUY9PrrtoStFzeCnhpMmgxYL1gikcW3BzvNW',
      })

      expect(sdJwtVcRecord.sdJwtVc.payload).toEqual({
        vct: 'IdentityCredential',
        iat: Math.floor(new Date().getTime() / 1000),
        iss: issuerDidUrl.split('#')[0],
        _sd: ['vcvFU4DsFKTqQ1vl4nelJWXTb_-0dNoBks6iqNFptyg'],
        _sd_alg: 'sha-256',
        cnf: {
          jwk: getJwkFromKey(holderKey).toJson(),
        },
      })

      expect(sdJwtVcRecord.sdJwtVc.payload).not.toContain({
        claim: 'some-claim',
      })

      expect(sdJwtVcRecord.sdJwtVc.disclosures).toEqual(expect.arrayContaining([['salt', 'claim', 'some-claim']]))
    })

    test('Create sd-jwt-vc from a basic payload with multiple (nested) disclosure', async () => {
      const { compact, sdJwtVcRecord } = await sdJwtVcService.create(
        agent.context,
        {
          vct: 'IdentityCredential',
          given_name: 'John',
          family_name: 'Doe',
          email: 'johndoe@example.com',
          phone_number: '+1-202-555-0101',
          address: {
            street_address: '123 Main St',
            locality: 'Anytown',
            region: 'Anystate',
            country: 'US',
          },
          birthdate: '1940-01-01',
          is_over_18: true,
          is_over_21: true,
          is_over_65: true,
        },
        {
          issuerDidUrl: issuerDidUrl,
          holderDidUrl: holderDidUrl,
          disclosureFrame: {
            is_over_65: true,
            is_over_21: true,
            is_over_18: true,
            birthdate: true,
            email: true,
            address: { region: true, country: true },
            given_name: true,
          },
        }
      )

      expect(compact).toStrictEqual(complexSdJwtVc)

      expect(sdJwtVcRecord.sdJwtVc.header).toEqual({
        alg: 'EdDSA',
        typ: 'vc+sd-jwt',
        kid: 'z6MktqtXNG8CDUY9PrrtoStFzeCnhpMmgxYL1gikcW3BzvNW',
      })

      expect(sdJwtVcRecord.sdJwtVc.payload).toEqual({
        vct: 'IdentityCredential',
        iat: Math.floor(new Date().getTime() / 1000),
        address: {
          _sd: ['NJnmct0BqBME1JfBlC6jRQVRuevpEONiYw7A7MHuJyQ', 'om5ZztZHB-Gd00LG21CV_xM4FaENSoiaOXnTAJNczB4'],
          locality: 'Anytown',
          street_address: '123 Main St',
        },
        phone_number: '+1-202-555-0101',
        family_name: 'Doe',
        iss: issuerDidUrl.split('#')[0],
        _sd: [
          '1Cur2k2A2oIB5CshSIf_A_Kg-l26u_qKuWQ79P0Vdas',
          'R1zTUvOYHgcepj0jHypGHz9EHttVKft0yswbc9ETPbU',
          'eDqQpdTXJXbWhf-EsI7zw5X6OvYmFN-UZQQMesXwKPw',
          'pdDk2_XAKHo7gOAfwF1b7OdCUVTit2kJHaxSECQ9xfc',
          'psauKUNWEi09nu3Cl89xKXgmpWENZl5uy1N1nyn_jMk',
          'sN_ge0pHXF6qmsYnX1A9SdwJ8ch8aENkxbODsT74YwI',
        ],
        _sd_alg: 'sha-256',
        cnf: {
          jwk: getJwkFromKey(holderKey).toJson(),
        },
      })

      expect(sdJwtVcRecord.sdJwtVc.payload).not.toContain({
        family_name: 'Doe',
        phone_number: '+1-202-555-0101',
        address: {
          region: 'Anystate',
          country: 'US',
        },
        birthdate: '1940-01-01',
        is_over_18: true,
        is_over_21: true,
        is_over_65: true,
      })

      expect(sdJwtVcRecord.sdJwtVc.disclosures).toEqual(
        expect.arrayContaining([
          ['salt', 'is_over_65', true],
          ['salt', 'is_over_21', true],
          ['salt', 'is_over_18', true],
          ['salt', 'birthdate', '1940-01-01'],
          ['salt', 'email', 'johndoe@example.com'],
          ['salt', 'region', 'Anystate'],
          ['salt', 'country', 'US'],
          ['salt', 'given_name', 'John'],
        ])
      )
    })
  })

  describe('SdJwtVcService.receive', () => {
    test('Receive sd-jwt-vc from a basic payload without disclosures', async () => {
      const sdJwtVc = simpleJwtVc

      const sdJwtVcRecord = await sdJwtVcService.fromSerializedJwt(agent.context, sdJwtVc, {
        issuerDidUrl,
        holderDidUrl,
      })

      await sdJwtVcService.storeCredential(agent.context, sdJwtVcRecord)

      expect(sdJwtVcRecord.sdJwtVc.header).toEqual({
        alg: 'EdDSA',
        typ: 'vc+sd-jwt',
        kid: 'z6MktqtXNG8CDUY9PrrtoStFzeCnhpMmgxYL1gikcW3BzvNW',
      })

      expect(sdJwtVcRecord.sdJwtVc.payload).toEqual({
        claim: 'some-claim',
        vct: 'IdentityCredential',
        iat: Math.floor(new Date().getTime() / 1000),
        iss: issuerDidUrl.split('#')[0],
        cnf: {
          jwk: getJwkFromKey(holderKey).toJson(),
        },
      })
    })

    test('Receive sd-jwt-vc from a basic payload with a disclosure', async () => {
      const sdJwtVc = sdJwtVcWithSingleDisclosure

      const sdJwtVcRecord = await sdJwtVcService.fromSerializedJwt(agent.context, sdJwtVc, {
        issuerDidUrl,
        holderDidUrl,
      })

      await sdJwtVcService.storeCredential(agent.context, sdJwtVcRecord)

      expect(sdJwtVcRecord.sdJwtVc.header).toEqual({
        alg: 'EdDSA',
        typ: 'vc+sd-jwt',
        kid: 'z6MktqtXNG8CDUY9PrrtoStFzeCnhpMmgxYL1gikcW3BzvNW',
      })

      expect(sdJwtVcRecord.sdJwtVc.payload).toEqual({
        vct: 'IdentityCredential',
        iat: Math.floor(new Date().getTime() / 1000),
        iss: issuerDidUrl.split('#')[0],
        _sd: ['vcvFU4DsFKTqQ1vl4nelJWXTb_-0dNoBks6iqNFptyg'],
        _sd_alg: 'sha-256',
        cnf: {
          jwk: getJwkFromKey(holderKey).toJson(),
        },
      })

      expect(sdJwtVcRecord.sdJwtVc.payload).not.toContain({
        claim: 'some-claim',
      })

      expect(sdJwtVcRecord.sdJwtVc.disclosures).toEqual(expect.arrayContaining([['salt', 'claim', 'some-claim']]))
    })

    test('Receive sd-jwt-vc from a basic payload with multiple (nested) disclosure', async () => {
      const sdJwtVc = complexSdJwtVc

      const sdJwtVcRecord = await sdJwtVcService.fromSerializedJwt(agent.context, sdJwtVc, {
        issuerDidUrl,
        holderDidUrl,
      })

      await sdJwtVcService.storeCredential(agent.context, sdJwtVcRecord)

      expect(sdJwtVcRecord.sdJwtVc.header).toEqual({
        alg: 'EdDSA',
        typ: 'vc+sd-jwt',
        kid: 'z6MktqtXNG8CDUY9PrrtoStFzeCnhpMmgxYL1gikcW3BzvNW',
      })

      expect(sdJwtVcRecord.sdJwtVc.payload).toEqual({
        vct: 'IdentityCredential',
        iat: Math.floor(new Date().getTime() / 1000),
        family_name: 'Doe',
        iss: issuerDidUrl.split('#')[0],
        address: {
          _sd: ['NJnmct0BqBME1JfBlC6jRQVRuevpEONiYw7A7MHuJyQ', 'om5ZztZHB-Gd00LG21CV_xM4FaENSoiaOXnTAJNczB4'],
          locality: 'Anytown',
          street_address: '123 Main St',
        },
        phone_number: '+1-202-555-0101',
        _sd: [
          '1Cur2k2A2oIB5CshSIf_A_Kg-l26u_qKuWQ79P0Vdas',
          'R1zTUvOYHgcepj0jHypGHz9EHttVKft0yswbc9ETPbU',
          'eDqQpdTXJXbWhf-EsI7zw5X6OvYmFN-UZQQMesXwKPw',
          'pdDk2_XAKHo7gOAfwF1b7OdCUVTit2kJHaxSECQ9xfc',
          'psauKUNWEi09nu3Cl89xKXgmpWENZl5uy1N1nyn_jMk',
          'sN_ge0pHXF6qmsYnX1A9SdwJ8ch8aENkxbODsT74YwI',
        ],
        _sd_alg: 'sha-256',
        cnf: {
          jwk: getJwkFromKey(holderKey).toJson(),
        },
      })

      expect(sdJwtVcRecord.sdJwtVc.payload).not.toContain({
        family_name: 'Doe',
        phone_number: '+1-202-555-0101',
        address: {
          region: 'Anystate',
          country: 'US',
        },
        birthdate: '1940-01-01',
        is_over_18: true,
        is_over_21: true,
        is_over_65: true,
      })

      expect(sdJwtVcRecord.sdJwtVc.disclosures).toEqual(
        expect.arrayContaining([
          ['salt', 'is_over_65', true],
          ['salt', 'is_over_21', true],
          ['salt', 'is_over_18', true],
          ['salt', 'birthdate', '1940-01-01'],
          ['salt', 'email', 'johndoe@example.com'],
          ['salt', 'region', 'Anystate'],
          ['salt', 'country', 'US'],
          ['salt', 'given_name', 'John'],
        ])
      )
    })
  })

  describe('SdJwtVcService.present', () => {
    test('Present sd-jwt-vc from a basic payload without disclosures', async () => {
      const sdJwtVc = simpleJwtVc

      const sdJwtVcRecord = await sdJwtVcService.fromSerializedJwt(agent.context, sdJwtVc, {
        issuerDidUrl,
        holderDidUrl,
      })

      await sdJwtVcService.storeCredential(agent.context, sdJwtVcRecord)

      const presentation = await sdJwtVcService.present(agent.context, sdJwtVcRecord, {
        presentationFrame: {},
        verifierMetadata: {
          issuedAt: new Date().getTime() / 1000,
          verifierDid,
          nonce: await agent.context.wallet.generateNonce(),
        },
      })

      expect(presentation).toStrictEqual(simpleJwtVcPresentation)
    })

    test('Present sd-jwt-vc from a basic payload with a disclosure', async () => {
      const sdJwtVc = sdJwtVcWithSingleDisclosure

      const sdJwtVcRecord = await sdJwtVcService.fromSerializedJwt(agent.context, sdJwtVc, {
        issuerDidUrl,
        holderDidUrl,
      })

      await sdJwtVcService.storeCredential(agent.context, sdJwtVcRecord)

      const presentation = await sdJwtVcService.present(agent.context, sdJwtVcRecord, {
        presentationFrame: {
          claim: true,
        },
        verifierMetadata: {
          issuedAt: new Date().getTime() / 1000,
          verifierDid,
          nonce: await agent.context.wallet.generateNonce(),
        },
      })

      expect(presentation).toStrictEqual(sdJwtVcWithSingleDisclosurePresentation)
    })

    test('Present sd-jwt-vc from a basic payload with multiple (nested) disclosure', async () => {
      const sdJwtVc = complexSdJwtVc

      const sdJwtVcRecord = await sdJwtVcService.fromSerializedJwt<
        Record<string, unknown>,
        {
          // FIXME: when not passing a payload, adding nested presentationFrame is broken
          // Needs to be fixed in sd-jwt library
          address: {
            country: string
          }
        }
      >(agent.context, sdJwtVc, {
        issuerDidUrl,
        holderDidUrl,
      })

      await sdJwtVcService.storeCredential(agent.context, sdJwtVcRecord)

      const presentation = await sdJwtVcService.present(agent.context, sdJwtVcRecord, {
        verifierMetadata: {
          issuedAt: new Date().getTime() / 1000,
          verifierDid,
          nonce: await agent.context.wallet.generateNonce(),
        },
        presentationFrame: {
          is_over_65: true,
          is_over_21: true,
          email: true,
          address: {
            country: true,
          },
          given_name: true,
        },
      })

      expect(presentation).toStrictEqual(complexSdJwtVcPresentation)
    })
  })

  describe('SdJwtVcService.verify', () => {
    test('Verify sd-jwt-vc without disclosures', async () => {
      const sdJwtVc = simpleJwtVc

      const sdJwtVcRecord = await sdJwtVcService.fromSerializedJwt(agent.context, sdJwtVc, {
        issuerDidUrl,
        holderDidUrl,
      })

      await sdJwtVcService.storeCredential(agent.context, sdJwtVcRecord)

      const presentation = await sdJwtVcService.present(agent.context, sdJwtVcRecord, {
        // no disclosures
        presentationFrame: {},
        verifierMetadata: {
          issuedAt: new Date().getTime() / 1000,
          verifierDid,
          nonce: await agent.context.wallet.generateNonce(),
        },
      })

      const { validation } = await sdJwtVcService.verify(agent.context, presentation, {
        challenge: { verifierDid },
        holderDidUrl,
        requiredClaimKeys: ['claim'],
      })

      expect(validation).toEqual({
        isSignatureValid: true,
        containsRequiredVcProperties: true,
        areRequiredClaimsIncluded: true,
        isValid: true,
        isKeyBindingValid: true,
      })
    })

    test('Verify sd-jwt-vc with a disclosure', async () => {
      const sdJwtVc = sdJwtVcWithSingleDisclosure

      const sdJwtVcRecord = await sdJwtVcService.fromSerializedJwt(agent.context, sdJwtVc, {
        issuerDidUrl,
        holderDidUrl,
      })

      await sdJwtVcService.storeCredential(agent.context, sdJwtVcRecord)

      const presentation = await sdJwtVcService.present(agent.context, sdJwtVcRecord, {
        verifierMetadata: {
          issuedAt: new Date().getTime() / 1000,
          verifierDid,
          nonce: await agent.context.wallet.generateNonce(),
        },
        presentationFrame: {
          claim: true,
        },
      })

      const { validation } = await sdJwtVcService.verify(agent.context, presentation, {
        challenge: { verifierDid },
        holderDidUrl,
        requiredClaimKeys: ['vct', 'cnf', 'claim', 'iat'],
      })

      expect(validation).toEqual({
        isSignatureValid: true,
        containsRequiredVcProperties: true,
        areRequiredClaimsIncluded: true,
        isValid: true,
        isKeyBindingValid: true,
      })
    })

    test('Verify sd-jwt-vc with multiple (nested) disclosure', async () => {
      const sdJwtVc = complexSdJwtVc

      const sdJwtVcRecord = await sdJwtVcService.fromSerializedJwt<SdJwtVcHeader, { address: { country: string } }>(
        agent.context,
        sdJwtVc,
        {
          issuerDidUrl,
          holderDidUrl,
        }
      )

      await sdJwtVcService.storeCredential(agent.context, sdJwtVcRecord)

      const presentation = await sdJwtVcService.present(agent.context, sdJwtVcRecord, {
        verifierMetadata: {
          issuedAt: new Date().getTime() / 1000,
          verifierDid,
          nonce: await agent.context.wallet.generateNonce(),
        },
        presentationFrame: {
          is_over_65: true,
          is_over_21: true,
          email: true,
          address: {
            country: true,
          },
          given_name: true,
        },
      })

      const { validation } = await sdJwtVcService.verify(agent.context, presentation, {
        challenge: { verifierDid },
        holderDidUrl,
        // FIXME: this should be a requiredFrame to be consistent with the other methods
        // using frames
        requiredClaimKeys: [
          'vct',
          'family_name',
          'phone_number',
          'address',
          'cnf',
          'iss',
          'iat',
          'is_over_65',
          'is_over_21',
          'email',
          'given_name',
          'street_address',
          'locality',
          'country',
        ],
      })

      expect(validation).toEqual({
        isSignatureValid: true,
        areRequiredClaimsIncluded: true,
        containsRequiredVcProperties: true,
        isValid: true,
        isKeyBindingValid: true,
      })
    })
  })
})
