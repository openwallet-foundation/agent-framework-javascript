import type { Wallet } from '../../../../../wallet'

import { getAgentContext, mockFunction } from '../../../../../../tests/helpers'
import { KeyType } from '../../../../../crypto'
import { Key } from '../../../../../crypto/Key'
import { TypedArrayEncoder } from '../../../../../utils'
import { JsonTransformer } from '../../../../../utils/JsonTransformer'
import { WalletError } from '../../../../../wallet/error'
import { DidCommV1Service, DidDocumentBuilder, getEd25519VerificationKey2018 } from '../../../domain'
import { DidDocumentRole } from '../../../domain/DidDocumentRole'
import { DidRepository } from '../../../repository/DidRepository'
import { PeerDidRegistrar } from '../PeerDidRegistrar'
import { PeerDidNumAlgo } from '../didPeer'

import didPeer0z6MksLeFixture from './__fixtures__/didPeer0z6MksLe.json'

jest.mock('../../../repository/DidRepository')
const DidRepositoryMock = DidRepository as jest.Mock<DidRepository>

const walletMock = {
  createKey: jest.fn(() => Key.fromFingerprint('z6MksLeew51QS6Ca6tVKM56LQNbxCNVcLHv4xXj4jMkAhPWU')),
} as unknown as Wallet
const didRepositoryMock = new DidRepositoryMock()

const agentContext = getAgentContext({ wallet: walletMock, registerInstances: [[DidRepository, didRepositoryMock]] })
const peerDidRegistrar = new PeerDidRegistrar()

describe('DidRegistrar', () => {
  afterEach(() => {
    jest.clearAllMocks()
  })

  describe('PeerDidRegistrar', () => {
    describe('did:peer:0', () => {
      it('should correctly create a did:peer:0 document using Ed25519 key type', async () => {
        const privateKey = TypedArrayEncoder.fromString('96213c3d7fc8d4d6754c712fd969598e')

        const result = await peerDidRegistrar.create(agentContext, {
          method: 'peer',
          options: {
            keyType: KeyType.Ed25519,
            numAlgo: PeerDidNumAlgo.InceptionKeyWithoutDoc,
          },
          secret: {
            privateKey,
          },
        })

        expect(JsonTransformer.toJSON(result)).toMatchObject({
          didDocumentMetadata: {},
          didRegistrationMetadata: {},
          didState: {
            state: 'finished',
            did: 'did:peer:0z6MksLeew51QS6Ca6tVKM56LQNbxCNVcLHv4xXj4jMkAhPWU',
            didDocument: didPeer0z6MksLeFixture,
            secret: {
              privateKey,
            },
          },
        })
      })

      it('should return an error state if no key type is provided', async () => {
        const result = await peerDidRegistrar.create(agentContext, {
          method: 'peer',
          // @ts-expect-error - key type is required in interface
          options: {
            numAlgo: PeerDidNumAlgo.InceptionKeyWithoutDoc,
          },
        })

        expect(JsonTransformer.toJSON(result)).toMatchObject({
          didDocumentMetadata: {},
          didRegistrationMetadata: {},
          didState: {
            state: 'failed',
            reason: 'Missing key type',
          },
        })
      })

      it('should return an error state if a key creation error is thrown', async () => {
        mockFunction(walletMock.createKey).mockRejectedValueOnce(new WalletError('Invalid private key provided'))

        const result = await peerDidRegistrar.create(agentContext, {
          method: 'peer',
          options: {
            keyType: KeyType.Ed25519,
            numAlgo: PeerDidNumAlgo.InceptionKeyWithoutDoc,
          },
          secret: {
            privateKey: TypedArrayEncoder.fromString('invalid'),
          },
        })

        expect(JsonTransformer.toJSON(result)).toMatchObject({
          didDocumentMetadata: {},
          didRegistrationMetadata: {},
          didState: {
            state: 'failed',
            reason: expect.stringContaining('Invalid private key provided'),
          },
        })
      })

      it('should store the did without the did document', async () => {
        const privateKey = TypedArrayEncoder.fromString('96213c3d7fc8d4d6754c712fd969598e')
        const did = 'did:peer:0z6MksLeew51QS6Ca6tVKM56LQNbxCNVcLHv4xXj4jMkAhPWU'

        await peerDidRegistrar.create(agentContext, {
          method: 'peer',
          options: {
            keyType: KeyType.Ed25519,
            numAlgo: PeerDidNumAlgo.InceptionKeyWithoutDoc,
          },
          secret: {
            privateKey,
          },
        })

        expect(didRepositoryMock.save).toHaveBeenCalledTimes(1)
        const [, didRecord] = mockFunction(didRepositoryMock.save).mock.calls[0]

        expect(didRecord).toMatchObject({
          did: did,
          role: DidDocumentRole.Created,
          _tags: {
            recipientKeyFingerprints: [],
          },
          didDocument: undefined,
        })
      })
    })

    describe('did:peer:1', () => {
      const verificationMethod = getEd25519VerificationKey2018({
        key: Key.fromFingerprint('z6LShxJc8afmt8L1HKjUE56hXwmAkUhdQygrH1VG2jmb1WRz'),
        // controller in method 1 did should be #id
        controller: '#id',
        id: '#41fb2ec7-1f8b-42bf-91a2-4ef9092ddc16',
      })

      const didDocument = new DidDocumentBuilder('')
        .addVerificationMethod(verificationMethod)
        .addAuthentication(verificationMethod.id)
        .addService(
          new DidCommV1Service({
            id: '#service-0',
            recipientKeys: [verificationMethod.id],
            serviceEndpoint: 'https://example.com',
            accept: ['didcomm/aip2;env=rfc19'],
          })
        )
        .build()

      it('should correctly create a did:peer:1 document from a did document', async () => {
        const result = await peerDidRegistrar.create(agentContext, {
          method: 'peer',
          didDocument: didDocument,
          options: {
            numAlgo: PeerDidNumAlgo.GenesisDoc,
          },
        })

        expect(JsonTransformer.toJSON(result)).toMatchObject({
          didDocumentMetadata: {},
          didRegistrationMetadata: {},
          didState: {
            state: 'finished',
            did: 'did:peer:1zQmUTNcSy2J2sAmX6Ad2bdPvhVnHPUaod8Skpt8DWPpZaiL',
            didDocument: {
              '@context': ['https://w3id.org/did/v1'],
              alsoKnownAs: undefined,
              controller: undefined,
              verificationMethod: [
                {
                  id: '#41fb2ec7-1f8b-42bf-91a2-4ef9092ddc16',
                  type: 'Ed25519VerificationKey2018',
                  controller: '#id',
                  publicKeyBase58: '7H8ScGrunfcGBwMhhRakDMYguLAWiNWhQ2maYH84J8fE',
                },
              ],
              service: [
                {
                  id: '#service-0',
                  serviceEndpoint: 'https://example.com',
                  type: 'did-communication',
                  priority: 0,
                  recipientKeys: ['#41fb2ec7-1f8b-42bf-91a2-4ef9092ddc16'],
                  accept: ['didcomm/aip2;env=rfc19'],
                },
              ],
              authentication: ['#41fb2ec7-1f8b-42bf-91a2-4ef9092ddc16'],
              assertionMethod: undefined,
              keyAgreement: undefined,
              capabilityInvocation: undefined,
              capabilityDelegation: undefined,
              id: 'did:peer:1zQmUTNcSy2J2sAmX6Ad2bdPvhVnHPUaod8Skpt8DWPpZaiL',
            },
          },
        })
      })

      it('should store the did with the did document', async () => {
        const did = 'did:peer:1zQmUTNcSy2J2sAmX6Ad2bdPvhVnHPUaod8Skpt8DWPpZaiL'

        const { didState } = await peerDidRegistrar.create(agentContext, {
          method: 'peer',
          didDocument,
          options: {
            numAlgo: PeerDidNumAlgo.GenesisDoc,
          },
        })

        expect(didRepositoryMock.save).toHaveBeenCalledTimes(1)
        const [, didRecord] = mockFunction(didRepositoryMock.save).mock.calls[0]

        expect(didRecord).toMatchObject({
          did: did,
          didDocument: didState.didDocument,
          role: DidDocumentRole.Created,
          _tags: {
            recipientKeyFingerprints: didDocument.recipientKeys.map((key) => key.fingerprint),
          },
        })
      })
    })

    describe('did:peer:2', () => {
      const key = Key.fromFingerprint('z6LShxJc8afmt8L1HKjUE56hXwmAkUhdQygrH1VG2jmb1WRz')
      const verificationMethod = getEd25519VerificationKey2018({
        key,
        // controller in method 1 did should be #id
        controller: '#id',
        // Use relative id for peer dids with pattern 'key-N'
        id: '#key-1',
      })

      const didDocument = new DidDocumentBuilder('')
        .addVerificationMethod(verificationMethod)
        .addAuthentication(verificationMethod.id)
        .addService(
          new DidCommV1Service({
            id: '#service-0',
            recipientKeys: [verificationMethod.id],
            serviceEndpoint: 'https://example.com',
            accept: ['didcomm/aip2;env=rfc19'],
          })
        )
        .build()

      it('should correctly create a did:peer:2 document from a did document', async () => {
        const result = await peerDidRegistrar.create(agentContext, {
          method: 'peer',
          didDocument: didDocument,
          options: {
            numAlgo: PeerDidNumAlgo.MultipleInceptionKeyWithoutDoc,
          },
        })

        expect(JsonTransformer.toJSON(result)).toMatchObject({
          didDocumentMetadata: {},
          didRegistrationMetadata: {},
          didState: {
            state: 'finished',
            did: 'did:peer:2.Vz6MkkjPVCX7M8D6jJSCQNzYb4T6giuSN8Fm463gWNZ65DMSc.SeyJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbSIsInQiOiJkaWQtY29tbXVuaWNhdGlvbiIsInByaW9yaXR5IjowLCJyZWNpcGllbnRLZXlzIjpbIiNrZXktMSJdLCJhIjpbImRpZGNvbW0vYWlwMjtlbnY9cmZjMTkiXX0',
            didDocument: {
              '@context': ['https://w3id.org/did/v1'],
              id: 'did:peer:2.Vz6MkkjPVCX7M8D6jJSCQNzYb4T6giuSN8Fm463gWNZ65DMSc.SeyJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbSIsInQiOiJkaWQtY29tbXVuaWNhdGlvbiIsInByaW9yaXR5IjowLCJyZWNpcGllbnRLZXlzIjpbIiNrZXktMSJdLCJhIjpbImRpZGNvbW0vYWlwMjtlbnY9cmZjMTkiXX0',
              service: [
                {
                  serviceEndpoint: 'https://example.com',
                  type: 'did-communication',
                  priority: 0,
                  recipientKeys: ['#key-1'],
                  accept: ['didcomm/aip2;env=rfc19'],
                  id: '#service-0',
                },
              ],
              verificationMethod: [
                {
                  id: '#key-1',
                  type: 'Ed25519VerificationKey2018',
                  controller: '#id',
                  publicKeyBase58: '7H8ScGrunfcGBwMhhRakDMYguLAWiNWhQ2maYH84J8fE',
                },
              ],
              authentication: ['#key-1'],
            },
            secret: {},
          },
        })
      })

      it('should store the did without the did document', async () => {
        const did =
          'did:peer:2.Vz6MkkjPVCX7M8D6jJSCQNzYb4T6giuSN8Fm463gWNZ65DMSc.SeyJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbSIsInQiOiJkaWQtY29tbXVuaWNhdGlvbiIsInByaW9yaXR5IjowLCJyZWNpcGllbnRLZXlzIjpbIiNrZXktMSJdLCJhIjpbImRpZGNvbW0vYWlwMjtlbnY9cmZjMTkiXX0'

        await peerDidRegistrar.create(agentContext, {
          method: 'peer',
          didDocument,
          options: {
            numAlgo: PeerDidNumAlgo.MultipleInceptionKeyWithoutDoc,
          },
        })

        expect(didRepositoryMock.save).toHaveBeenCalledTimes(1)
        const [, didRecord] = mockFunction(didRepositoryMock.save).mock.calls[0]

        expect(didRecord).toMatchObject({
          did: did,
          role: DidDocumentRole.Created,
          _tags: {
            recipientKeyFingerprints: didDocument.recipientKeys.map((key) => key.fingerprint),
          },
          didDocument: undefined,
        })
      })
    })

    describe('did:peer:4', () => {
      const key = Key.fromFingerprint('z6LShxJc8afmt8L1HKjUE56hXwmAkUhdQygrH1VG2jmb1WRz')
      const verificationMethod = getEd25519VerificationKey2018({
        key,
        controller: '#id',
        // Use relative id for peer dids
        id: '#41fb2ec7-1f8b-42bf-91a2-4ef9092ddc16',
      })

      const didDocument = new DidDocumentBuilder('')
        .addVerificationMethod(verificationMethod)
        .addAuthentication(verificationMethod.id)
        .addService(
          new DidCommV1Service({
            id: '#service-0',
            recipientKeys: [verificationMethod.id],
            serviceEndpoint: 'https://example.com',
            accept: ['didcomm/aip2;env=rfc19'],
          })
        )
        .build()

      it('should correctly create a did:peer:4 document from a did document', async () => {
        const result = await peerDidRegistrar.create(agentContext, {
          method: 'peer',
          didDocument: didDocument,
          options: {
            numAlgo: PeerDidNumAlgo.ShortFormAndLongForm,
          },
        })

        const longFormDid =
          'did:peer:4zQmUJdJN7h66RpdeNEkNQ1tpUpN9nr2LcDz4Ftd3xKSgmn4:zD6dcwCdYV2zR4EBGTpxfEaRDLEq3ncjbutZpYTrMcGqaWip2P8vT6LrSH4cCVWfTdZgpuzBV4qY3ZasBMAs8M12JWstLTQHRVtu5ongsGvHCaWdWGS5cQaK6KLABnpBB5KgjPAN391Eekn1Zm4e14atfuj6gKHGp6V41GEumQFGM3YDwijVH82prvah5CqhRx6gXh4CYXu8MJVKiY5HBFdWyNLBtzaPWasGSEdLXYx6FcDv21igJfpcVbwQHwbU43wszfPypKiL9GDyys2n5zAWek5nQFGmDwrF65Vqy74CMFt8fZcvfBc1PTXSexhEwZkUY5inmeBbLXjbJU33FpWK6GxyDANxq5opQeRtAzUCtqeWxdafK56LYUes1THq6DzEKN2VirvvqygtnfPSJUfQWcRYixXq6bGGk5bjt14YygT7mALy5Ne6APGysjnNfH1MA3hrfEM9Ho8tuGSA2JeDvqYebV41chQDfKWoJrsG2bdFwZGgnkb3aBPHd4qyPvEdWiFLawR4mNj8qrtTagX1CyWvcAiWMKbspo5mVvCqP1SJuuT451X4uRBXazC9JGD2k7P63p71HU25zff4LvYkLeU8izcdBva1Tu4RddJN7jMFg4ifkTeZscFfbLPejFTmEDNRFswK1e'
        const shortFormDid = 'did:peer:4zQmUJdJN7h66RpdeNEkNQ1tpUpN9nr2LcDz4Ftd3xKSgmn4'
        expect(JsonTransformer.toJSON(result)).toMatchObject({
          didDocumentMetadata: {},
          didRegistrationMetadata: {},
          didState: {
            state: 'finished',
            did: longFormDid,
            didDocument: {
              '@context': ['https://w3id.org/did/v1'],
              id: longFormDid,
              alsoKnownAs: [shortFormDid],
              service: [
                {
                  serviceEndpoint: 'https://example.com',
                  type: 'did-communication',
                  priority: 0,
                  recipientKeys: ['#41fb2ec7-1f8b-42bf-91a2-4ef9092ddc16'],
                  accept: ['didcomm/aip2;env=rfc19'],
                  id: '#service-0',
                },
              ],
              verificationMethod: [
                {
                  id: '#41fb2ec7-1f8b-42bf-91a2-4ef9092ddc16',
                  type: 'Ed25519VerificationKey2018',
                  controller: '#id',
                  publicKeyBase58: '7H8ScGrunfcGBwMhhRakDMYguLAWiNWhQ2maYH84J8fE',
                },
              ],
              authentication: ['#41fb2ec7-1f8b-42bf-91a2-4ef9092ddc16'],
            },
            secret: {},
          },
        })
      })

      it('should store the did without the did document', async () => {
        const longFormDid =
          'did:peer:4zQmUJdJN7h66RpdeNEkNQ1tpUpN9nr2LcDz4Ftd3xKSgmn4:zD6dcwCdYV2zR4EBGTpxfEaRDLEq3ncjbutZpYTrMcGqaWip2P8vT6LrSH4cCVWfTdZgpuzBV4qY3ZasBMAs8M12JWstLTQHRVtu5ongsGvHCaWdWGS5cQaK6KLABnpBB5KgjPAN391Eekn1Zm4e14atfuj6gKHGp6V41GEumQFGM3YDwijVH82prvah5CqhRx6gXh4CYXu8MJVKiY5HBFdWyNLBtzaPWasGSEdLXYx6FcDv21igJfpcVbwQHwbU43wszfPypKiL9GDyys2n5zAWek5nQFGmDwrF65Vqy74CMFt8fZcvfBc1PTXSexhEwZkUY5inmeBbLXjbJU33FpWK6GxyDANxq5opQeRtAzUCtqeWxdafK56LYUes1THq6DzEKN2VirvvqygtnfPSJUfQWcRYixXq6bGGk5bjt14YygT7mALy5Ne6APGysjnNfH1MA3hrfEM9Ho8tuGSA2JeDvqYebV41chQDfKWoJrsG2bdFwZGgnkb3aBPHd4qyPvEdWiFLawR4mNj8qrtTagX1CyWvcAiWMKbspo5mVvCqP1SJuuT451X4uRBXazC9JGD2k7P63p71HU25zff4LvYkLeU8izcdBva1Tu4RddJN7jMFg4ifkTeZscFfbLPejFTmEDNRFswK1e'
        const shortFormDid = 'did:peer:4zQmUJdJN7h66RpdeNEkNQ1tpUpN9nr2LcDz4Ftd3xKSgmn4'
        await peerDidRegistrar.create(agentContext, {
          method: 'peer',
          didDocument,
          options: {
            numAlgo: PeerDidNumAlgo.ShortFormAndLongForm,
          },
        })

        expect(didRepositoryMock.save).toHaveBeenCalledTimes(1)
        const [, didRecord] = mockFunction(didRepositoryMock.save).mock.calls[0]

        expect(didRecord).toMatchObject({
          did: longFormDid,
          role: DidDocumentRole.Created,
          _tags: {
            recipientKeyFingerprints: didDocument.recipientKeys.map((key) => key.fingerprint),
            alternativeDids: [shortFormDid],
          },
          didDocument: undefined,
        })
      })
    })

    it('should return an error state if an unsupported numAlgo is provided', async () => {
      const result = await peerDidRegistrar.create(agentContext, {
        method: 'peer',
        options: {
          // @ts-expect-error - this is not a valid numAlgo
          numAlgo: 5,
        },
      })

      expect(JsonTransformer.toJSON(result)).toMatchObject({
        didDocumentMetadata: {},
        didRegistrationMetadata: {},
        didState: {
          state: 'failed',
          reason: 'Missing or incorrect numAlgo provided',
        },
      })
    })

    it('should return an error state when calling update', async () => {
      const result = await peerDidRegistrar.update()

      expect(result).toEqual({
        didDocumentMetadata: {},
        didRegistrationMetadata: {},
        didState: {
          state: 'failed',
          reason: `notImplemented: updating did:peer not implemented yet`,
        },
      })
    })

    it('should return an error state when calling deactivate', async () => {
      const result = await peerDidRegistrar.deactivate()

      expect(result).toEqual({
        didDocumentMetadata: {},
        didRegistrationMetadata: {},
        didState: {
          state: 'failed',
          reason: `notImplemented: deactivating did:peer not implemented yet`,
        },
      })
    })
  })
})
