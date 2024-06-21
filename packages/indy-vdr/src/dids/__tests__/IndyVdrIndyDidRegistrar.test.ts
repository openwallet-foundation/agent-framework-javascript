/* eslint-disable @typescript-eslint/ban-ts-comment */
import type { DidRecord, RecordSavedEvent } from '@credo-ts/core'

import {
  DidCommV1Service,
  DidCommV2Service,
  DidDocumentService,
  DidDocument,
  DidDocumentRole,
  DidRepository,
  DidsApi,
  EventEmitter,
  JsonTransformer,
  Key,
  KeyType,
  RepositoryEventTypes,
  TypedArrayEncoder,
  VerificationMethod,
} from '@credo-ts/core'
import { Subject } from 'rxjs'

import { InMemoryStorageService } from '../../../../../tests/InMemoryStorageService'
import { InMemoryWallet } from '../../../../../tests/InMemoryWallet'
import { agentDependencies, getAgentConfig, getAgentContext, mockProperty } from '../../../../core/tests'
import { IndyVdrPool, IndyVdrPoolService } from '../../pool'
import { IndyVdrIndyDidRegistrar } from '../IndyVdrIndyDidRegistrar'

jest.mock('../../pool/IndyVdrPool')
const IndyVdrPoolMock = IndyVdrPool as jest.Mock<IndyVdrPool>
const poolMock = new IndyVdrPoolMock()
mockProperty(poolMock, 'indyNamespace', 'ns1')

const agentConfig = getAgentConfig('IndyVdrIndyDidRegistrar')
const wallet = new InMemoryWallet()

jest
  .spyOn(wallet, 'createKey')
  .mockResolvedValue(Key.fromPublicKeyBase58('E6D1m3eERqCueX4ZgMCY14B4NceAr6XP2HyVqt55gDhu', KeyType.Ed25519))
const storageService = new InMemoryStorageService<DidRecord>()
const eventEmitter = new EventEmitter(agentDependencies, new Subject())
const didRepository = new DidRepository(storageService, eventEmitter)

const agentContext = getAgentContext({
  wallet,
  registerInstances: [
    [DidRepository, didRepository],
    [IndyVdrPoolService, { getPoolForNamespace: jest.fn().mockReturnValue(poolMock) }],
    [
      DidsApi,
      {
        resolve: jest.fn().mockResolvedValue({
          didDocument: new DidDocument({
            id: 'did:indy:pool1:BzCbsNYhMrjHiqZDTUASHg',
            authentication: [
              new VerificationMethod({
                id: 'did:indy:pool1:BzCbsNYhMrjHiqZDTUASHg#verkey',
                type: 'Ed25519VerificationKey2018',
                controller: 'did:indy:pool1:BzCbsNYhMrjHiqZDTUASHg',
                publicKeyBase58: 'E6D1m3eERqCueX4ZgMCY14B4NceAr6XP2HyVqt55gDhu',
              }),
            ],
          }),
        }),
      },
    ],
  ],
  agentConfig,
})

const indyVdrIndyDidRegistrar = new IndyVdrIndyDidRegistrar()

describe('IndyVdrIndyDidRegistrar', () => {
  afterEach(() => {
    jest.clearAllMocks()
  })

  test('returns an error state if both did and privateKey are provided', async () => {
    const result = await indyVdrIndyDidRegistrar.create(agentContext, {
      did: 'did:indy:pool1:did-value',
      options: {
        alias: 'Hello',
        endorserMode: 'internal',
        endorserDid: 'did:indy:pool1:BzCbsNYhMrjHiqZDTUASHg',
      },
      secret: {
        privateKey: TypedArrayEncoder.fromString('key'),
      },
    })

    expect(JsonTransformer.toJSON(result)).toMatchObject({
      didDocumentMetadata: {},
      didRegistrationMetadata: {},
      didState: {
        state: 'failed',
        reason: `Only one of 'seed', 'privateKey' and 'did' must be provided`,
      },
    })
  })

  test('returns an error state if the endorser did is not a valid did:indy did', async () => {
    const result = await indyVdrIndyDidRegistrar.create(agentContext, {
      method: 'indy',
      options: {
        endorserMode: 'internal',
        endorserDid: 'BzCbsNYhMrjHiqZDTUASHg',
        alias: 'Hello',
      },
    })

    expect(JsonTransformer.toJSON(result)).toMatchObject({
      didDocumentMetadata: {},
      didRegistrationMetadata: {},
      didState: {
        state: 'failed',
        reason: 'unknownError: BzCbsNYhMrjHiqZDTUASHg is not a valid did:indy did',
      },
    })
  })

  test('returns an error state if did is provided, but it is not a valid did:indy did', async () => {
    const result = await indyVdrIndyDidRegistrar.create(agentContext, {
      did: 'BzCbsNYhMrjHiqZDTUASHg',
      options: {
        endorserMode: 'internal',
        endorserDid: 'did:indy:pool1:BzCbsNYhMrjHiqZDTUASHg',
        verkey: 'verkey',
        alias: 'Hello',
      },
    })

    expect(JsonTransformer.toJSON(result)).toMatchObject({
      didDocumentMetadata: {},
      didRegistrationMetadata: {},
      didState: {
        state: 'failed',
        reason: 'unknownError: BzCbsNYhMrjHiqZDTUASHg is not a valid did:indy did',
      },
    })
  })

  test('returns an error state if did is provided, but no verkey', async () => {
    const result = await indyVdrIndyDidRegistrar.create(agentContext, {
      did: 'BzCbsNYhMrjHiqZDTUASHg',
      options: {
        endorserMode: 'internal',
        endorserDid: 'did:indy:pool1:BzCbsNYhMrjHiqZDTUASHg',
        alias: 'Hello',
      },
    })

    expect(JsonTransformer.toJSON(result)).toMatchObject({
      didDocumentMetadata: {},
      didRegistrationMetadata: {},
      didState: {
        state: 'failed',
        reason: 'If a did is defined, a matching verkey must be provided',
      },
    })
  })

  test('returns an error state if did and verkey are provided, but the did is not self certifying', async () => {
    const result = await indyVdrIndyDidRegistrar.create(agentContext, {
      did: 'did:indy:pool1:BzCbsNYhMrjHiqZDTUASHg',
      options: {
        endorserMode: 'internal',
        endorserDid: 'did:indy:pool1:BzCbsNYhMrjHiqZDTUASHg',
        verkey: 'verkey',
        alias: 'Hello',
      },
    })

    expect(JsonTransformer.toJSON(result)).toMatchObject({
      didDocumentMetadata: {},
      didRegistrationMetadata: {},
      didState: {
        state: 'failed',
        reason: 'Initial verkey verkey does not match did did:indy:pool1:BzCbsNYhMrjHiqZDTUASHg',
      },
    })
  })

  test('returns an error state if did is provided, but does not match with the namespace from the endorserDid', async () => {
    const result = await indyVdrIndyDidRegistrar.create(agentContext, {
      did: 'did:indy:pool2:B6xaJg1c2xU3D9ppCtt1CZ',
      options: {
        endorserMode: 'internal',
        endorserDid: 'did:indy:pool1:BzCbsNYhMrjHiqZDTUASHg',
        verkey: 'E6D1m3eERqCueX4ZgMCY14B4NceAr6XP2HyVqt55gDhu',
        alias: 'Hello',
      },
    })

    expect(JsonTransformer.toJSON(result)).toMatchObject({
      didDocumentMetadata: {},
      didRegistrationMetadata: {},
      didState: {
        state: 'failed',
        reason:
          "The endorser did uses namespace: 'pool1' and the did to register uses namespace: 'pool2'. Namespaces must match.",
      },
    })
  })

  test('creates a did:indy document without services', async () => {
    const privateKey = TypedArrayEncoder.fromString('96213c3d7fc8d4d6754c712fd969598e')

    // @ts-ignore - method is private
    const createRegisterDidWriteRequest = jest.spyOn<undefined, undefined>(
      indyVdrIndyDidRegistrar,
      'createRegisterDidWriteRequest'
    )
    // @ts-ignore type check fails because method is private
    createRegisterDidWriteRequest.mockImplementationOnce(() => Promise.resolve())

    // @ts-ignore - method is private
    const registerPublicDidSpy = jest.spyOn<undefined, undefined>(indyVdrIndyDidRegistrar, 'registerPublicDid')
    // @ts-ignore type check fails because method is private
    registerPublicDidSpy.mockImplementationOnce(() => Promise.resolve())

    const result = await indyVdrIndyDidRegistrar.create(agentContext, {
      method: 'indy',
      options: {
        alias: 'Hello',
        endorserMode: 'internal',
        endorserDid: 'did:indy:pool1:BzCbsNYhMrjHiqZDTUASHg',
        role: 'STEWARD',
      },
      secret: {
        privateKey,
      },
    })

    expect(createRegisterDidWriteRequest).toHaveBeenCalledWith({
      agentContext,
      pool: poolMock,
      signingKey: expect.any(Key),
      submitterNamespaceIdentifier: 'BzCbsNYhMrjHiqZDTUASHg',
      namespaceIdentifier: 'B6xaJg1c2xU3D9ppCtt1CZ',
      verificationKey: expect.any(Key),
      alias: 'Hello',
      diddocContent: undefined,
      role: 'STEWARD',
    })

    expect(registerPublicDidSpy).toHaveBeenCalledWith(agentContext, poolMock, undefined)
    expect(JsonTransformer.toJSON(result)).toMatchObject({
      didDocumentMetadata: {},
      didRegistrationMetadata: {},
      didState: {
        state: 'finished',
        did: 'did:indy:pool1:B6xaJg1c2xU3D9ppCtt1CZ',
        didDocument: {
          '@context': ['https://w3id.org/did/v1', 'https://w3id.org/security/suites/ed25519-2018/v1'],
          id: 'did:indy:pool1:B6xaJg1c2xU3D9ppCtt1CZ',
          verificationMethod: [
            {
              id: 'did:indy:pool1:B6xaJg1c2xU3D9ppCtt1CZ#verkey',
              type: 'Ed25519VerificationKey2018',
              controller: 'did:indy:pool1:B6xaJg1c2xU3D9ppCtt1CZ',
              publicKeyBase58: 'E6D1m3eERqCueX4ZgMCY14B4NceAr6XP2HyVqt55gDhu',
            },
          ],
          authentication: ['did:indy:pool1:B6xaJg1c2xU3D9ppCtt1CZ#verkey'],
          assertionMethod: undefined,
          keyAgreement: undefined,
        },
        secret: {
          privateKey,
        },
      },
    })
  })

  test('creates a did:indy document by passing did', async () => {
    // @ts-ignore - method is private
    const createRegisterDidWriteRequest = jest.spyOn<undefined, undefined>(
      indyVdrIndyDidRegistrar,
      'createRegisterDidWriteRequest'
    )
    // @ts-ignore type check fails because method is private
    createRegisterDidWriteRequest.mockImplementationOnce(() => Promise.resolve())

    // @ts-ignore - method is private
    const registerPublicDidSpy = jest.spyOn<undefined, undefined>(indyVdrIndyDidRegistrar, 'registerPublicDid')
    // @ts-ignore type check fails because method is private
    registerPublicDidSpy.mockImplementationOnce(() => Promise.resolve())

    const result = await indyVdrIndyDidRegistrar.create(agentContext, {
      did: 'did:indy:pool1:B6xaJg1c2xU3D9ppCtt1CZ',
      options: {
        verkey: 'E6D1m3eERqCueX4ZgMCY14B4NceAr6XP2HyVqt55gDhu',
        alias: 'Hello',
        endorserMode: 'internal',
        endorserDid: 'did:indy:pool1:BzCbsNYhMrjHiqZDTUASHg',
        role: 'STEWARD',
      },
      secret: {},
    })

    expect(createRegisterDidWriteRequest).toHaveBeenCalledWith({
      agentContext,
      pool: poolMock,
      signingKey: expect.any(Key),
      submitterNamespaceIdentifier: 'BzCbsNYhMrjHiqZDTUASHg',
      namespaceIdentifier: 'B6xaJg1c2xU3D9ppCtt1CZ',
      verificationKey: expect.any(Key),
      alias: 'Hello',
      diddocContent: undefined,
      role: 'STEWARD',
    })

    expect(registerPublicDidSpy).toHaveBeenCalledWith(
      agentContext,
      poolMock,
      // writeRequest
      undefined
    )
    expect(JsonTransformer.toJSON(result)).toMatchObject({
      didDocumentMetadata: {},
      didRegistrationMetadata: {},
      didState: {
        state: 'finished',
        did: 'did:indy:pool1:B6xaJg1c2xU3D9ppCtt1CZ',
        didDocument: {
          '@context': ['https://w3id.org/did/v1', 'https://w3id.org/security/suites/ed25519-2018/v1'],
          id: 'did:indy:pool1:B6xaJg1c2xU3D9ppCtt1CZ',
          verificationMethod: [
            {
              id: 'did:indy:pool1:B6xaJg1c2xU3D9ppCtt1CZ#verkey',
              type: 'Ed25519VerificationKey2018',
              controller: 'did:indy:pool1:B6xaJg1c2xU3D9ppCtt1CZ',
              publicKeyBase58: 'E6D1m3eERqCueX4ZgMCY14B4NceAr6XP2HyVqt55gDhu',
            },
          ],
          authentication: ['did:indy:pool1:B6xaJg1c2xU3D9ppCtt1CZ#verkey'],
          assertionMethod: undefined,
          keyAgreement: undefined,
        },
        secret: {},
      },
    })
  })

  test('creates a did:indy document with services using diddocContent', async () => {
    const privateKey = TypedArrayEncoder.fromString('96213c3d7fc8d4d6754c712fd969598e')

    // @ts-ignore - method is private
    const createRegisterDidWriteRequestSpy = jest.spyOn<undefined, undefined>(
      indyVdrIndyDidRegistrar,
      'createRegisterDidWriteRequest'
    )
    // @ts-ignore type check fails because method is private
    createRegisterDidWriteRequestSpy.mockImplementationOnce(() => Promise.resolve())

    // @ts-ignore - method is private
    const registerPublicDidSpy = jest.spyOn<undefined, undefined>(indyVdrIndyDidRegistrar, 'registerPublicDid')
    // @ts-ignore type check fails because method is private
    registerPublicDidSpy.mockImplementationOnce(() => Promise.resolve())

    // @ts-ignore - method is private
    const setEndpointsForDidSpy = jest.spyOn<undefined, undefined>(indyVdrIndyDidRegistrar, 'setEndpointsForDid')

    const result = await indyVdrIndyDidRegistrar.create(agentContext, {
      method: 'indy',
      options: {
        alias: 'Hello',
        endorserMode: 'internal',
        endorserDid: 'did:indy:pool1:BzCbsNYhMrjHiqZDTUASHg',
        role: 'STEWARD',
        services: [
          new DidDocumentService({
            id: `#endpoint`,
            serviceEndpoint: 'https://example.com/endpoint',
            type: 'endpoint',
          }),
          new DidCommV1Service({
            id: `#did-communication`,
            priority: 0,
            recipientKeys: [`#key-agreement-1`],
            routingKeys: ['key-1'],
            serviceEndpoint: 'https://example.com/endpoint',
            accept: ['didcomm/aip2;env=rfc19'],
          }),
          new DidCommV2Service({
            accept: ['didcomm/v2'],
            id: `#didcomm-1`,
            routingKeys: ['key-1'],
            serviceEndpoint: 'https://example.com/endpoint',
          }),
        ],
      },
      secret: {
        privateKey,
      },
    })

    expect(createRegisterDidWriteRequestSpy).toHaveBeenCalledWith({
      agentContext,
      pool: poolMock,
      signingKey: expect.any(Key),
      submitterNamespaceIdentifier: 'BzCbsNYhMrjHiqZDTUASHg',
      namespaceIdentifier: 'B6xaJg1c2xU3D9ppCtt1CZ',
      verificationKey: expect.any(Key),
      alias: 'Hello',
      role: 'STEWARD',
      diddocContent: {
        '@context': [],
        authentication: [],
        id: 'did:indy:pool1:B6xaJg1c2xU3D9ppCtt1CZ',
        keyAgreement: ['did:indy:pool1:B6xaJg1c2xU3D9ppCtt1CZ#key-agreement-1'],
        service: [
          {
            id: 'did:indy:pool1:B6xaJg1c2xU3D9ppCtt1CZ#endpoint',
            serviceEndpoint: 'https://example.com/endpoint',
            type: 'endpoint',
          },
          {
            accept: ['didcomm/aip2;env=rfc19'],
            id: 'did:indy:pool1:B6xaJg1c2xU3D9ppCtt1CZ#did-communication',
            priority: 0,
            recipientKeys: ['did:indy:pool1:B6xaJg1c2xU3D9ppCtt1CZ#key-agreement-1'],
            routingKeys: ['key-1'],
            serviceEndpoint: 'https://example.com/endpoint',
            type: 'did-communication',
          },
          {
            accept: ['didcomm/v2'],
            id: 'did:indy:pool1:B6xaJg1c2xU3D9ppCtt1CZ#didcomm-1',
            routingKeys: ['key-1'],
            serviceEndpoint: 'https://example.com/endpoint',
            type: 'DIDComm',
          },
        ],
        verificationMethod: [
          {
            controller: 'did:indy:pool1:B6xaJg1c2xU3D9ppCtt1CZ',
            id: 'did:indy:pool1:B6xaJg1c2xU3D9ppCtt1CZ#key-agreement-1',
            publicKeyBase58: 'Fbv17ZbnUSbafsiUBJbdGeC62M8v8GEscVMMcE59mRPt',
            type: 'X25519KeyAgreementKey2019',
          },
        ],
      },
    })

    expect(registerPublicDidSpy).toHaveBeenCalledWith(
      agentContext,
      poolMock,
      // writeRequest
      undefined
    )
    expect(setEndpointsForDidSpy).not.toHaveBeenCalled()
    expect(JsonTransformer.toJSON(result)).toMatchObject({
      didDocumentMetadata: {},
      didRegistrationMetadata: {},
      didState: {
        state: 'finished',
        did: 'did:indy:pool1:B6xaJg1c2xU3D9ppCtt1CZ',
        didDocument: {
          '@context': [
            'https://w3id.org/did/v1',
            'https://w3id.org/security/suites/ed25519-2018/v1',
            'https://w3id.org/security/suites/x25519-2019/v1',
            'https://didcomm.org/messaging/contexts/v2',
          ],
          id: 'did:indy:pool1:B6xaJg1c2xU3D9ppCtt1CZ',
          verificationMethod: [
            {
              id: 'did:indy:pool1:B6xaJg1c2xU3D9ppCtt1CZ#verkey',
              type: 'Ed25519VerificationKey2018',
              controller: 'did:indy:pool1:B6xaJg1c2xU3D9ppCtt1CZ',
              publicKeyBase58: 'E6D1m3eERqCueX4ZgMCY14B4NceAr6XP2HyVqt55gDhu',
            },
            {
              id: 'did:indy:pool1:B6xaJg1c2xU3D9ppCtt1CZ#key-agreement-1',
              type: 'X25519KeyAgreementKey2019',
              controller: 'did:indy:pool1:B6xaJg1c2xU3D9ppCtt1CZ',
              publicKeyBase58: 'Fbv17ZbnUSbafsiUBJbdGeC62M8v8GEscVMMcE59mRPt',
            },
          ],
          service: [
            {
              id: 'did:indy:pool1:B6xaJg1c2xU3D9ppCtt1CZ#endpoint',
              serviceEndpoint: 'https://example.com/endpoint',
              type: 'endpoint',
            },
            {
              id: 'did:indy:pool1:B6xaJg1c2xU3D9ppCtt1CZ#did-communication',
              serviceEndpoint: 'https://example.com/endpoint',
              type: 'did-communication',
              priority: 0,
              recipientKeys: ['did:indy:pool1:B6xaJg1c2xU3D9ppCtt1CZ#key-agreement-1'],
              routingKeys: ['key-1'],
              accept: ['didcomm/aip2;env=rfc19'],
            },
            {
              id: 'did:indy:pool1:B6xaJg1c2xU3D9ppCtt1CZ#didcomm-1',
              serviceEndpoint: 'https://example.com/endpoint',
              type: 'DIDComm',
              routingKeys: ['key-1'],
              accept: ['didcomm/v2'],
            },
          ],
          authentication: ['did:indy:pool1:B6xaJg1c2xU3D9ppCtt1CZ#verkey'],
          assertionMethod: undefined,
          keyAgreement: ['did:indy:pool1:B6xaJg1c2xU3D9ppCtt1CZ#key-agreement-1'],
        },
        secret: {
          privateKey,
        },
      },
    })
  })

  test('creates a did:indy document with services using attrib', async () => {
    const privateKey = TypedArrayEncoder.fromString('96213c3d7fc8d4d6754c712fd969598e')

    // @ts-ignore - method is private
    const createRegisterDidWriteRequestSpy = jest.spyOn<undefined, undefined>(
      indyVdrIndyDidRegistrar,
      'createRegisterDidWriteRequest'
    )
    // @ts-ignore type check fails because method is private
    createRegisterDidWriteRequestSpy.mockImplementationOnce(() => Promise.resolve())

    // @ts-ignore - method is private
    const registerPublicDidSpy = jest.spyOn<undefined, undefined>(indyVdrIndyDidRegistrar, 'registerPublicDid')
    // @ts-ignore type check fails because method is private
    registerPublicDidSpy.mockImplementationOnce(() => Promise.resolve())

    // @ts-ignore - method is private
    const createSetDidEndpointsRequestSpy = jest.spyOn<undefined, undefined>(
      indyVdrIndyDidRegistrar,
      'createSetDidEndpointsRequest'
    )
    // @ts-ignore type check fails because method is private
    createSetDidEndpointsRequestSpy.mockImplementationOnce(() => Promise.resolve(undefined))

    // @ts-ignore - method is private
    const setEndpointsForDidSpy = jest.spyOn<undefined, undefined>(indyVdrIndyDidRegistrar, 'setEndpointsForDid')
    // @ts-ignore type check fails because method is private
    setEndpointsForDidSpy.mockImplementationOnce(() => Promise.resolve(undefined))

    const result = await indyVdrIndyDidRegistrar.create(agentContext, {
      method: 'indy',
      options: {
        alias: 'Hello',
        endorserMode: 'internal',
        endorserDid: 'did:indy:pool1:BzCbsNYhMrjHiqZDTUASHg',
        role: 'STEWARD',
        useEndpointAttrib: true,
        services: [
          new DidDocumentService({
            id: `#endpoint`,
            serviceEndpoint: 'https://example.com/endpoint',
            type: 'endpoint',
          }),
          new DidCommV1Service({
            id: `#did-communication`,
            priority: 0,
            recipientKeys: [`#key-agreement-1`],
            routingKeys: ['key-1'],
            serviceEndpoint: 'https://example.com/endpoint',
            accept: ['didcomm/aip2;env=rfc19'],
          }),
          new DidCommV2Service({
            accept: ['didcomm/v2'],
            id: `#didcomm-1`,
            routingKeys: ['key-1'],
            serviceEndpoint: 'https://example.com/endpoint',
          }),
        ],
      },
      secret: {
        privateKey,
      },
    })

    expect(createRegisterDidWriteRequestSpy).toHaveBeenCalledWith({
      agentContext,
      pool: poolMock,
      signingKey: expect.any(Key),
      submitterNamespaceIdentifier: 'BzCbsNYhMrjHiqZDTUASHg',
      namespaceIdentifier: 'B6xaJg1c2xU3D9ppCtt1CZ',
      verificationKey: expect.any(Key),
      alias: 'Hello',
      diddocContent: undefined,
      role: 'STEWARD',
    })

    expect(registerPublicDidSpy).toHaveBeenCalledWith(
      agentContext,
      poolMock,
      // writeRequest
      undefined
    )
    expect(createSetDidEndpointsRequestSpy).toHaveBeenCalledWith({
      agentContext,
      pool: poolMock,
      signingKey: expect.any(Key),
      endorserDid: undefined,
      // Unqualified created indy did
      unqualifiedDid: 'B6xaJg1c2xU3D9ppCtt1CZ',
      endpoints: {
        endpoint: 'https://example.com/endpoint',
        routingKeys: ['key-1'],
        types: ['endpoint', 'did-communication', 'DIDComm'],
      },
    })
    expect(setEndpointsForDidSpy).not.toHaveBeenCalled()
    expect(JsonTransformer.toJSON(result)).toMatchObject({
      didDocumentMetadata: {},
      didRegistrationMetadata: {},
      didState: {
        state: 'finished',
        did: 'did:indy:pool1:B6xaJg1c2xU3D9ppCtt1CZ',
        didDocument: {
          '@context': [
            'https://w3id.org/did/v1',
            'https://w3id.org/security/suites/ed25519-2018/v1',
            'https://w3id.org/security/suites/x25519-2019/v1',
            'https://didcomm.org/messaging/contexts/v2',
          ],
          id: 'did:indy:pool1:B6xaJg1c2xU3D9ppCtt1CZ',
          verificationMethod: [
            {
              id: 'did:indy:pool1:B6xaJg1c2xU3D9ppCtt1CZ#verkey',
              type: 'Ed25519VerificationKey2018',
              controller: 'did:indy:pool1:B6xaJg1c2xU3D9ppCtt1CZ',
              publicKeyBase58: 'E6D1m3eERqCueX4ZgMCY14B4NceAr6XP2HyVqt55gDhu',
            },
            {
              id: 'did:indy:pool1:B6xaJg1c2xU3D9ppCtt1CZ#key-agreement-1',
              type: 'X25519KeyAgreementKey2019',
              controller: 'did:indy:pool1:B6xaJg1c2xU3D9ppCtt1CZ',
              publicKeyBase58: 'Fbv17ZbnUSbafsiUBJbdGeC62M8v8GEscVMMcE59mRPt',
            },
          ],
          service: [
            {
              id: 'did:indy:pool1:B6xaJg1c2xU3D9ppCtt1CZ#endpoint',
              serviceEndpoint: 'https://example.com/endpoint',
              type: 'endpoint',
            },
            {
              id: 'did:indy:pool1:B6xaJg1c2xU3D9ppCtt1CZ#did-communication',
              serviceEndpoint: 'https://example.com/endpoint',
              type: 'did-communication',
              priority: 0,
              recipientKeys: ['did:indy:pool1:B6xaJg1c2xU3D9ppCtt1CZ#key-agreement-1'],
              routingKeys: ['key-1'],
              accept: ['didcomm/aip2;env=rfc19'],
            },
            {
              id: 'did:indy:pool1:B6xaJg1c2xU3D9ppCtt1CZ#didcomm-1',
              serviceEndpoint: 'https://example.com/endpoint',
              type: 'DIDComm',
              routingKeys: ['key-1'],
              accept: ['didcomm/v2'],
            },
          ],
          authentication: ['did:indy:pool1:B6xaJg1c2xU3D9ppCtt1CZ#verkey'],
          assertionMethod: undefined,
          keyAgreement: ['did:indy:pool1:B6xaJg1c2xU3D9ppCtt1CZ#key-agreement-1'],
        },
        secret: {
          privateKey,
        },
      },
    })
  })

  test('stores the did document', async () => {
    const privateKey = TypedArrayEncoder.fromString('96213c3d7fc8d4d6754c712fd969598e')

    // @ts-ignore - method is private
    const createRegisterDidWriteRequestSpy = jest.spyOn<undefined, undefined>(
      indyVdrIndyDidRegistrar,
      'createRegisterDidWriteRequest'
    )
    // @ts-ignore type check fails because method is private
    createRegisterDidWriteRequestSpy.mockImplementationOnce(() => Promise.resolve())

    // @ts-ignore - method is private
    const registerPublicDidSpy = jest.spyOn<undefined, undefined>(indyVdrIndyDidRegistrar, 'registerPublicDid')
    // @ts-ignore type check fails because method is private
    registerPublicDidSpy.mockImplementationOnce(() => Promise.resolve())

    // @ts-ignore - method is private
    const setEndpointsForDidSpy = jest.spyOn<undefined, undefined>(indyVdrIndyDidRegistrar, 'setEndpointsForDid')
    // @ts-ignore type check fails because method is private
    setEndpointsForDidSpy.mockImplementationOnce(() => Promise.resolve(undefined))

    const saveCalled = jest.fn()
    eventEmitter.on<RecordSavedEvent<DidRecord>>(RepositoryEventTypes.RecordSaved, saveCalled)

    await indyVdrIndyDidRegistrar.create(agentContext, {
      method: 'indy',
      options: {
        alias: 'Hello',
        endorserMode: 'internal',
        endorserDid: 'did:indy:pool1:BzCbsNYhMrjHiqZDTUASHg',
        role: 'STEWARD',
        services: [
          new DidDocumentService({
            id: `#endpoint`,
            serviceEndpoint: 'https://example.com/endpoint',
            type: 'endpoint',
          }),
          new DidCommV1Service({
            id: `#did-communication`,
            priority: 0,
            recipientKeys: [`#key-agreement-1`],
            routingKeys: ['key-1'],
            serviceEndpoint: 'https://example.com/endpoint',
            accept: ['didcomm/aip2;env=rfc19'],
          }),
          new DidCommV2Service({
            accept: ['didcomm/v2'],
            id: `#didcomm-1`,
            routingKeys: ['key-1'],
            serviceEndpoint: 'https://example.com/endpoint',
          }),
        ],
      },
      secret: {
        privateKey,
      },
    })

    expect(saveCalled).toHaveBeenCalledTimes(1)
    const [saveEvent] = saveCalled.mock.calls[0]

    expect(saveEvent.payload.record.getTags()).toMatchObject({
      recipientKeyFingerprints: ['z6LSrH6AdsQeZuKKmG6Ehx7abEQZsVg2psR2VU536gigUoAe'],
    })
    expect(saveEvent.payload.record).toMatchObject({
      did: 'did:indy:pool1:B6xaJg1c2xU3D9ppCtt1CZ',
      role: DidDocumentRole.Created,
      didDocument: expect.any(DidDocument),
    })
  })

  test('returns an error state when calling update', async () => {
    const result = await indyVdrIndyDidRegistrar.update()

    expect(result).toEqual({
      didDocumentMetadata: {},
      didRegistrationMetadata: {},
      didState: {
        state: 'failed',
        reason: `notImplemented: updating did:indy not implemented yet`,
      },
    })
  })

  test('returns an error state when calling deactivate', async () => {
    const result = await indyVdrIndyDidRegistrar.deactivate()

    expect(result).toEqual({
      didDocumentMetadata: {},
      didRegistrationMetadata: {},
      didState: {
        state: 'failed',
        reason: `notImplemented: deactivating did:indy not implemented yet`,
      },
    })
  })
})
