import type { AgentContext } from '../../../agent'
import type { Wallet } from '../../../wallet'

import { Subject } from 'rxjs'

import { InMemoryStorageService } from '../../../../../../tests/InMemoryStorageService'
import { InMemoryWallet } from '../../../../../../tests/InMemoryWallet'
import { getAgentConfig, getAgentContext } from '../../../../tests/helpers'
import { EventEmitter } from '../../../agent/EventEmitter'
import { InjectionSymbols } from '../../../constants'
import { Key, KeyType } from '../../../crypto'
import { JsonTransformer, TypedArrayEncoder } from '../../../utils'
import { DidsModuleConfig } from '../DidsModuleConfig'
import {
  DidCommV1Service,
  DidDocument,
  DidDocumentBuilder,
  convertPublicKeyToX25519,
  getEd25519VerificationKey2018,
  getX25519KeyAgreementKey2019,
} from '../domain'
import { DidDocumentRole } from '../domain/DidDocumentRole'
import { PeerDidResolver } from '../methods'
import { DidKey } from '../methods/key'
import { getNumAlgoFromPeerDid, PeerDidNumAlgo } from '../methods/peer/didPeer'
import { didDocumentJsonToNumAlgo1Did } from '../methods/peer/peerDidNumAlgo1'
import { DidRecord, DidRepository } from '../repository'
import { DidResolverService } from '../services'

import didPeer1zQmY from './__fixtures__/didPeer1zQmY.json'

describe('peer dids', () => {
  const config = getAgentConfig('Peer DIDs Lifecycle')

  let didRepository: DidRepository
  let didResolverService: DidResolverService
  let wallet: Wallet
  let agentContext: AgentContext
  let eventEmitter: EventEmitter

  beforeEach(async () => {
    wallet = new InMemoryWallet()
    const storageService = new InMemoryStorageService<DidRecord>()
    eventEmitter = new EventEmitter(config.agentDependencies, new Subject())
    didRepository = new DidRepository(storageService, eventEmitter)

    agentContext = getAgentContext({
      wallet,
      registerInstances: [
        [DidRepository, didRepository],
        [InjectionSymbols.StorageService, storageService],
      ],
    })
    await wallet.createAndOpen(config.walletConfig)

    didResolverService = new DidResolverService(
      config.logger,
      new DidsModuleConfig({ resolvers: [new PeerDidResolver()] }),
      {} as unknown as DidRepository
    )
  })

  afterEach(async () => {
    await wallet.delete()
  })

  test('create a peer did method 1 document from ed25519 keys with a service', async () => {
    // The following scenario show how we could create a key and create a did document from it for DID Exchange

    const ed25519Key = await wallet.createKey({
      privateKey: TypedArrayEncoder.fromString('astringoftotalin32characterslong'),
      keyType: KeyType.Ed25519,
    })
    const mediatorEd25519Key = await wallet.createKey({
      privateKey: TypedArrayEncoder.fromString('anotherstringof32characterslong1'),
      keyType: KeyType.Ed25519,
    })

    const x25519Key = Key.fromPublicKey(convertPublicKeyToX25519(ed25519Key.publicKey), KeyType.X25519)

    const ed25519VerificationMethod = getEd25519VerificationKey2018({
      // The id can either be the first 8 characters of the key data (for ed25519 it's publicKeyBase58)
      // uuid is easier as it is consistent between different key types. Normally you would dynamically
      // generate the uuid, but static for testing purposes
      id: `#d0d32199-851f-48e3-b178-6122bd4216a4`,
      key: ed25519Key,
      // For peer dids generated with method 1, the controller MUST be #id as we don't know the did yet
      controller: '#id',
    })
    const x25519VerificationMethod = getX25519KeyAgreementKey2019({
      // The id can either be the first 8 characters of the key data (for ed25519 it's publicKeyBase58)
      // uuid is easier as it is consistent between different key types. Normally you would dynamically
      // generate the uuid, but static for testing purposes
      id: `#08673492-3c44-47fe-baa4-a1780c585d75`,
      key: x25519Key,
      // For peer dids generated with method 1, the controller MUST be #id as we don't know the did yet
      controller: '#id',
    })

    const mediatorEd25519DidKey = new DidKey(mediatorEd25519Key)
    const mediatorX25519Key = Key.fromPublicKey(convertPublicKeyToX25519(mediatorEd25519Key.publicKey), KeyType.X25519)

    // Use ed25519 did:key, which also includes the x25519 key used for didcomm
    const mediatorRoutingKey = `${mediatorEd25519DidKey.did}#${mediatorX25519Key.fingerprint}`

    const service = new DidCommV1Service({
      id: '#service-0',
      // Fixme: can we use relative reference (#id) instead of absolute reference here (did:example:123#id)?
      // We don't know the did yet
      recipientKeys: [ed25519VerificationMethod.id],
      serviceEndpoint: 'https://example.com',
      accept: ['didcomm/aip2;env=rfc19'],
      // It is important that we encode the routing keys as key references.
      // So instead of using plain verkeys, we should encode them as did:key dids
      routingKeys: [mediatorRoutingKey],
    })

    const didDocument =
      // placeholder did, as it is generated from the did document
      new DidDocumentBuilder('')
        // ed25519 authentication method for signatures
        .addAuthentication(ed25519VerificationMethod)
        // x25519 for key agreement
        .addKeyAgreement(x25519VerificationMethod)
        .addService(service)
        .build()

    const didDocumentJson = didDocument.toJSON()
    const did = didDocumentJsonToNumAlgo1Did(didDocumentJson)

    expect(did).toBe(didPeer1zQmY.id)

    // Set did after generating it
    didDocument.id = did

    expect(didDocument.toJSON()).toMatchObject(didPeer1zQmY)

    // Save the record to storage
    const didDocumentRecord = new DidRecord({
      did: didPeer1zQmY.id,
      role: DidDocumentRole.Created,
      // It is important to take the did document from the PeerDid class
      // as it will have the id property
      didDocument: didDocument,
    })

    await didRepository.save(agentContext, didDocumentRecord)
  })

  test('receive a did and did document', async () => {
    // This flow assumes peer dids. When implementing for did exchange other did methods could be used

    // We receive the did and did document from the did exchange message (request or response)
    // It is important to not parse the did document to a DidDocument class yet as we need the raw json
    // to consistently verify the hash of the did document
    const did = didPeer1zQmY.id
    const numAlgo = getNumAlgoFromPeerDid(did)

    // Note that the did document could be undefined (if inlined did:peer or public did)
    const didDocument = JsonTransformer.fromJSON(didPeer1zQmY, DidDocument)

    // make sure the dids are valid by matching them against our encoded variants
    expect(didDocumentJsonToNumAlgo1Did(didPeer1zQmY)).toBe(did)

    // If a did document was provided, we match it against the did document of the peer did
    // This validates whether we get the same did document
    if (didDocument) {
      expect(didDocument.toJSON()).toMatchObject(didPeer1zQmY)
    }

    const didDocumentRecord = new DidRecord({
      did: did,
      role: DidDocumentRole.Received,
      // If the method is a genesis doc (did:peer:1) we should store the document
      // Otherwise we only need to store the did itself (as the did can be generated)
      didDocument: numAlgo === PeerDidNumAlgo.GenesisDoc ? didDocument : undefined,
      tags: {
        // We need to save the recipientKeys, so we can find the associated did
        // of a key when we receive a message from another connection.
        recipientKeyFingerprints: didDocument.recipientKeys.map((key) => key.fingerprint),
      },
    })

    await didRepository.save(agentContext, didDocumentRecord)

    // Then we save the did (not the did document) in the connection record
    // connectionRecord.theirDid = didPeer.did

    // Then when we want to send a message we can resolve the did document
    const { didDocument: resolvedDidDocument } = await didResolverService.resolve(agentContext, did)
    expect(resolvedDidDocument).toBeInstanceOf(DidDocument)
    expect(resolvedDidDocument?.toJSON()).toMatchObject(didPeer1zQmY)
  })
})
