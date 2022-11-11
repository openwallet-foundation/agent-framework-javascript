import type { Logger } from '../../../logger'
import type { DIDInformation, DidDocument, DidProps } from '../../dids/domain'
import type { MediationRecord } from '../../routing/repository'
import type { DidMetadataChangedEvent, DidReceivedEvent } from '../DidEvents'
import type { DidTags } from '../repository'
import type { DIDMetadata } from '../types'

import { AgentConfig } from '../../../agent/AgentConfig'
import { EventEmitter } from '../../../agent/EventEmitter'
import { KeyType } from '../../../crypto'
import { AriesFrameworkError } from '../../../error'
import { injectable } from '../../../plugins'
import { KeyService } from '../../keys'
import { MediationRecipientService } from '../../routing/services/MediationRecipientService'
import { hasOnlineTransport, Transports } from '../../routing/types'
import { DidEventTypes } from '../DidEvents'
import { DidCommV2Service, DidDocumentBuilder, DidMarker, DidType, Key } from '../domain'
import { DidDocumentRole } from '../domain/DidDocumentRole'
import { getEd25519VerificationMethod } from '../domain/key-type/ed25519'
import { getX25519VerificationMethod } from '../domain/key-type/x25519'
import { PeerDid } from '../methods/peer/PeerDid'
import { PeerDidNumAlgo } from '../methods/peer/utils'
import { DidRecord, DidRepository } from '../repository'

import { DidResolverService } from './DidResolverService'

@injectable()
export class DidService {
  private agentConfig: AgentConfig
  private logger: Logger
  private keysService: KeyService
  private didRepository: DidRepository
  private didResolverService: DidResolverService
  private mediationRecipientService: MediationRecipientService
  private eventEmitter: EventEmitter

  public constructor(
    agentConfig: AgentConfig,
    keysService: KeyService,
    didRepository: DidRepository,
    didResolverService: DidResolverService,
    mediationRecipientService: MediationRecipientService,
    eventEmitter: EventEmitter
  ) {
    this.logger = agentConfig.logger
    this.agentConfig = agentConfig
    this.keysService = keysService
    this.didRepository = didRepository
    this.didResolverService = didResolverService
    this.mediationRecipientService = mediationRecipientService
    this.eventEmitter = eventEmitter
  }

  public async createDID(
    params: DidProps & {
      isStatic?: boolean
      transports?: Transports[]
    } = {}
  ): Promise<DidRecord> {
    const didType_ = params.type || DidType.PeerDid
    const needMediation = params.needMediation || params.needMediation === undefined

    this.logger.debug(`creating DID with type ${didType_}`)

    // restrict transports for offline if there is no internet connection
    const hasInternetAccess = await this.agentConfig.internetChecker.hasInternetAccess()
    const transports = params.transports
      ? params.transports
      : hasInternetAccess
      ? this.agentConfig.transports
      : this.agentConfig.offlineTransports

    // Generate keys
    const ed25519KeyPair = await this.keysService.createKey({ seed: params.seed })
    const ed25519Key = Key.fromPublicKey(ed25519KeyPair.publicKey, KeyType.Ed25519)

    const x25519KeyPair = await this.keysService.convertEd25519ToX25519Key({ keyPair: ed25519KeyPair })
    const x25519Key = Key.fromPublicKey(x25519KeyPair.publicKey, KeyType.X25519)

    // Create DIDDoc
    const { didPeer, mediator } = await this.prepareDIDDoc({
      needMediation,
      endpoint: params.endpoint,
      transports,
      ed25519Key,
      x25519Key,
    })

    await this.keysService.storeKey({
      keyPair: ed25519KeyPair,
      controller: didPeer.did,
      kid: ed25519Key.buildKeyId(didPeer.did),
      keyType: KeyType.Ed25519,
    })

    await this.keysService.storeKey({
      keyPair: x25519KeyPair,
      controller: didPeer.did,
      kid: x25519Key.buildKeyId(didPeer.did),
      keyType: KeyType.X25519,
    })

    if (hasOnlineTransport(transports) && needMediation && mediator) {
      await this.mediationRecipientService.getRouting(didPeer.did, { useDefaultMediator: true })
    }

    const didRecord = new DidRecord({
      id: didPeer.did,
      didDocument: didPeer.didDocument,
      role: DidDocumentRole.Created,
      isStatic: params.isStatic,
      didType: didType_,
      marker: params.marker,
    })

    await this.didRepository.save(didRecord)

    return didRecord
  }

  private async prepareDIDDoc(params: {
    needMediation?: boolean
    endpoint?: string
    transports: Transports[]
    ed25519Key: Key
    x25519Key: Key
  }): Promise<{ didPeer: PeerDid; mediator?: MediationRecord | null }> {
    let mediator: MediationRecord | null = null

    const didDocumentBuilder = new DidDocumentBuilder('')
      .addEd25519Context()
      .addX25519Context()
      .addAuthentication(getEd25519VerificationMethod({ controller: '', id: '', key: params.ed25519Key }))
      .addKeyAgreement(getX25519VerificationMethod({ controller: '', id: '', key: params.x25519Key }))

    if (params.transports.includes(Transports.HTTP) || params.transports.includes(Transports.HTTPS)) {
      if (params.endpoint) {
        didDocumentBuilder.addService(
          new DidCommV2Service({
            id: Transports.HTTP,
            serviceEndpoint: params.endpoint,
            routingKeys: [],
          })
        )
      } else if (params.needMediation) {
        mediator = await this.mediationRecipientService.findDefaultMediator()
        if (mediator && mediator.endpoint && params.needMediation) {
          didDocumentBuilder.addService(
            new DidCommV2Service({
              id: Transports.HTTP,
              serviceEndpoint: mediator.endpoint,
              routingKeys: mediator.routingKeys,
            })
          )
        }
      }
    }

    if (params.transports.includes(Transports.NFC)) {
      didDocumentBuilder.addService(new DidCommV2Service({ id: Transports.NFC, serviceEndpoint: Transports.NFC }))
    }

    if (params.transports.includes(Transports.Nearby)) {
      didDocumentBuilder.addService(
        new DidCommV2Service({
          id: Transports.Nearby,
          serviceEndpoint: Transports.Nearby,
        })
      )
    }

    const didDocument = didDocumentBuilder.build()
    const didPeer =
      didDocument.service && didDocument.service?.length > 0
        ? PeerDid.fromDidDocument(didDocument, PeerDidNumAlgo.MultipleInceptionKeyWithoutDoc)
        : PeerDid.fromKey(params.ed25519Key)

    return { didPeer, mediator }
  }

  public async getPublicDid() {
    // find for a public DID which is not marked
    const publicDid = await this.findStaticDid(DidMarker.Public)
    if (publicDid) return publicDid
  }

  public async getPublicDidOrCreateNew(usePublicDid?: boolean) {
    // find for public DID if requested
    if (usePublicDid) {
      const publicDid = await this.getPublicDid()
      if (publicDid) return publicDid
    }

    // create new DID
    return this.createDID()
  }

  public async getDIDDoc(did: string): Promise<DidDocument> {
    // resolve according to DID type
    const didDoc = await this.didResolverService.resolve(did)
    if (!didDoc.didDocument) {
      throw new AriesFrameworkError(`Unable to get DIDDoc for did: ${did}`)
    }
    return didDoc.didDocument
  }

  public async storeRemoteDid({ did, label, logoUrl }: DIDInformation) {
    const didDocument = await this.didResolverService.resolve(did)
    if (!didDocument.didDocument) {
      throw new AriesFrameworkError(`Unable to resolve DidDoc for the DID: ${did}`)
    }

    const existingRecord = await this.findById(did)
    if (existingRecord) {
      throw new AriesFrameworkError(`DID already exists: ${did}`)
    }

    const didRecord = new DidRecord({
      id: didDocument.didDocument.id,
      label: label,
      logoUrl: logoUrl,
      didDocument: didDocument.didDocument,
      role: DidDocumentRole.Received,
      didType: didDocument.didType,
    })

    await this.didRepository.save(didRecord)
    this.eventEmitter.emit<DidReceivedEvent>({
      type: DidEventTypes.DidReceived,
      payload: { record: didRecord },
    })
  }

  public async setDidMetadata(record: DidRecord, meta: DIDMetadata) {
    record.label = meta.label
    record.logoUrl = meta.logoUrl
    await this.didRepository.update(record)
    this.eventEmitter.emit<DidMetadataChangedEvent>({
      type: DidEventTypes.DidMetadataChanged,
      payload: { record: record },
    })
  }

  public async getDidMetadata(did: string): Promise<DIDMetadata> {
    const didRecord = await this.getById(did)
    return {
      label: didRecord.label,
      logoUrl: didRecord.logoUrl,
    }
  }

  public async getDidInfo(did: string): Promise<DIDInformation> {
    const didRecord = await this.findById(did)
    if (didRecord) {
      // did was stored before
      return {
        did: didRecord.did,
        didDocument: didRecord.didDocument,
        didType: didRecord.didType,
        connectivity: didRecord.didDocument?.connectivity,
        label: didRecord.label,
        logoUrl: didRecord.logoUrl,
      }
    }

    // resolve did information
    const resolvedDid = await this.didResolverService.resolve(did)
    if (!resolvedDid || !resolvedDid.didDocument) {
      throw new AriesFrameworkError(`Unable to resolve DIDDocument for did: ${did}`)
    }

    return {
      did: resolvedDid.didDocument?.id,
      didDocument: resolvedDid.didDocument,
      didType: resolvedDid.didType,
      connectivity: resolvedDid.didDocument?.connectivity,
      label: resolvedDid.didMeta?.label,
      logoUrl: resolvedDid.didMeta?.logoUrl,
    }
  }

  public async getAll(): Promise<DidRecord[]> {
    return this.didRepository.getAll()
  }

  public async getMyDIDs() {
    return this.didRepository.findByQuery({
      role: DidDocumentRole.Created,
    })
  }

  public async getReceivedDIDs() {
    return this.didRepository.findByQuery({
      role: DidDocumentRole.Received,
    })
  }

  public async findAllByQuery(query: Partial<DidTags>) {
    return this.didRepository.findByQuery(query)
  }

  public getById(recordId: string): Promise<DidRecord> {
    return this.didRepository.getById(recordId)
  }

  public findById(recordId: string): Promise<DidRecord | null> {
    return this.didRepository.findById(recordId)
  }

  public async deleteById(recordId: string) {
    return this.didRepository.deleteById(recordId)
  }

  public async findStaticDid(marker?: DidMarker) {
    const did = await this.didRepository.findByQuery({
      isStatic: true,
      marker: marker,
    })
    if (did.length) return did[0]
    return undefined
  }
}
