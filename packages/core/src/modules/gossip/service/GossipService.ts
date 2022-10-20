import type { InboundMessageContext } from '../../../agent/models/InboundMessageContext'
import type { ValueTransferWitnessConfig } from '../../../types'
import type { ResumeValueTransferTransactionEvent, WitnessTableReceivedEvent } from '../../value-transfer'
import type { WitnessGossipMessage, WitnessTableQueryMessage } from '../messages'
import type { SqliteDriver } from '@mikro-orm/sqlite'
import type {
  GossipInterface,
  TransactionRecord,
  GossipStorageOrmRepository,
} from '@sicpa-dlab/witness-gossip-protocol-ts'

import { MikroORM } from '@mikro-orm/core'
import {
  makeOrmGossipStorage,
  WitnessGossipInfo,
  WitnessState,
  WitnessTableQuery,
  Gossip,
  initGossipSqlite,
  PartyStateHashEntity,
  WitnessDetailsEntity,
  WitnessMappingTableEntity,
  WitnessDetails,
  MappingTable,
} from '@sicpa-dlab/witness-gossip-protocol-ts'

import { AgentConfig } from '../../../agent/AgentConfig'
import { EventEmitter } from '../../../agent/EventEmitter'
import { AriesFrameworkError } from '../../../error'
import { injectable } from '../../../plugins'
import { DidMarker } from '../../dids/domain'
import { DidService } from '../../dids/services/DidService'
import { ValueTransferEventTypes } from '../../value-transfer/ValueTransferEvents'
import { WitnessTableMessage } from '../messages'
import { WitnessStateRecord, WitnessStateRepository } from '../repository'

import { GossipCryptoService } from './GossipCryptoService'
import { GossipLoggerService } from './GossipLoggerService'
import { WitnessGossipStateService } from './GossipStateService'
import { GossipTransportService } from './GossipTransportService'

@injectable()
export class GossipService implements GossipInterface {
  private gossip!: Gossip
  private gossipingStarted = false

  public constructor(
    private readonly config: AgentConfig,
    private readonly gossipCryptoService: GossipCryptoService,
    private readonly witnessGossipStateService: WitnessGossipStateService,
    private readonly gossipTransportService: GossipTransportService,
    private readonly gossipLoggerService: GossipLoggerService,
    private readonly witnessStateRepository: WitnessStateRepository,
    private readonly didService: DidService,
    private readonly eventEmitter: EventEmitter
  ) {}

  public getWitnessDetails(): Promise<WitnessDetails> {
    return this.gossip.getWitnessDetails()
  }

  public commitParticipantsTransition(giver: TransactionRecord, getter: TransactionRecord): Promise<void> {
    return this.gossip.commitParticipantsTransition(giver, getter)
  }

  public commitSingleParticipantTransition(transition: TransactionRecord): Promise<void> {
    return this.commitSingleParticipantTransition(transition)
  }

  public async init(dbConnectionString: string): Promise<void> {
    // const orm = await initGossipSqlite(dbConnectionString)

    const orm = await MikroORM.init<SqliteDriver>({
      debug: true,
      // entitiesTs: ['./src/data-access/entities'],
      // entities: ['./build/data-access/entities'],
      entities: [PartyStateHashEntity, WitnessDetailsEntity, WitnessMappingTableEntity],
      type: 'sqlite',
      dbName: dbConnectionString,
      schemaGenerator: {},
      // baseDir:
      //   '/Users/dmitry-vychikov/Projects/DSR/sicpa/aries-framework-javascript/emulator/node_modules/@sicpa-dlab/witness-gossip-protocol-ts',
    })

    const generator = orm.getSchemaGenerator()
    await generator.refreshDatabase()

    const storageV2 = makeOrmGossipStorage(orm).gossipStorage
    this.gossip = new Gossip(
      {
        logger: this.gossipLoggerService,
        crypto: this.gossipCryptoService,
        storage: this.witnessGossipStateService,
        storageV2: storageV2,
        transport: this.gossipTransportService,
        metrics: this.config.witnessGossipMetrics,
      },
      {
        label: this.config.label,
        tockTime: this.config.valueTransferConfig?.witness?.tockTime,
        cleanupTime: this.config.valueTransferConfig?.witness?.cleanupTime,
        redeliverTime: this.config.valueTransferConfig?.witness?.redeliverTime,
        historyThreshold: this.config.valueTransferConfig?.witness?.historyThreshold,
        redeliveryThreshold: this.config.valueTransferConfig?.witness?.redeliveryThreshold,
      }
    )

    await this.initState(storageV2)
    await this.startGossiping()
  }

  private async initState(gossipRepository: GossipStorageOrmRepository): Promise<void> {
    const config = this.config.valueWitnessConfig
    if (!config) throw new Error('Value transfer config is not available')

    await this.initAriesFrameworkState(config)
    await this.initGossipOrmState(config, gossipRepository)
  }

  private async initAriesFrameworkState(config: ValueTransferWitnessConfig): Promise<void> {
    this.config.logger.info('> initAriesFrameworkState started')
    const existingState = await this.witnessStateRepository.findSingleByQuery({})

    if (existingState) {
      this.config.logger.info('> initAriesFrameworkState: state already exists, returning...')
      return
    }

    const witnessState = new WitnessState({
      mappingTable: config.knownWitnesses,
    })
    const state = new WitnessStateRecord({
      witnessState,
    })
    await this.witnessStateRepository.save(state)

    this.config.logger.info('> initAriesFrameworkState completed successfull')
  }

  private async initGossipOrmState(
    config: ValueTransferWitnessConfig,
    gossipRepository: GossipStorageOrmRepository
  ): Promise<void> {
    this.config.logger.info('> initGossipOrmState')
    const existingOrmState = await gossipRepository.isInitialized()

    if (existingOrmState) {
      this.config.logger.info('> initGossipOrmState already exists, returning')
      return
    }

    const did = await this.didService.findStaticDid(DidMarker.Public)
    if (!did) {
      throw new AriesFrameworkError(
        'Witness public DID not found. Please set `Public` marker for static DID in the agent config.'
      )
    }

    if (!config || !config?.knownWitnesses.length) {
      throw new AriesFrameworkError('Witness table must be provided.')
    }

    const info = new WitnessDetails({ wid: config.wid, did: did.did })
    const mappingTable = new MappingTable(config.knownWitnesses)

    await gossipRepository.setMyInfo(info)
    await gossipRepository.setMappingTable(mappingTable)

    this.config.logger.info('< initGossipOrmState completed!')
  }

  private async startGossiping() {
    if (!this.gossipingStarted) await this.gossip.start()
    this.gossipingStarted = true
  }

  /**
   * Process a received {@link WitnessGossipMessage}.
   *   If it contains `tell` section - apply transaction updates
   *   If it contains `ask` section - return transaction updates handled since request time
   * */
  public async processWitnessGossipInfo(messageContext: InboundMessageContext<WitnessGossipMessage>): Promise<void> {
    const { message: witnessGossipMessage } = messageContext

    this.config.logger.info(
      `> Witness ${this.config.label}: process witness gossip info message from ${witnessGossipMessage.from}`
    )

    const witnessGossipInfo = new WitnessGossipInfo({ ...witnessGossipMessage })

    const operation = async () => {
      return this.gossip.processWitnessGossipInfo(witnessGossipInfo)
    }
    const { error } = await this.doSafeOperationWithWitnessSate(operation)
    if (error) {
      this.config.logger.info(`  < Witness ${this.config.label}: Unable to process transaction update. Error: ${error}`)
      return
    }

    if (witnessGossipMessage.body.tell && witnessGossipMessage.pthid) {
      // Resume VTP Transaction if exists -> this event will be caught in WitnessService
      this.eventEmitter.emit<ResumeValueTransferTransactionEvent>({
        type: ValueTransferEventTypes.ResumeTransaction,
        payload: {
          thid: witnessGossipMessage.pthid,
        },
      })
    }
  }

  public async checkPartyStateHash(hash: Uint8Array): Promise<Uint8Array | undefined> {
    return this.gossip.checkPartyStateHash(hash)
  }

  public async askTransactionUpdates(id?: string) {
    return this.gossip.askTransactionUpdates(id)
  }

  public async processWitnessTableQuery(messageContext: InboundMessageContext<WitnessTableQueryMessage>): Promise<{
    message?: WitnessTableMessage
  }> {
    this.config.logger.info('> Witness process witness table query message')

    const { message: witnessTableQueryMessage } = messageContext

    const witnessTableQuery = new WitnessTableQuery(witnessTableQueryMessage)
    const { message, error } = await this.gossip.processWitnessTableQuery(witnessTableQuery)
    if (error || !message) {
      this.config.logger.error(`  Witness: Failed to process table query: ${error?.message}`)
      return {}
    }

    const witnessTableMessage = new WitnessTableMessage(message)

    this.config.logger.info('> Witness process witness table query message completed!')
    return { message: witnessTableMessage }
  }

  public async processWitnessTable(messageContext: InboundMessageContext<WitnessTableMessage>): Promise<void> {
    this.config.logger.info('> Witness process witness table message')

    const { message: witnessTable } = messageContext

    if (!witnessTable.from) {
      this.config.logger.info('   Unknown Witness Table sender')
      return
    }

    this.eventEmitter.emit<WitnessTableReceivedEvent>({
      type: ValueTransferEventTypes.WitnessTableReceived,
      payload: {
        witnesses: witnessTable.body.witnesses,
      },
    })
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  public async doSafeOperationWithWitnessSate(operation: () => Promise<any>): Promise<any> {
    // FIXME: `safeSateOperation` locks the whole WitnessState
    // I used it only for functions mutating the state to prevent concurrent updates
    // We need to discuss the list of read/write operations which should use this lock and how to do it properly
    return this.witnessGossipStateService.safeOperationWithWitnessState(operation.bind(this))
  }
}
