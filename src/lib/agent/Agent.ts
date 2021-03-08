import type Indy from 'indy-sdk';
import logger from '../logger';
import { InitConfig } from '../types';
import { IndyWallet } from '../wallet/IndyWallet';
import { MessageReceiver } from './MessageReceiver';
import { EnvelopeService } from './EnvelopeService';
import { ConnectionService, TrustPingService, ConnectionRecord } from '../modules/connections';
import { CredentialService, CredentialRecord } from '../modules/credentials';
import { ProofService, ProofRecord } from '../modules/proofs';
import {
  ConsumerRoutingService,
  ProviderRoutingService,
  MessagePickupService,
  ProvisioningService,
  ProvisioningRecord,
} from '../modules/routing';
import { BasicMessageService, BasicMessageRecord } from '../modules/basic-messages';
import { LedgerService } from '../modules/ledger';
import { Dispatcher } from './Dispatcher';
import { MessageSender } from './MessageSender';
import { InboundTransporter } from '../transport/InboundTransporter';
import { OutboundTransporter } from '../transport/OutboundTransporter';
import { MessageRepository } from '../storage/MessageRepository';
import { Repository } from '../storage/Repository';
import { IndyStorageService } from '../storage/IndyStorageService';
import { AgentConfig } from './AgentConfig';
import { Wallet } from '../wallet/Wallet';
import { ConnectionsModule } from '../modules/connections/ConnectionsModule';
import { CredentialsModule } from '../modules/credentials/CredentialsModule';
import { ProofsModule } from '../modules/proofs/ProofsModule';
import { RoutingModule } from '../modules/routing/RoutingModule';
import { BasicMessagesModule } from '../modules/basic-messages/BasicMessagesModule';
import { LedgerModule } from '../modules/ledger/LedgerModule';

export class Agent {
  protected wallet: Wallet;
  protected agentConfig: AgentConfig;
  protected messageReceiver: MessageReceiver;
  protected dispatcher: Dispatcher;
  protected messageSender: MessageSender;
  protected connectionService: ConnectionService;
  protected proofService: ProofService;
  protected basicMessageService: BasicMessageService;
  protected providerRoutingService: ProviderRoutingService;
  protected consumerRoutingService: ConsumerRoutingService;
  protected trustPingService: TrustPingService;
  protected messagePickupService: MessagePickupService;
  protected provisioningService: ProvisioningService;
  protected ledgerService: LedgerService;
  protected credentialService: CredentialService;
  protected basicMessageRepository: Repository<BasicMessageRecord>;
  protected connectionRepository: Repository<ConnectionRecord>;
  protected provisioningRepository: Repository<ProvisioningRecord>;
  protected credentialRepository: Repository<CredentialRecord>;
  protected proofRepository: Repository<ProofRecord>;
  protected indy: typeof Indy;

  public inboundTransporter: InboundTransporter;

  public connections!: ConnectionsModule;
  public proofs!: ProofsModule;
  public routing!: RoutingModule;
  public basicMessages!: BasicMessagesModule;
  public ledger!: LedgerModule;
  public credentials!: CredentialsModule;

  public constructor(
    initialConfig: InitConfig,
    inboundTransporter: InboundTransporter,
    outboundTransporter: OutboundTransporter,
    indy: typeof Indy,
    messageRepository?: MessageRepository
  ) {
    logger.logJson('Creating agent with config', initialConfig);
    this.wallet = new IndyWallet(initialConfig.walletConfig, initialConfig.walletCredentials, indy);
    const envelopeService = new EnvelopeService(this.wallet);

    this.indy = indy;

    this.agentConfig = new AgentConfig(initialConfig);
    this.messageSender = new MessageSender(envelopeService, outboundTransporter);
    this.dispatcher = new Dispatcher(this.messageSender);
    this.inboundTransporter = inboundTransporter;

    const storageService = new IndyStorageService(this.wallet);
    this.basicMessageRepository = new Repository<BasicMessageRecord>(BasicMessageRecord, storageService);
    this.connectionRepository = new Repository<ConnectionRecord>(ConnectionRecord, storageService);
    this.provisioningRepository = new Repository<ProvisioningRecord>(ProvisioningRecord, storageService);
    this.credentialRepository = new Repository<CredentialRecord>(CredentialRecord, storageService);
    this.proofRepository = new Repository<ProofRecord>(ProofRecord, storageService);
    this.provisioningService = new ProvisioningService(this.provisioningRepository);
    this.connectionService = new ConnectionService(this.wallet, this.agentConfig, this.connectionRepository);
    this.basicMessageService = new BasicMessageService(this.basicMessageRepository);
    this.providerRoutingService = new ProviderRoutingService();
    this.consumerRoutingService = new ConsumerRoutingService(this.messageSender, this.agentConfig);
    this.trustPingService = new TrustPingService();
    this.messagePickupService = new MessagePickupService(messageRepository);
    this.ledgerService = new LedgerService(this.wallet, indy);
    this.credentialService = new CredentialService(
      this.wallet,
      this.credentialRepository,
      this.connectionService,
      this.ledgerService
    );
    this.proofService = new ProofService(this.proofRepository, this.ledgerService, this.wallet, indy);

    this.messageReceiver = new MessageReceiver(
      this.agentConfig,
      envelopeService,
      this.connectionService,
      this.dispatcher
    );

    this.registerModules();
  }

  public async init() {
    await this.wallet.init();

    const { publicDidSeed, genesisPath, poolName } = this.agentConfig;
    if (publicDidSeed) {
      // If an agent has publicDid it will be used as routing key.
      await this.wallet.initPublicDid({ seed: publicDidSeed });
    }

    // If the genesisPath is provided in the config, we will automatically handle ledger connection
    // otherwise the framework consumer needs to do this manually
    if (genesisPath) {
      await this.ledger.connect(poolName, {
        genesis_txn: genesisPath,
      });
    }

    return this.inboundTransporter.start(this);
  }

  public get publicDid() {
    return this.wallet.publicDid;
  }

  public getMediatorUrl() {
    return this.agentConfig.mediatorUrl;
  }

  public async receiveMessage(inboundPackedMessage: unknown) {
    return await this.messageReceiver.receiveMessage(inboundPackedMessage);
  }

  public async closeAndDeleteWallet() {
    await this.wallet.close();
    await this.wallet.delete();
  }

  protected registerModules() {
    this.connections = new ConnectionsModule(
      this.dispatcher,
      this.agentConfig,
      this.connectionService,
      this.trustPingService,
      this.consumerRoutingService,
      this.messageSender
    );

    this.credentials = new CredentialsModule(
      this.dispatcher,
      this.connectionService,
      this.credentialService,
      this.messageSender
    );

    this.proofs = new ProofsModule(this.dispatcher, this.proofService, this.connectionService, this.messageSender);

    this.routing = new RoutingModule(
      this.dispatcher,
      this.agentConfig,
      this.providerRoutingService,
      this.provisioningService,
      this.messagePickupService,
      this.connectionService,
      this.messageSender
    );

    this.basicMessages = new BasicMessagesModule(this.dispatcher, this.basicMessageService, this.messageSender);

    this.ledger = new LedgerModule(this.wallet, this.ledgerService);
  }
}
