import type { Module } from '../../plugins'

import { injectable } from 'tsyringe'

import { InMemoryWalletModule } from '../../../../../tests/InMemoryWalletModule'
import {
  BasicMessageRepository,
  BasicMessageService,
  ConnectionService,
  DidRotateService,
  TrustPingService,
  Dispatcher,
  EnvelopeService,
  FeatureRegistry,
  MessageReceiver,
  MessageSender,
} from '../../../../didcomm/src'
import { BasicMessagesApi } from '../../../../didcomm/src/modules/basic-messages/BasicMessagesApi'
import { ConnectionsApi, ConnectionRepository } from '../../../../didcomm/src/modules/connections'
import { CredentialRepository } from '../../../../didcomm/src/modules/credentials'
import { CredentialsApi } from '../../../../didcomm/src/modules/credentials/CredentialsApi'
import { MessagePickupApi, InMemoryMessagePickupRepository } from '../../../../didcomm/src/modules/message-pickup'
import { ProofsApi, ProofRepository } from '../../../../didcomm/src/modules/proofs'
import {
  MediationRecipientService,
  MediationRepository,
  MediatorApi,
  MediatorService,
  MediationRecipientApi,
  MediationRecipientModule,
} from '../../../../didcomm/src/modules/routing'
import { getDefaultDidcommModules } from '../../../../didcomm/src/util/modules'
import { getInMemoryAgentOptions } from '../../../tests/helpers'
import { InjectionSymbols } from '../../constants'
import { WalletError } from '../../wallet/error'
import { Agent } from '../Agent'

const agentOptions = getInMemoryAgentOptions('Agent Class Test')

const myModuleMethod = jest.fn()
@injectable()
class MyApi {
  public myModuleMethod = myModuleMethod
}

class MyModule implements Module {
  public api = MyApi
  public register() {
    // noop
  }
}

describe('Agent', () => {
  describe('Module registration', () => {
    test('does not return default modules on modules key if no modules were provided', () => {
      const agent = new Agent({
        ...agentOptions,
        modules: {
          inMemory: new InMemoryWalletModule(),
        },
      })

      expect(agent.modules).toEqual({})
    })
    test('registers custom and default modules if custom modules are provided', () => {
      const agent = new Agent({
        ...agentOptions,
        modules: {
          myModule: new MyModule(),
          inMemory: new InMemoryWalletModule(),
        },
      })

      expect(agent.modules.myModule.myModuleMethod).toBe(myModuleMethod)
      expect(agent.modules).toEqual({
        myModule: expect.any(MyApi),
      })
    })

    test('override default module configuration', () => {
      const agent = new Agent({
        ...agentOptions,
        modules: {
          ...getDefaultDidcommModules(),
          myModule: new MyModule(),
          mediationRecipient: new MediationRecipientModule({
            maximumMessagePickup: 42,
          }),
          inMemory: new InMemoryWalletModule(),
        },
      })

      // Should be custom module config property, not the default value
      expect(agent.modules.mediationRecipient.config.maximumMessagePickup).toBe(42)
      expect(agent.modules.myModule).toEqual(expect.any(MyApi))
    })
  })

  describe('Initialization', () => {
    let agent: Agent

    afterEach(async () => {
      const wallet = agent.context.wallet

      if (wallet.isInitialized) {
        await wallet.delete()
      }
    })

    it('isInitialized should only return true after initialization', async () => {
      expect.assertions(2)

      agent = new Agent(agentOptions)

      expect(agent.isInitialized).toBe(false)
      await agent.initialize()
      expect(agent.isInitialized).toBe(true)
    })

    it('wallet isInitialized should return true after agent initialization if wallet config is set in agent constructor', async () => {
      expect.assertions(4)

      agent = new Agent(agentOptions)
      const wallet = agent.context.wallet

      expect(agent.isInitialized).toBe(false)
      expect(wallet.isInitialized).toBe(false)
      await agent.initialize()
      expect(agent.isInitialized).toBe(true)
      expect(wallet.isInitialized).toBe(true)
    })

    it('wallet must be initialized if wallet config is not set before agent can be initialized', async () => {
      expect.assertions(9)

      const { walletConfig, ...withoutWalletConfig } = agentOptions.config
      agent = new Agent({ ...agentOptions, config: withoutWalletConfig })

      expect(agent.isInitialized).toBe(false)
      expect(agent.wallet.isInitialized).toBe(false)

      expect(agent.initialize()).rejects.toThrowError(WalletError)
      expect(agent.isInitialized).toBe(false)
      expect(agent.wallet.isInitialized).toBe(false)

      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      await agent.wallet.initialize(walletConfig!)
      expect(agent.isInitialized).toBe(false)
      expect(agent.wallet.isInitialized).toBe(true)

      await agent.initialize()
      expect(agent.wallet.isInitialized).toBe(true)
      expect(agent.isInitialized).toBe(true)
    })
  })

  describe('Dependency Injection', () => {
    it('should be able to resolve registered instances', () => {
      const agent = new Agent(agentOptions)
      const container = agent.dependencyManager

      // Modules
      expect(container.resolve(ConnectionsApi)).toBeInstanceOf(ConnectionsApi)
      expect(container.resolve(ConnectionService)).toBeInstanceOf(ConnectionService)
      expect(container.resolve(ConnectionRepository)).toBeInstanceOf(ConnectionRepository)
      expect(container.resolve(DidRotateService)).toBeInstanceOf(DidRotateService)
      expect(container.resolve(TrustPingService)).toBeInstanceOf(TrustPingService)

      expect(container.resolve(ProofsApi)).toBeInstanceOf(ProofsApi)
      expect(container.resolve(ProofRepository)).toBeInstanceOf(ProofRepository)

      expect(container.resolve(CredentialsApi)).toBeInstanceOf(CredentialsApi)
      expect(container.resolve(CredentialRepository)).toBeInstanceOf(CredentialRepository)

      expect(container.resolve(BasicMessagesApi)).toBeInstanceOf(BasicMessagesApi)
      expect(container.resolve(BasicMessageService)).toBeInstanceOf(BasicMessageService)
      expect(container.resolve(BasicMessageRepository)).toBeInstanceOf(BasicMessageRepository)

      expect(container.resolve(MediatorApi)).toBeInstanceOf(MediatorApi)
      expect(container.resolve(MediationRecipientApi)).toBeInstanceOf(MediationRecipientApi)
      expect(container.resolve(MessagePickupApi)).toBeInstanceOf(MessagePickupApi)
      expect(container.resolve(MediationRepository)).toBeInstanceOf(MediationRepository)
      expect(container.resolve(MediatorService)).toBeInstanceOf(MediatorService)
      expect(container.resolve(MediationRecipientService)).toBeInstanceOf(MediationRecipientService)

      // Symbols, interface based
      expect(container.resolve(InjectionSymbols.Logger)).toBe(agentOptions.config.logger)
      expect(container.resolve(InjectionSymbols.MessagePickupRepository)).toBeInstanceOf(
        InMemoryMessagePickupRepository
      )

      // Agent
      expect(container.resolve(MessageSender)).toBeInstanceOf(MessageSender)
      expect(container.resolve(MessageReceiver)).toBeInstanceOf(MessageReceiver)
      expect(container.resolve(Dispatcher)).toBeInstanceOf(Dispatcher)
      expect(container.resolve(EnvelopeService)).toBeInstanceOf(EnvelopeService)
    })

    it('should return the same instance for consequent resolves', () => {
      const agent = new Agent(agentOptions)
      const container = agent.dependencyManager

      // Modules
      expect(container.resolve(ConnectionsApi)).toBe(container.resolve(ConnectionsApi))
      expect(container.resolve(ConnectionService)).toBe(container.resolve(ConnectionService))
      expect(container.resolve(ConnectionRepository)).toBe(container.resolve(ConnectionRepository))
      expect(container.resolve(TrustPingService)).toBe(container.resolve(TrustPingService))
      expect(container.resolve(DidRotateService)).toBe(container.resolve(DidRotateService))

      expect(container.resolve(ProofsApi)).toBe(container.resolve(ProofsApi))
      expect(container.resolve(ProofRepository)).toBe(container.resolve(ProofRepository))

      expect(container.resolve(CredentialsApi)).toBe(container.resolve(CredentialsApi))
      expect(container.resolve(CredentialRepository)).toBe(container.resolve(CredentialRepository))

      expect(container.resolve(BasicMessagesApi)).toBe(container.resolve(BasicMessagesApi))
      expect(container.resolve(BasicMessageService)).toBe(container.resolve(BasicMessageService))
      expect(container.resolve(BasicMessageRepository)).toBe(container.resolve(BasicMessageRepository))

      expect(container.resolve(MediatorApi)).toBe(container.resolve(MediatorApi))
      expect(container.resolve(MediationRecipientApi)).toBe(container.resolve(MediationRecipientApi))
      expect(container.resolve(MessagePickupApi)).toBe(container.resolve(MessagePickupApi))
      expect(container.resolve(MediationRepository)).toBe(container.resolve(MediationRepository))
      expect(container.resolve(MediatorService)).toBe(container.resolve(MediatorService))
      expect(container.resolve(MediationRecipientService)).toBe(container.resolve(MediationRecipientService))

      // Symbols, interface based
      expect(container.resolve(InjectionSymbols.Logger)).toBe(container.resolve(InjectionSymbols.Logger))
      expect(container.resolve(InjectionSymbols.MessagePickupRepository)).toBe(
        container.resolve(InjectionSymbols.MessagePickupRepository)
      )
      expect(container.resolve(InjectionSymbols.StorageService)).toBe(
        container.resolve(InjectionSymbols.StorageService)
      )

      // Agent
      expect(container.resolve(MessageSender)).toBe(container.resolve(MessageSender))
      expect(container.resolve(MessageReceiver)).toBe(container.resolve(MessageReceiver))
      expect(container.resolve(Dispatcher)).toBe(container.resolve(Dispatcher))
      expect(container.resolve(FeatureRegistry)).toBe(container.resolve(FeatureRegistry))
      expect(container.resolve(EnvelopeService)).toBe(container.resolve(EnvelopeService))
    })
  })

  it('all core features are properly registered', async () => {
    const agent = new Agent(agentOptions)
    await agent.initialize() // Initialization is needed to properly register DIDComm features
    const registry = agent.dependencyManager.resolve(FeatureRegistry)

    const protocols = registry.query({ featureType: 'protocol', match: '*' }).map((p) => p.id)

    expect(protocols.length).toEqual(14)

    expect(protocols).toEqual(
      expect.arrayContaining([
        'https://didcomm.org/basicmessage/1.0',
        'https://didcomm.org/connections/1.0',
        'https://didcomm.org/coordinate-mediation/1.0',
        'https://didcomm.org/issue-credential/2.0',
        'https://didcomm.org/present-proof/2.0',
        'https://didcomm.org/didexchange/1.1',
        'https://didcomm.org/did-rotate/1.0',
        'https://didcomm.org/discover-features/1.0',
        'https://didcomm.org/discover-features/2.0',
        'https://didcomm.org/messagepickup/1.0',
        'https://didcomm.org/messagepickup/2.0',
        'https://didcomm.org/out-of-band/1.1',
        'https://didcomm.org/revocation_notification/1.0',
        'https://didcomm.org/revocation_notification/2.0',
      ])
    )
  })
})
