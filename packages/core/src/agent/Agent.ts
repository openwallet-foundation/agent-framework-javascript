import type { AgentDependencies } from './AgentDependencies'
import type { AgentModulesInput } from './AgentModules'
import type { Module } from '../plugins'
import type { InitConfig } from '../types'

import { Subject } from 'rxjs'

import { InjectionSymbols } from '../constants'
import { SigningProviderToken } from '../crypto'
import { JwsService } from '../crypto/JwsService'
import { CredoError } from '../error'
import { DependencyManager } from '../plugins'
import { StorageUpdateService, StorageVersionRepository } from '../storage'

import { AgentConfig } from './AgentConfig'
import { extendModulesWithDefaultModules } from './AgentModules'
import { BaseAgent } from './BaseAgent'
import { EventEmitter } from './EventEmitter'
import { AgentContext, DefaultAgentContextProvider } from './context'

interface AgentOptions<AgentModules extends AgentModulesInput> {
  config: InitConfig
  modules?: AgentModules
  dependencies: AgentDependencies
}

// Any makes sure you can use Agent as a type without always needing to specify the exact generics for the agent
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export class Agent<AgentModules extends AgentModulesInput = any> extends BaseAgent<AgentModules> {
  public constructor(options: AgentOptions<AgentModules>, dependencyManager = new DependencyManager()) {
    const agentConfig = new AgentConfig(options.config, options.dependencies)
    const modulesWithDefaultModules = extendModulesWithDefaultModules(options.modules)

    // Register internal dependencies
    dependencyManager.registerSingleton(EventEmitter)
    dependencyManager.registerSingleton(JwsService)
    dependencyManager.registerSingleton(StorageVersionRepository)
    dependencyManager.registerSingleton(StorageUpdateService)

    // This is a really ugly hack to make tsyringe work without any SigningProviders registered
    // It is currently impossible to use @injectAll if there are no instances registered for the
    // token. We register a value of `default` by default and will filter that out in the registry.
    // Once we have a signing provider that should always be registered we can remove this. We can make an ed25519
    // signer using the @stablelib/ed25519 library.
    dependencyManager.registerInstance(SigningProviderToken, 'default')

    dependencyManager.registerInstance(AgentConfig, agentConfig)
    dependencyManager.registerInstance(InjectionSymbols.AgentDependencies, agentConfig.agentDependencies)
    dependencyManager.registerInstance(InjectionSymbols.Stop$, new Subject<boolean>())
    dependencyManager.registerInstance(InjectionSymbols.FileSystem, new agentConfig.agentDependencies.FileSystem())

    // Register all modules. This will also include the default modules
    dependencyManager.registerModules(modulesWithDefaultModules)

    // Register possibly already defined services
    if (!dependencyManager.isRegistered(InjectionSymbols.Wallet)) {
      throw new CredoError(
        "Missing required dependency: 'Wallet'. You can register it using the AskarModule, or implement your own."
      )
    }
    if (!dependencyManager.isRegistered(InjectionSymbols.Logger)) {
      dependencyManager.registerInstance(InjectionSymbols.Logger, agentConfig.logger)
    }
    if (!dependencyManager.isRegistered(InjectionSymbols.StorageService)) {
      throw new CredoError(
        "Missing required dependency: 'StorageService'. You can register it using the AskarModule, or implement your own."
      )
    }

    // TODO: contextCorrelationId for base wallet
    // Bind the default agent context to the container for use in modules etc.
    dependencyManager.registerInstance(
      AgentContext,
      new AgentContext({
        dependencyManager,
        contextCorrelationId: 'default',
      })
    )

    // If no agent context provider has been registered we use the default agent context provider.
    if (!dependencyManager.isRegistered(InjectionSymbols.AgentContextProvider)) {
      dependencyManager.registerSingleton(InjectionSymbols.AgentContextProvider, DefaultAgentContextProvider)
    }

    super(agentConfig, dependencyManager)
  }

  public get events() {
    return this.eventEmitter
  }

  public async initialize() {
    await super.initialize()

    for (const [, module] of Object.entries(this.dependencyManager.registeredModules) as [string, Module][]) {
      if (module.initialize) {
        await module.initialize(this.agentContext)
      }
    }

    this._isInitialized = true
  }

  public async shutdown() {
    const stop$ = this.dependencyManager.resolve<Subject<boolean>>(InjectionSymbols.Stop$)
    // All observables use takeUntil with the stop$ observable
    // this means all observables will stop running if a value is emitted on this observable
    stop$.next(true)

    for (const [, module] of Object.entries(this.dependencyManager.registeredModules) as [string, Module][]) {
      if (module.shutdown) {
        await module.shutdown(this.agentContext)
      }
    }

    if (this.wallet.isInitialized) {
      await this.wallet.close()
    }

    this._isInitialized = false
  }
}
