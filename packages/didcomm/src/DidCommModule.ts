import type { DidCommModuleConfigOptions } from './DidCommModuleConfig'
import type { AgentMessageReceivedEvent } from './Events'
import type { AgentContext, DependencyManager, Module, Update } from '@credo-ts/core'
import type { Subject } from 'rxjs'

import { mergeMap, takeUntil } from 'rxjs'

import { EventEmitter, InjectionSymbols } from '@credo-ts/core'

import { DidCommApi } from './DidCommApi'
import { DidCommModuleConfig } from './DidCommModuleConfig'
import { Dispatcher } from './Dispatcher'
import { EnvelopeService } from './EnvelopeService'
import { AgentEventTypes } from './Events'
import { FeatureRegistry } from './FeatureRegistry'
import { MessageHandlerRegistry } from './MessageHandlerRegistry'
import { MessageReceiver } from './MessageReceiver'
import { MessageSender } from './MessageSender'
import { TransportService } from './TransportService'
import { DidCommMessageRepository } from './repository'
import { updateV0_1ToV0_2 } from './updates/0.1-0.2'
import { updateV0_2ToV0_3 } from './updates/0.2-0.3'
import { updateV0_4ToV0_5 } from './updates/0.4-0.5'

export class DidCommModule implements Module {
  public readonly config: DidCommModuleConfig
  public readonly api = DidCommApi

  public constructor(config?: DidCommModuleConfigOptions) {
    this.config = new DidCommModuleConfig(config)
  }

  /**
   * Registers the dependencies of the question answer module on the dependency manager.
   */
  public register(dependencyManager: DependencyManager) {
    // Config
    dependencyManager.registerInstance(DidCommModuleConfig, this.config)

    // Registries
    dependencyManager.registerSingleton(MessageHandlerRegistry)
    dependencyManager.registerSingleton(FeatureRegistry)

    // Services
    dependencyManager.registerSingleton(MessageSender)
    dependencyManager.registerSingleton(MessageReceiver)
    dependencyManager.registerSingleton(TransportService)
    dependencyManager.registerSingleton(Dispatcher)
    dependencyManager.registerSingleton(EnvelopeService)

    // Repositories
    dependencyManager.registerSingleton(DidCommMessageRepository)

    // Features
    // TODO: Constraints?
  }

  public async initialize(agentContext: AgentContext): Promise<void> {
    const stop$ = agentContext.dependencyManager.resolve<Subject<boolean>>(InjectionSymbols.Stop$)
    const eventEmitter = agentContext.dependencyManager.resolve(EventEmitter)
    const messageReceiver = agentContext.dependencyManager.resolve(MessageReceiver)
    const messageSender = agentContext.dependencyManager.resolve(MessageSender)

    // Listen for new messages (either from transports or somewhere else in the framework / extensions)
    // We create this before doing any other initialization, so the initialization could already receive messages
    eventEmitter
      .observable<AgentMessageReceivedEvent>(AgentEventTypes.AgentMessageReceived)
      .pipe(
        takeUntil(stop$),
        mergeMap(
          (e) =>
            messageReceiver
              .receiveMessage(e.payload.message, {
                connection: e.payload.connection,
                contextCorrelationId: e.payload.contextCorrelationId,
                session: e.payload.session,
              })
              .catch((error) => {
                agentContext.config.logger.error('Failed to process message', { error })
              }),
          this.config.processDidCommMessagesConcurrently ? undefined : 1
        )
      )
      .subscribe()

    for (const transport of messageReceiver.inboundTransports) {
      await transport.start(agentContext)
    }

    for (const transport of messageSender.outboundTransports) {
      await transport.start(agentContext)
    }
  }

  // TODO: Shall shutdown and initialize be part of API (so Agent can be stopped/restarted without creating a new instance)?
  public async shutdown(agentContext: AgentContext) {
    const messageReceiver = agentContext.dependencyManager.resolve(MessageReceiver)
    const messageSender = agentContext.dependencyManager.resolve(MessageSender)

    // Stop transports
    const allTransports = [...messageReceiver.inboundTransports, ...messageSender.outboundTransports]
    const transportPromises = allTransports.map((transport) => transport.stop())
    await Promise.all(transportPromises)
  }

  public updates = [
    {
      fromVersion: '0.1',
      toVersion: '0.2',
      doUpdate: updateV0_1ToV0_2,
    },
    {
      fromVersion: '0.2',
      toVersion: '0.3',
      doUpdate: updateV0_2ToV0_3,
    },
    {
      fromVersion: '0.4',
      toVersion: '0.5',
      doUpdate: updateV0_4ToV0_5,
    },
  ] satisfies Update[]
}
