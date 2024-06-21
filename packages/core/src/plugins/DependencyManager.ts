import type { ModulesMap } from '../agent/AgentModules'
import type { MessageHandler } from '../agent/MessageHandler'
import type { MessageHandlerMiddleware } from '../agent/MessageHandlerMiddleware'
import type { Constructor } from '../utils/mixins'
import type { DependencyContainer } from 'tsyringe'

import { container as rootContainer, InjectionToken, Lifecycle } from 'tsyringe'

import { FeatureRegistry } from '../agent/FeatureRegistry'
import { MessageHandlerRegistry } from '../agent/MessageHandlerRegistry'
import { CredoError } from '../error'

export { InjectionToken }

export class DependencyManager {
  public readonly container: DependencyContainer
  public readonly registeredModules: ModulesMap

  public constructor(
    container: DependencyContainer = rootContainer.createChildContainer(),
    registeredModules: ModulesMap = {}
  ) {
    this.container = container
    this.registeredModules = registeredModules
  }

  public registerModules(modules: ModulesMap) {
    const featureRegistry = this.resolve(FeatureRegistry)

    for (const [moduleKey, module] of Object.entries(modules)) {
      if (this.registeredModules[moduleKey]) {
        throw new CredoError(
          `Module with key ${moduleKey} has already been registered. Only a single module can be registered with the same key.`
        )
      }

      this.registeredModules[moduleKey] = module
      if (module.api) {
        this.registerContextScoped(module.api)
      }
      module.register(this, featureRegistry)
    }
  }

  public registerMessageHandlers(messageHandlers: MessageHandler[]) {
    const messageHandlerRegistry = this.resolve(MessageHandlerRegistry)

    for (const messageHandler of messageHandlers) {
      messageHandlerRegistry.registerMessageHandler(messageHandler)
    }
  }

  public registerMessageHandlerMiddleware(messageHandlerMiddleware: MessageHandlerMiddleware) {
    const messageHandlerRegistry = this.resolve(MessageHandlerRegistry)

    messageHandlerRegistry.registerMessageHandlerMiddleware(messageHandlerMiddleware)
  }

  public get fallbackMessageHandler() {
    const messageHandlerRegistry = this.resolve(MessageHandlerRegistry)

    return messageHandlerRegistry.fallbackMessageHandler
  }

  public get messageHandlerMiddlewares() {
    const messageHandlerRegistry = this.resolve(MessageHandlerRegistry)

    return messageHandlerRegistry.messageHandlerMiddlewares
  }

  /**
   * Sets the fallback message handler, the message handler that will be called if no handler
   * is registered for an incoming message type.
   */
  public setFallbackMessageHandler(fallbackMessageHandler: MessageHandler['handle']) {
    const messageHandlerRegistry = this.resolve(MessageHandlerRegistry)

    messageHandlerRegistry.setFallbackMessageHandler(fallbackMessageHandler)
  }

  public registerSingleton<T>(from: InjectionToken<T>, to: InjectionToken<T>): void
  public registerSingleton<T>(token: Constructor<T>): void
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  public registerSingleton<T = any>(fromOrToken: InjectionToken<T> | Constructor<T>, to?: any) {
    this.container.registerSingleton(fromOrToken, to)
  }

  public resolve<T>(token: InjectionToken<T>): T {
    return this.container.resolve(token)
  }

  public registerInstance<T>(token: InjectionToken<T>, instance: T) {
    this.container.registerInstance(token, instance)
  }

  public isRegistered<T>(token: InjectionToken<T>): boolean {
    return this.container.isRegistered(token)
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  public registerContextScoped<T = any>(token: Constructor<T>): void
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  public registerContextScoped<T = any>(token: InjectionToken<T>, provider: Constructor<T>): void

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  public registerContextScoped(token: any, provider?: any) {
    if (provider) this.container.register(token, provider, { lifecycle: Lifecycle.ContainerScoped })
    else this.container.register(token, token, { lifecycle: Lifecycle.ContainerScoped })
  }

  /**
   * Dispose the dependency manager. Calls `.dispose()` on all instances that implement the `Disposable` interface and have
   * been constructed by the `DependencyManager`. This means all instances registered using `registerInstance` won't have the
   * dispose method called.
   */
  public async dispose() {
    await this.container.dispose()
  }

  public createChild() {
    return new DependencyManager(this.container.createChildContainer(), this.registeredModules)
  }
}
