import type { Module, DependencyManager, ApiModule } from '../plugins'
import type { IsAny } from '../types'
import type { Constructor } from '../utils/mixins'

import { CacheModule } from '../modules/cache'
import { DidsModule } from '../modules/dids'
import { DifPresentationExchangeModule } from '../modules/dif-presentation-exchange'
import { GenericRecordsModule } from '../modules/generic-records'
import { MdocModule } from '../modules/mdoc/MdocModule'
import { SdJwtVcModule } from '../modules/sd-jwt-vc'
import { W3cCredentialsModule } from '../modules/vc'
import { X509Module } from '../modules/x509'
import { WalletModule } from '../wallet'

/**
 * Simple utility type that represent a map of modules. This is used to map from moduleKey (api key) to the api in the framework.
 */
export type ModulesMap = { [key: string]: Module }

// eslint-disable-next-line @typescript-eslint/ban-types
export type EmptyModuleMap = {}

/**
 * Default modules can be optionally defined to provide custom configuration. This type makes it so that it is not
 * possible to use a different key for the default modules
 */
export type AgentModulesInput = ModulesMap

/**
 * Type that represents the default agent modules. This is the {@link ModulesMap} variant for the default modules in the framework.
 * It uses the return type of the {@link getDefaultAgentModules} method to automatically infer which modules are always available on
 * the agent and in the agent. namespace.
 */
export type DefaultAgentModules = {
  [moduleKey in keyof ReturnType<typeof getDefaultAgentModules>]: ReturnType<
    ReturnType<typeof getDefaultAgentModules>[moduleKey]
  >
}

export type WithoutDefaultModules<Modules extends ModulesMap> = {
  [moduleKey in Exclude<keyof Modules, keyof DefaultAgentModules>]: Modules[moduleKey]
}

/**
 * Type that represents the api object of the agent (`agent.xxx`). It will extract all keys of the modules and map this to the
 * registered {@link Module.api} class instance. If the module does not have an api class registered, the property will be removed
 * and won't be available on the api object.
 *
 * @example
 * If the following AgentModules type was passed:
 * ```ts
 * {
 *   connections: ConnectionsModule
 *   indy: IndyModule
 * }
 * ```
 *
 * And we use the `AgentApi` type like this:
 * ```ts
 * type MyAgentApi = AgentApi<{
 *   connections: ConnectionsModule
 *   indy: IndyModule
 * }>
 * ```
 *
 * the resulting agent api will look like:
 *
 * ```ts
 * {
 *   connections: ConnectionsApi
 * }
 * ```
 *
 * The `indy` module has been ignored because it doesn't define an api class.
 */
export type AgentApi<Modules extends ModulesMap> = {
  [moduleKey in keyof Modules as Modules[moduleKey]['api'] extends Constructor<unknown>
    ? moduleKey
    : never]: Modules[moduleKey]['api'] extends Constructor<unknown> ? InstanceType<Modules[moduleKey]['api']> : never
}

/**
 * Returns the `api` type from the CustomModuleType if the module is an ApiModule. If the module is not defined
 * which is the case if you don't configure a default agent module (e.g. credentials module), it will use the default
 * module type and use that for the typing. This will contain the default typing, and thus provide the correct agent api
 * interface
 */
export type CustomOrDefaultApi<
  CustomModuleType,
  DefaultModuleType extends ApiModule
> = IsAny<CustomModuleType> extends true
  ? InstanceType<DefaultModuleType['api']>
  : CustomModuleType extends ApiModule
  ? InstanceType<CustomModuleType['api']>
  : CustomModuleType extends Module
  ? never
  : InstanceType<DefaultModuleType['api']>

/**
 * Method to get the default agent modules to be registered on any agent instance. It doens't configure the modules in any way,
 * and if that's needed the user needs to provide the module in the agent constructor
 */
function getDefaultAgentModules() {
  return {
    genericRecords: () => new GenericRecordsModule(),
    dids: () => new DidsModule(),
    wallet: () => new WalletModule(),
    w3cCredentials: () => new W3cCredentialsModule(),
    cache: () => new CacheModule(),
    pex: () => new DifPresentationExchangeModule(),
    sdJwtVc: () => new SdJwtVcModule(),
    x509: () => new X509Module(),
    mdoc: () => new MdocModule(),
  } as const
}

/**
 * Extend the provided modules object with the default agent modules. If the modules property already contains a module with the same
 * name as a default module, the module won't be added to the extended module object. This allows users of the framework to override
 * the modules with custom configuration. The agent constructor type ensures you can't provide a different module for a key that registered
 * on the default agent.
 */
export function extendModulesWithDefaultModules<AgentModules extends AgentModulesInput>(
  modules?: AgentModules
): AgentModules & DefaultAgentModules {
  const extendedModules: Record<string, Module> = { ...modules }
  const defaultAgentModules = getDefaultAgentModules()

  // Register all default modules, if not registered yet
  for (const [moduleKey, getConfiguredModule] of Object.entries(defaultAgentModules)) {
    // Do not register if the module is already registered.
    if (modules && modules[moduleKey]) continue

    extendedModules[moduleKey] = getConfiguredModule()
  }

  return extendedModules as AgentModules & DefaultAgentModules
}

/**
 * Get the agent api object based on the modules registered in the dependency manager. For each registered module on the
 * dependency manager, the method will extract the api class from the module, resolve it and assign it to the module key
 * as provided in the agent constructor (or the {@link getDefaultAgentModules} method).
 *
 * Modules that don't have an api class defined ({@link Module.api} is undefined) will be ignored and won't be added to the
 * api object.
 *
 * If the api of a module is passed in the `excluded` array, the api will not be added to the resulting api object.
 *
 * @example
 * If the dependency manager has the following modules configured:
 * ```ts
 * {
 *   connections: ConnectionsModule
 *   indy: IndyModule
 * }
 * ```
 *
 * And we call the `getAgentApi` method like this:
 * ```ts
 * const api = getAgentApi(dependencyManager)
 * ```
 *
 * the resulting agent api will look like:
 *
 * ```ts
 * {
 *   connections: ConnectionsApi
 * }
 * ```
 *
 * The `indy` module has been ignored because it doesn't define an api class.
 */
export function getAgentApi<AgentModules extends ModulesMap>(
  dependencyManager: DependencyManager,
  excludedApis: unknown[] = []
): AgentApi<AgentModules> {
  // Create the api object based on the `api` properties on the modules. If no `api` exists
  // on the module it will be ignored.
  const api = Object.entries(dependencyManager.registeredModules).reduce((api, [moduleKey, module]) => {
    // Module has no api
    if (!module.api) return api

    const apiInstance = dependencyManager.resolve(module.api)

    // Api is excluded
    if (excludedApis.includes(apiInstance)) return api
    return { ...api, [moduleKey]: apiInstance }
  }, {}) as AgentApi<AgentModules>

  return api
}
