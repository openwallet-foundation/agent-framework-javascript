import type { DidCommModuleConfigOptions } from '../DidCommModuleConfig'
import type { Agent, ModulesMap } from '@credo-ts/core'

import { DidCommModule } from '../DidCommModule'
import {
  ConnectionsModule,
  CredentialsModule,
  ProofsModule,
  MediatorModule,
  DiscoverFeaturesModule,
  MediationRecipientModule,
  MessagePickupModule,
  BasicMessagesModule,
  OutOfBandModule,
} from '../modules'

/**
 * Type that represents the default agent modules. This is the {@link ModulesMap} variant for the default modules in the framework.
 * It uses the return type of the {@link getDefaultDidcommModules} method to automatically infer which modules are always available on
 * the agent and in the agent. namespace.
 */
export type DefaultDidCommModules = {
  [moduleKey in keyof ReturnType<typeof getDefaultDidcommModules>]: ReturnType<
    typeof getDefaultDidcommModules
  >[moduleKey]
}

export type WithoutDefaultDidCommModules<Modules extends ModulesMap> = {
  [moduleKey in Exclude<keyof Modules, keyof DefaultDidCommModules>]: Modules[moduleKey]
}

export type AgentModulesInput = Partial<DefaultAgentModulesInput> & ModulesMap

/**
 * Defines the input type for the default agent modules. This is overwritten as we
 * want the input type to allow for generics to be passed in for the credentials module.
 */
export type DefaultAgentModulesInput = Omit<DefaultDidCommModules, 'credentials' | 'proofs'> & {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  credentials: CredentialsModule<any>
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  proofs: ProofsModule<any>
}

export type DidCommAgent = Agent<DefaultDidCommModules>

export function getDefaultDidcommModules(didcommModuleConfig?: DidCommModuleConfigOptions) {
  return {
    connections: new ConnectionsModule(),
    credentials: new CredentialsModule(),
    proofs: new ProofsModule(),
    mediator: new MediatorModule(),
    discovery: new DiscoverFeaturesModule(),
    mediationRecipient: new MediationRecipientModule(),
    messagePickup: new MessagePickupModule(),
    basicMessages: new BasicMessagesModule(),
    didcomm: new DidCommModule(didcommModuleConfig),
    oob: new OutOfBandModule(),
  } as const
}
