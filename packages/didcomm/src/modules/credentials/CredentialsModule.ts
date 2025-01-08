import type { CredentialsModuleConfigOptions } from './CredentialsModuleConfig'
import type { CredentialProtocol } from './protocol/CredentialProtocol'
import type { AgentContext, ApiModule, DependencyManager, Constructor, Optional } from '@credo-ts/core'

import { FeatureRegistry } from '../../FeatureRegistry'
import { MessageHandlerRegistry } from '../../MessageHandlerRegistry'
import { Protocol } from '../../models'

import { CredentialsApi } from './CredentialsApi'
import { CredentialsModuleConfig } from './CredentialsModuleConfig'
import { RevocationNotificationService } from './protocol/revocation-notification/services'
import { V2CredentialProtocol } from './protocol/v2'
import { CredentialRepository } from './repository'

/**
 * Default credentialProtocols that will be registered if the `credentialProtocols` property is not configured.
 */
export type DefaultCredentialProtocols = []

// CredentialsModuleOptions makes the credentialProtocols property optional from the config, as it will set it when not provided.
export type CredentialsModuleOptions<CredentialProtocols extends CredentialProtocol[]> = Optional<
  CredentialsModuleConfigOptions<CredentialProtocols>,
  'credentialProtocols'
>

export class CredentialsModule<CredentialProtocols extends CredentialProtocol[] = DefaultCredentialProtocols>
  implements ApiModule
{
  public readonly config: CredentialsModuleConfig<CredentialProtocols>

  // Infer Api type from the config
  public readonly api: Constructor<CredentialsApi<CredentialProtocols>> = CredentialsApi

  public constructor(config?: CredentialsModuleOptions<CredentialProtocols>) {
    this.config = new CredentialsModuleConfig({
      ...config,
      // NOTE: the credentialProtocols defaults are set in the CredentialsModule rather than the CredentialsModuleConfig to
      // avoid dependency cycles.
      credentialProtocols: config?.credentialProtocols ?? [new V2CredentialProtocol({ credentialFormats: [] })],
    }) as CredentialsModuleConfig<CredentialProtocols>
  }

  /**
   * Registers the dependencies of the credentials module on the dependency manager.
   */
  public register(dependencyManager: DependencyManager) {
    // Config
    dependencyManager.registerInstance(CredentialsModuleConfig, this.config)

    // Services
    dependencyManager.registerSingleton(RevocationNotificationService)

    // Repositories
    dependencyManager.registerSingleton(CredentialRepository)
  }

  public async initialize(agentContext: AgentContext): Promise<void> {
    const messageHandlerRegistry = agentContext.dependencyManager.resolve(MessageHandlerRegistry)
    const featureRegistry = agentContext.dependencyManager.resolve(FeatureRegistry)

    featureRegistry.register(
      new Protocol({
        id: 'https://didcomm.org/revocation_notification/1.0',
        roles: ['holder'],
      }),
      new Protocol({
        id: 'https://didcomm.org/revocation_notification/2.0',
        roles: ['holder'],
      })
    )

    // Protocol needs to register feature registry items and handlers
    for (const credentialProtocol of this.config.credentialProtocols) {
      credentialProtocol.register(messageHandlerRegistry, featureRegistry)
    }
  }
}
