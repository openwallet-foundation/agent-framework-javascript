import type { CredentialProtocol } from './protocol/CredentialProtocol'

import { AutoAcceptCredential } from './models'

/**
 * CredentialsModuleConfigOptions defines the interface for the options of the CredentialsModuleConfig class.
 * This can contain optional parameters that have default values in the config class itself.
 */
export interface CredentialsModuleConfigOptions<CredentialProtocols extends CredentialProtocol[]> {
  /**
   * Whether to automatically accept credential messages. Applies to all issue credential protocol versions.
   *
   * @default {@link AutoAcceptCredential.Never}
   */
  autoAcceptCredentials?: AutoAcceptCredential

  /**
   * Credential protocols to make available to the credentials module. Only one credential protocol should be registered for each credential
   * protocol version.
   *
   * When not provided, the `V2CredentialProtocol` is registered by default.
   *
   * @default
   * ```
   * [V2CredentialProtocol]
   * ```
   */
  credentialProtocols: CredentialProtocols
}

export class CredentialsModuleConfig<CredentialProtocols extends CredentialProtocol[]> {
  private options: CredentialsModuleConfigOptions<CredentialProtocols>

  public constructor(options: CredentialsModuleConfigOptions<CredentialProtocols>) {
    this.options = options
  }

  /** See {@link CredentialsModuleConfigOptions.autoAcceptCredentials} */
  public get autoAcceptCredentials() {
    return this.options.autoAcceptCredentials ?? AutoAcceptCredential.Never
  }

  /** See {@link CredentialsModuleConfigOptions.credentialProtocols} */
  public get credentialProtocols() {
    return this.options.credentialProtocols
  }
}
