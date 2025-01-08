import type { ProofProtocol } from './protocol/ProofProtocol'

import { AutoAcceptProof } from './models/ProofAutoAcceptType'

/**
 * ProofsModuleConfigOptions defines the interface for the options of the ProofsModuleConfig class.
 * This can contain optional parameters that have default values in the config class itself.
 */
export interface ProofsModuleConfigOptions<ProofProtocols extends ProofProtocol[]> {
  /**
   * Whether to automatically accept proof messages. Applies to all present proof protocol versions.
   *
   * @default {@link AutoAcceptProof.Never}
   */
  autoAcceptProofs?: AutoAcceptProof

  /**
   * Proof protocols to make available to the proofs module. Only one proof protocol should be registered for each proof
   * protocol version.
   *
   * When not provided, the `V2ProofProtocol` is registered by default.
   *
   * @default
   * ```
   * [V2ProofProtocol]
   * ```
   */
  proofProtocols: ProofProtocols
}

export class ProofsModuleConfig<ProofProtocols extends ProofProtocol[]> {
  private options: ProofsModuleConfigOptions<ProofProtocols>

  public constructor(options: ProofsModuleConfigOptions<ProofProtocols>) {
    this.options = options
  }

  /** See {@link ProofsModuleConfigOptions.autoAcceptProofs} */
  public get autoAcceptProofs() {
    return this.options.autoAcceptProofs ?? AutoAcceptProof.Never
  }

  /** See {@link ProofsModuleConfigOptions.proofProtocols} */
  public get proofProtocols() {
    return this.options.proofProtocols
  }
}
