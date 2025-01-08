import { PeerDidNumAlgo } from '@credo-ts/core'

/**
 * ConnectionsModuleConfigOptions defines the interface for the options of the ConnectionsModuleConfig class.
 * This can contain optional parameters that have default values in the config class itself.
 */
export interface ConnectionsModuleConfigOptions {
  /**
   * Whether to automatically accept connection messages. Applies to both the connection protocol (RFC 0160)
   * and the DID exchange protocol (RFC 0023).
   *
   * Note: this setting does not apply to implicit invitation flows, which always need to be manually accepted
   * using ConnectionStateChangedEvent
   *
   * @default false
   */
  autoAcceptConnections?: boolean

  /**
   * Peer did num algo to use in requests for DID exchange protocol (RFC 0023). It will be also used by default
   * in responses in case that the request does not use a peer did.
   *
   * @default PeerDidNumAlgo.GenesisDoc
   */
  peerNumAlgoForDidExchangeRequests?: PeerDidNumAlgo

  /**
   * Peer did num algo to use for DID rotation (RFC 0794).
   *
   * @default PeerDidNumAlgo.ShortFormAndLongForm
   */
  peerNumAlgoForDidRotation?: PeerDidNumAlgo.MultipleInceptionKeyWithoutDoc | PeerDidNumAlgo.ShortFormAndLongForm
}

export class ConnectionsModuleConfig {
  #autoAcceptConnections?: boolean
  #peerNumAlgoForDidExchangeRequests?: PeerDidNumAlgo
  #peerNumAlgoForDidRotation?: PeerDidNumAlgo.MultipleInceptionKeyWithoutDoc | PeerDidNumAlgo.ShortFormAndLongForm

  private options: ConnectionsModuleConfigOptions

  public constructor(options?: ConnectionsModuleConfigOptions) {
    this.options = options ?? {}
    this.#autoAcceptConnections = this.options.autoAcceptConnections
    this.#peerNumAlgoForDidExchangeRequests = this.options.peerNumAlgoForDidExchangeRequests
    this.#peerNumAlgoForDidRotation = this.options.peerNumAlgoForDidRotation
  }

  /** See {@link ConnectionsModuleConfigOptions.autoAcceptConnections} */
  public get autoAcceptConnections() {
    return this.#autoAcceptConnections ?? false
  }

  /** See {@link ConnectionsModuleConfigOptions.autoAcceptConnections} */
  public set autoAcceptConnections(autoAcceptConnections: boolean) {
    this.#autoAcceptConnections = autoAcceptConnections
  }

  /** See {@link ConnectionsModuleConfigOptions.peerNumAlgoForDidExchangeRequests} */
  public get peerNumAlgoForDidExchangeRequests() {
    return this.#peerNumAlgoForDidExchangeRequests ?? PeerDidNumAlgo.GenesisDoc
  }

  /** See {@link ConnectionsModuleConfigOptions.peerNumAlgoForDidExchangeRequests} */
  public set peerNumAlgoForDidExchangeRequests(peerNumAlgoForDidExchangeRequests: PeerDidNumAlgo) {
    this.#peerNumAlgoForDidExchangeRequests = peerNumAlgoForDidExchangeRequests
  }

  /** See {@link ConnectionsModuleConfigOptions.peerNumAlgoForDidRotation} */
  public get peerNumAlgoForDidRotation() {
    return this.#peerNumAlgoForDidRotation ?? PeerDidNumAlgo.ShortFormAndLongForm
  }

  /** See {@link ConnectionsModuleConfigOptions.peerNumAlgoForDidRotation} */
  public set peerNumAlgoForDidRotation(
    peerNumAlgoForDidRotation: PeerDidNumAlgo.MultipleInceptionKeyWithoutDoc | PeerDidNumAlgo.ShortFormAndLongForm
  ) {
    this.#peerNumAlgoForDidRotation = peerNumAlgoForDidRotation
  }
}
