import { DID_COMM_TRANSPORT_QUEUE } from './constants'

import { DidCommMimeType } from './types'

/**
 * MediatorModuleConfigOptions defines the interface for the options of the MediatorModuleConfig class.
 * This can contain optional parameters that have default values in the config class itself.
 */
export interface DidCommModuleConfigOptions {
  endpoints?: string[]
  useDidSovPrefixWhereAllowed?: boolean
  connectionImageUrl?: string
  processDidCommMessagesConcurrently?: boolean
  didCommMimeType?: string
  useDidKeyInProtocols?: boolean
}

export class DidCommModuleConfig {
  private options: DidCommModuleConfigOptions
  private _endpoints?: string[]

  public constructor(options?: DidCommModuleConfigOptions) {
    this.options = options ?? {}
    this._endpoints = options?.endpoints
  }

  public get endpoints(): [string, ...string[]] {
    // if endpoints is not set, return queue endpoint
    // https://github.com/hyperledger/aries-rfcs/issues/405#issuecomment-582612875
    if (!this._endpoints || this._endpoints.length === 0) {
      return [DID_COMM_TRANSPORT_QUEUE]
    }

    return this._endpoints as [string, ...string[]]
  }

  public set endpoints(endpoints: string[]) {
    this._endpoints = endpoints
  }

  public get useDidSovPrefixWhereAllowed() {
    return this.options.useDidSovPrefixWhereAllowed ?? false
  }

  /**
   * @todo move to context configuration
   */
  public get connectionImageUrl() {
    return this.options.connectionImageUrl
  }

  public get processDidCommMessagesConcurrently() {
    return this.options.processDidCommMessagesConcurrently ?? false
  }

  public get didCommMimeType() {
    return this.options.didCommMimeType ?? DidCommMimeType.V1
  }

  /**
   * Encode keys in did:key format instead of 'naked' keys, as stated in Aries RFC 0360.
   *
   * This setting will not be taken into account if the other party has previously used naked keys
   * in a given protocol (i.e. it does not support Aries RFC 0360).
   */
  public get useDidKeyInProtocols() {
    return this.options.useDidKeyInProtocols ?? true
  }
}
