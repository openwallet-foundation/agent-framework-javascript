import type { AgentContext } from '../../../agent'
import type { ParsedDid, DidResolutionResult, DidResolutionOptions } from '../types'

export interface DidResolver {
  readonly supportedMethods: string[]
  readonly allowsCaching: boolean

  /**
   * Whether the resolver allows using a local created did document from
   * a did record to resolve the did document.
   *
   * @default false
   * @todo make required in 0.6.0
   */
  readonly allowsLocalDidRecord?: boolean

  resolve(
    agentContext: AgentContext,
    did: string,
    parsed: ParsedDid,
    didResolutionOptions: DidResolutionOptions
  ): Promise<DidResolutionResult>
}
