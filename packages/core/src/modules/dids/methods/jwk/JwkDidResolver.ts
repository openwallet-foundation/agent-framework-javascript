import type { AgentContext } from '../../../../agent'
import type { DidResolver } from '../../domain/DidResolver'
import type { DidResolutionResult } from '../../types'

import { DidJwk } from './DidJwk'

export class JwkDidResolver implements DidResolver {
  public readonly supportedMethods = ['jwk']

  /**
   * No remote resolving done, did document is dynamically constructed. To not pollute the cache we don't allow caching
   */
  public readonly allowsCaching = false

  /**
   * Easier to calculate for resolving than serving the local did document. Record also doesn't
   * have a did document
   */
  public readonly allowsLocalDidRecord = false

  public async resolve(agentContext: AgentContext, did: string): Promise<DidResolutionResult> {
    const didDocumentMetadata = {}

    try {
      const didDocument = DidJwk.fromDid(did).didDocument

      return {
        didDocument,
        didDocumentMetadata,
        didResolutionMetadata: { contentType: 'application/did+ld+json' },
      }
    } catch (error) {
      return {
        didDocument: null,
        didDocumentMetadata,
        didResolutionMetadata: {
          error: 'notFound',
          message: `resolver_error: Unable to resolve did '${did}': ${error}`,
        },
      }
    }
  }
}
