import type { AgentContext, DidResolutionResult, DidResolver } from '@credo-ts/core'

import { parseIndyDid } from '@credo-ts/anoncreds'

import { IndyVdrPoolService } from '../pool'

import { buildDidDocument } from './didIndyUtil'

export class IndyVdrIndyDidResolver implements DidResolver {
  public readonly supportedMethods = ['indy']

  public readonly allowsCaching = true
  public readonly allowsLocalDidRecord = true

  public async resolve(agentContext: AgentContext, did: string): Promise<DidResolutionResult> {
    const didDocumentMetadata = {}
    try {
      const poolService = agentContext.dependencyManager.resolve(IndyVdrPoolService)
      const pool = poolService.getPoolForNamespace(parseIndyDid(did).namespace)

      // Get DID Document from Get NYM response
      const didDocument = await buildDidDocument(agentContext, pool, did)

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
