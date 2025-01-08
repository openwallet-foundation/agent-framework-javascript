import type {
  AgentContext,
  DidRegistrar,
  DidResolver,
  DidDocument,
  DidCreateOptions,
  DidCreateResult,
  DidUpdateResult,
  DidDeactivateResult,
  DidResolutionResult,
} from '@credo-ts/core'

import { DidRecord, DidDocumentRole, DidRepository } from '@credo-ts/core'

export class InMemoryDidRegistry implements DidRegistrar, DidResolver {
  public readonly supportedMethods = ['inmemory']

  public readonly allowsCaching = false

  private dids: Record<string, DidDocument> = {}

  public async create(agentContext: AgentContext, options: DidCreateOptions): Promise<DidCreateResult> {
    const { did, didDocument } = options

    if (!did || !didDocument) {
      return {
        didDocumentMetadata: {},
        didRegistrationMetadata: {},
        didState: {
          state: 'failed',
          reason: 'InMemoryDidRegistrar requires to specify both did and didDocument',
        },
      }
    }

    this.dids[did] = didDocument

    // Save the did so we know we created it and can use it for didcomm
    const didRecord = new DidRecord({
      did: didDocument.id,
      role: DidDocumentRole.Created,
      didDocument,
    })
    const didRepository = agentContext.dependencyManager.resolve(DidRepository)
    await didRepository.save(agentContext, didRecord)

    return {
      didDocumentMetadata: {},
      didRegistrationMetadata: {},
      didState: {
        state: 'finished',
        did: didDocument.id,
        didDocument,
      },
    }
  }

  public async update(): Promise<DidUpdateResult> {
    return {
      didDocumentMetadata: {},
      didRegistrationMetadata: {},
      didState: {
        state: 'failed',
        reason: `notImplemented: updating did:inmemory not implemented yet`,
      },
    }
  }

  public async deactivate(): Promise<DidDeactivateResult> {
    return {
      didDocumentMetadata: {},
      didRegistrationMetadata: {},
      didState: {
        state: 'failed',
        reason: `notImplemented: deactivating did:inmemory not implemented yet`,
      },
    }
  }

  public async resolve(agentContext: AgentContext, did: string): Promise<DidResolutionResult> {
    const didDocument = this.dids[did]

    if (!didDocument) {
      return {
        didDocument: null,
        didDocumentMetadata: {},
        didResolutionMetadata: {
          error: 'notFound',
          message: `resolver_error: Unable to resolve did '${did}'`,
        },
      }
    }

    return {
      didDocument,
      didDocumentMetadata: {},
      didResolutionMetadata: { contentType: 'application/did+ld+json' },
    }
  }
}
