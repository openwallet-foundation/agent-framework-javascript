import type { AgentContext } from '../../../../agent'
import type { DidDocument } from '../../domain'
import type { DidResolver } from '../../domain/DidResolver'
import type { DidResolutionResult } from '../../types'

import { CredoError } from '../../../../error'
import { DidRepository } from '../../repository'

import { getNumAlgoFromPeerDid, isValidPeerDid, PeerDidNumAlgo } from './didPeer'
import { didToNumAlgo0DidDocument } from './peerDidNumAlgo0'
import { didToNumAlgo2DidDocument } from './peerDidNumAlgo2'
import { didToNumAlgo4DidDocument, isShortFormDidPeer4 } from './peerDidNumAlgo4'

export class PeerDidResolver implements DidResolver {
  public readonly supportedMethods = ['peer']

  /**
   * No remote resolving done, did document is fetched from storage. To not pollute the cache we don't allow caching
   */
  public readonly allowsCaching = false

  /**
   * Did peer records are often server from local did doucment, but it's easier to handle it in
   * the peer did resolver.
   */
  public readonly allowsLocalDidRecord = false

  public async resolve(agentContext: AgentContext, did: string): Promise<DidResolutionResult> {
    const didRepository = agentContext.dependencyManager.resolve(DidRepository)

    const didDocumentMetadata = {}

    try {
      let didDocument: DidDocument

      if (!isValidPeerDid(did)) {
        throw new CredoError(`did ${did} is not a valid peer did`)
      }

      const numAlgo = getNumAlgoFromPeerDid(did)

      // For method 0, generate from did
      if (numAlgo === PeerDidNumAlgo.InceptionKeyWithoutDoc) {
        didDocument = didToNumAlgo0DidDocument(did)
      }
      // For Method 1, retrieve from storage
      else if (numAlgo === PeerDidNumAlgo.GenesisDoc) {
        // We can have multiple did document records stored for a single did (one created and one received). In this case it
        // doesn't matter which one we use, and they should be identical. So we just take the first one.
        const [didDocumentRecord] = await didRepository.findAllByDid(agentContext, did)

        if (!didDocumentRecord) {
          throw new CredoError(`No did record found for peer did ${did}.`)
        }

        if (!didDocumentRecord.didDocument) {
          throw new CredoError(`Found did record for method 1 peer did (${did}), but no did document.`)
        }

        didDocument = didDocumentRecord.didDocument
      }
      // For Method 2, generate from did
      else if (numAlgo === PeerDidNumAlgo.MultipleInceptionKeyWithoutDoc) {
        didDocument = didToNumAlgo2DidDocument(did)
      }
      // For Method 4, if short form is received, attempt to get the didDocument from stored record
      else {
        if (isShortFormDidPeer4(did)) {
          const [didRecord] = await didRepository.findAllByDid(agentContext, did)

          if (!didRecord) {
            throw new CredoError(`No did record found for peer did ${did}.`)
          }
          didDocument = didToNumAlgo4DidDocument(didRecord.did)
        } else {
          didDocument = didToNumAlgo4DidDocument(did)
        }
      }

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
