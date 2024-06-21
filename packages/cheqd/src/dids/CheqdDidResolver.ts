import type { ParsedCheqdDid } from '../anoncreds/utils/identifiers'
import type { Metadata } from '@cheqd/ts-proto/cheqd/resource/v2'
import type { AgentContext, DidResolutionResult, DidResolver, ParsedDid } from '@credo-ts/core'

import { DidDocument, CredoError, utils, JsonTransformer } from '@credo-ts/core'

import {
  cheqdDidMetadataRegex,
  cheqdDidRegex,
  cheqdDidVersionRegex,
  cheqdDidVersionsRegex,
  cheqdResourceMetadataRegex,
  cheqdResourceRegex,
  parseCheqdDid,
} from '../anoncreds/utils/identifiers'
import { CheqdLedgerService } from '../ledger'

import { filterResourcesByNameAndType, getClosestResourceVersion, renderResourceData } from './didCheqdUtil'

export class CheqdDidResolver implements DidResolver {
  public readonly supportedMethods = ['cheqd']
  public readonly allowsCaching = true
  public readonly allowsLocalDidRecord = true

  public async resolve(agentContext: AgentContext, did: string, parsed: ParsedDid): Promise<DidResolutionResult> {
    const didDocumentMetadata = {}

    try {
      const parsedDid = parseCheqdDid(parsed.didUrl)
      if (!parsedDid) {
        throw new Error('Invalid DID')
      }

      switch (did) {
        case did.match(cheqdDidRegex)?.input:
          return await this.resolveDidDoc(agentContext, parsedDid.did)
        case did.match(cheqdDidVersionRegex)?.input: {
          const version = did.split('/')[2]
          return await this.resolveDidDoc(agentContext, parsedDid.did, version)
        }
        case did.match(cheqdDidVersionsRegex)?.input:
          return await this.resolveAllDidDocVersions(agentContext, parsedDid)
        case did.match(cheqdDidMetadataRegex)?.input:
          return await this.dereferenceCollectionResources(agentContext, parsedDid)
        case did.match(cheqdResourceMetadataRegex)?.input:
          return await this.dereferenceResourceMetadata(agentContext, parsedDid)
        default:
          return {
            didDocument: null,
            didDocumentMetadata,
            didResolutionMetadata: {
              error: 'Invalid request',
              message: `Unsupported did Url: '${did}'`,
            },
          }
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

  public async resolveResource(agentContext: AgentContext, did: string) {
    const cheqdLedgerService = agentContext.dependencyManager.resolve(CheqdLedgerService)
    try {
      const parsedDid = parseCheqdDid(did)
      if (!parsedDid) {
        throw new Error('Invalid DID')
      }

      const { params, id } = parsedDid
      let resourceId: string
      if (did.match(cheqdResourceRegex)?.input) {
        resourceId = did.split('/')[2]
      } else if (params && params.resourceName && params.resourceType) {
        let resources = (await cheqdLedgerService.resolveCollectionResources(parsedDid.did, id)).resources
        resources = filterResourcesByNameAndType(resources, params.resourceName, params.resourceType)
        if (!resources.length) {
          throw new Error(`No resources found`)
        }

        let resource: Metadata | undefined
        if (params.version) {
          resource = resources.find((resource) => resource.version == params.version)
        } else {
          const date = params.resourceVersionTime ? new Date(Number(params.resourceVersionTime) * 1000) : new Date()
          // find the resourceId closest to the created time
          resource = getClosestResourceVersion(resources, date)
        }

        if (!resource) {
          throw new Error(`No resources found`)
        }

        resourceId = resource.id
      } else {
        return {
          error: 'notFound',
          message: `resolver_error: Invalid did url '${did}'`,
        }
      }
      if (!utils.isValidUuid(resourceId)) {
        throw new Error('Invalid resource Id')
      }

      const { resource, metadata } = await cheqdLedgerService.resolveResource(parsedDid.did, id, resourceId)
      if (!resource || !metadata) {
        throw new Error('resolver_error: Unable to resolve resource, Please try again')
      }

      const result = await renderResourceData(resource.data, metadata.mediaType)
      return {
        resource: result,
        resourceMetadata: metadata,
        resourceResolutionMetadata: {},
      }
    } catch (error) {
      return {
        error: 'notFound',
        message: `resolver_error: Unable to resolve resource '${did}': ${error}`,
      }
    }
  }

  private async resolveAllDidDocVersions(agentContext: AgentContext, parsedDid: ParsedCheqdDid) {
    const cheqdLedgerService = agentContext.dependencyManager.resolve(CheqdLedgerService)
    const { did } = parsedDid

    const { didDocumentVersionsMetadata } = await cheqdLedgerService.resolveMetadata(did)
    return {
      didDocument: new DidDocument({ id: did }),
      didDocumentMetadata: didDocumentVersionsMetadata,
      didResolutionMetadata: {},
    }
  }

  private async dereferenceCollectionResources(agentContext: AgentContext, parsedDid: ParsedCheqdDid) {
    const cheqdLedgerService = agentContext.dependencyManager.resolve(CheqdLedgerService)
    const { did, id } = parsedDid

    const metadata = await cheqdLedgerService.resolveCollectionResources(did, id)
    return {
      didDocument: new DidDocument({ id: did }),
      didDocumentMetadata: {
        linkedResourceMetadata: metadata,
      },
      didResolutionMetadata: {},
    }
  }

  private async dereferenceResourceMetadata(agentContext: AgentContext, parsedDid: ParsedCheqdDid) {
    const cheqdLedgerService = agentContext.dependencyManager.resolve(CheqdLedgerService)
    const { did, id } = parsedDid

    if (!parsedDid.path) {
      throw new CredoError(`Missing path in did ${parsedDid.did}`)
    }

    const [, , resourceId] = parsedDid.path.split('/')

    if (!resourceId) {
      throw new CredoError(`Missing resource id in didUrl ${parsedDid.didUrl}`)
    }

    const metadata = await cheqdLedgerService.resolveResourceMetadata(did, id, resourceId)
    return {
      didDocument: new DidDocument({ id: did }),
      didDocumentMetadata: {
        linkedResourceMetadata: metadata,
      },
      didResolutionMetadata: {},
    }
  }

  private async resolveDidDoc(agentContext: AgentContext, did: string, version?: string): Promise<DidResolutionResult> {
    const cheqdLedgerService = agentContext.dependencyManager.resolve(CheqdLedgerService)

    const { didDocument, didDocumentMetadata } = await cheqdLedgerService.resolve(did, version)
    const { resources } = await cheqdLedgerService.resolveCollectionResources(did, did.split(':')[3])
    didDocumentMetadata.linkedResourceMetadata = resources

    return {
      didDocument: JsonTransformer.fromJSON(didDocument, DidDocument),
      didDocumentMetadata,
      didResolutionMetadata: {},
    }
  }
}
