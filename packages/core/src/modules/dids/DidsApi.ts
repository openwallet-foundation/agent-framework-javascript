import type { StoreDidOptions } from './DidsApiOptions'
import type {
  DidCreateOptions,
  DidCreateResult,
  DidDeactivateOptions,
  DidDeactivateResult,
  DidResolutionOptions,
  DidUpdateOptions,
  DidUpdateResult,
} from './types'

import { AgentContext } from '../../agent'
import { injectable } from '../../plugins'

import { DidsModuleConfig } from './DidsModuleConfig'
import { DidRepository } from './repository'
import { DidRegistrarService, DidResolverService } from './services'

@injectable()
export class DidsApi {
  public config: DidsModuleConfig

  private didResolverService: DidResolverService
  private didRegistrarService: DidRegistrarService
  private didRepository: DidRepository
  private agentContext: AgentContext

  public constructor(
    didResolverService: DidResolverService,
    didRegistrarService: DidRegistrarService,
    didRepository: DidRepository,
    agentContext: AgentContext,
    config: DidsModuleConfig
  ) {
    this.didResolverService = didResolverService
    this.didRegistrarService = didRegistrarService
    this.didRepository = didRepository
    this.agentContext = agentContext
    this.config = config
  }

  /**
   * Resolve a did to a did document.
   *
   * Follows the interface as defined in https://w3c-ccg.github.io/did-resolution/
   */
  public resolve(didUrl: string, options?: DidResolutionOptions) {
    return this.didResolverService.resolve(this.agentContext, didUrl, options)
  }

  /**
   * Create, register and store a did and did document.
   *
   * Follows the interface as defined in https://identity.foundation/did-registration
   */
  public create<CreateOptions extends DidCreateOptions = DidCreateOptions>(
    options: CreateOptions
  ): Promise<DidCreateResult> {
    return this.didRegistrarService.create<CreateOptions>(this.agentContext, options)
  }

  /**
   * Update an existing did document.
   *
   * Follows the interface as defined in https://identity.foundation/did-registration
   */
  public update<UpdateOptions extends DidUpdateOptions = DidUpdateOptions>(
    options: UpdateOptions
  ): Promise<DidUpdateResult> {
    return this.didRegistrarService.update(this.agentContext, options)
  }

  /**
   * Deactivate an existing did.
   *
   * Follows the interface as defined in https://identity.foundation/did-registration
   */
  public deactivate<DeactivateOptions extends DidDeactivateOptions = DidDeactivateOptions>(
    options: DeactivateOptions
  ): Promise<DidDeactivateResult> {
    return this.didRegistrarService.deactivate(this.agentContext, options)
  }

  /**
   * Resolve a did to a did document. This won't return the associated metadata as defined
   * in the did resolution specification, and will throw an error if the did document could not
   * be resolved.
   */
  public resolveDidDocument(didUrl: string) {
    return this.didResolverService.resolveDidDocument(this.agentContext, didUrl)
  }

  /**
   * Get a list of all dids created by the agent. This will return a list of {@link DidRecord} objects.
   * Each document will have an id property with the value of the did. Optionally, it will contain a did document,
   * but this is only for documents that can't be resolved from the did itself or remotely.
   *
   * You can call `${@link DidsModule.resolve} to resolve the did document based on the did itself.
   */
  public getCreatedDids({ method, did }: { method?: string; did?: string } = {}) {
    return this.didRepository.getCreatedDids(this.agentContext, { method, did })
  }

  /**
   * Store a did document that was created outside of the agent. This will create a `DidRecord` for the did
   * and will allow the did to be used in other parts of the agent. If you need to create a new did document,
   * you can use the {@link DidsApi.create} method to create and register the did.
   *
   * NOTE: You need to make sure the keys in the did document are stored in the agent wallet before you can
   * use them for other operations. You can use the {@link WalletApi.createKey} method to import keys based
   * on a seed or privateKey
   */
  public async storeCreatedDid({ didDocument }: StoreDidOptions) {
    await this.didRepository.storeCreatedDid(this.agentContext, {
      did: didDocument.id,
      didDocument,
      tags: {
        recipientKeyFingerprints: didDocument.recipientKeys.map((key) => key.fingerprint),
      },
    })
  }
}
