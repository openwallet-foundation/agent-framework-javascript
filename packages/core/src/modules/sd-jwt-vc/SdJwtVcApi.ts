import type {
  SdJwtVcSignOptions,
  SdJwtVcHeader,
  SdJwtVcPayload,
  SdJwtVcPresentOptions,
  SdJwtVcVerifyOptions,
} from './SdJwtVcOptions'
import type { SdJwtVcRecord } from './repository'
import type { Query, QueryOptions } from '../../storage/StorageService'

import { AgentContext } from '../../agent'
import { injectable } from '../../plugins'

import { SdJwtVcService } from './SdJwtVcService'

/**
 * @public
 */
@injectable()
export class SdJwtVcApi {
  private agentContext: AgentContext
  private sdJwtVcService: SdJwtVcService

  public constructor(agentContext: AgentContext, sdJwtVcService: SdJwtVcService) {
    this.agentContext = agentContext
    this.sdJwtVcService = sdJwtVcService
  }

  public async sign<Payload extends SdJwtVcPayload>(options: SdJwtVcSignOptions<Payload>) {
    return await this.sdJwtVcService.sign<Payload>(this.agentContext, options)
  }

  /**
   *
   * Create a compact presentation of the sd-jwt.
   * This presentation can be send in- or out-of-band to the verifier.
   *
   * Also, whether to include the holder key binding.
   */
  public async present<Payload extends SdJwtVcPayload = SdJwtVcPayload>(
    options: SdJwtVcPresentOptions<Payload>
  ): Promise<string> {
    return await this.sdJwtVcService.present(this.agentContext, options)
  }

  /**
   *
   * Verify an incoming sd-jwt. It will check whether everything is valid, but also returns parts of the validation.
   *
   * For example, you might still want to continue with a flow if not all the claims are included, but the signature is valid.
   *
   */
  public async verify<Header extends SdJwtVcHeader, Payload extends SdJwtVcPayload>(options: SdJwtVcVerifyOptions) {
    return await this.sdJwtVcService.verify<Header, Payload>(this.agentContext, options)
  }

  /**
   * Get and validate a sd-jwt-vc from a serialized JWT.
   */
  public fromCompact<Header extends SdJwtVcHeader, Payload extends SdJwtVcPayload>(sdJwtVcCompact: string) {
    return this.sdJwtVcService.fromCompact<Header, Payload>(sdJwtVcCompact)
  }

  public async store(compactSdJwtVc: string) {
    return await this.sdJwtVcService.store(this.agentContext, compactSdJwtVc)
  }

  public async getById(id: string): Promise<SdJwtVcRecord> {
    return await this.sdJwtVcService.getById(this.agentContext, id)
  }

  public async getAll(): Promise<Array<SdJwtVcRecord>> {
    return await this.sdJwtVcService.getAll(this.agentContext)
  }

  public async findAllByQuery(query: Query<SdJwtVcRecord>, queryOptions?: QueryOptions): Promise<Array<SdJwtVcRecord>> {
    return await this.sdJwtVcService.findByQuery(this.agentContext, query, queryOptions)
  }

  public async deleteById(id: string) {
    return await this.sdJwtVcService.deleteById(this.agentContext, id)
  }

  public async update(sdJwtVcRecord: SdJwtVcRecord) {
    return await this.sdJwtVcService.update(this.agentContext, sdJwtVcRecord)
  }
}
