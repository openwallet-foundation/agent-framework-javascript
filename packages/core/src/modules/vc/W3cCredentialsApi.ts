import type {
  StoreCredentialOptions,
  W3cCreatePresentationOptions,
  W3cSignCredentialOptions,
  W3cSignPresentationOptions,
  W3cVerifyCredentialOptions,
  W3cVerifyPresentationOptions,
} from './W3cCredentialServiceOptions'
import type { W3cVerifiableCredential, ClaimFormat } from './models'
import type { W3cCredentialRecord } from './repository'
import type { Query, QueryOptions } from '../../storage/StorageService'

import { AgentContext } from '../../agent'
import { injectable } from '../../plugins'

import { W3cCredentialService } from './W3cCredentialService'

/**
 * @public
 */
@injectable()
export class W3cCredentialsApi {
  private agentContext: AgentContext
  private w3cCredentialService: W3cCredentialService

  public constructor(agentContext: AgentContext, w3cCredentialService: W3cCredentialService) {
    this.agentContext = agentContext
    this.w3cCredentialService = w3cCredentialService
  }

  public async storeCredential(options: StoreCredentialOptions): Promise<W3cCredentialRecord> {
    return this.w3cCredentialService.storeCredential(this.agentContext, options)
  }

  public async removeCredentialRecord(id: string) {
    return this.w3cCredentialService.removeCredentialRecord(this.agentContext, id)
  }

  public async getAllCredentialRecords(): Promise<W3cCredentialRecord[]> {
    return this.w3cCredentialService.getAllCredentialRecords(this.agentContext)
  }

  public async getCredentialRecordById(id: string): Promise<W3cCredentialRecord> {
    return this.w3cCredentialService.getCredentialRecordById(this.agentContext, id)
  }

  public async findCredentialRecordsByQuery(
    query: Query<W3cCredentialRecord>,
    queryOptions?: QueryOptions
  ): Promise<W3cVerifiableCredential[]> {
    return this.w3cCredentialService.findCredentialsByQuery(this.agentContext, query, queryOptions)
  }

  public async signCredential<Format extends ClaimFormat.JwtVc | ClaimFormat.LdpVc>(
    options: W3cSignCredentialOptions<Format>
  ) {
    return this.w3cCredentialService.signCredential<Format>(this.agentContext, options)
  }

  public async verifyCredential(options: W3cVerifyCredentialOptions) {
    return this.w3cCredentialService.verifyCredential(this.agentContext, options)
  }

  public async createPresentation(options: W3cCreatePresentationOptions) {
    return this.w3cCredentialService.createPresentation(options)
  }

  public async signPresentation<Format extends ClaimFormat.JwtVp | ClaimFormat.LdpVp>(
    options: W3cSignPresentationOptions<Format>
  ) {
    return this.w3cCredentialService.signPresentation<Format>(this.agentContext, options)
  }

  public async verifyPresentation(options: W3cVerifyPresentationOptions) {
    return this.w3cCredentialService.verifyPresentation(this.agentContext, options)
  }
}
