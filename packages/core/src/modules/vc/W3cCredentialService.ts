import type {
  StoreCredentialOptions,
  W3cCreatePresentationOptions,
  W3cJsonLdVerifyCredentialOptions,
  W3cJsonLdVerifyPresentationOptions,
  W3cJwtVerifyCredentialOptions,
  W3cJwtVerifyPresentationOptions,
  W3cSignCredentialOptions,
  W3cSignPresentationOptions,
  W3cVerifyCredentialOptions,
  W3cVerifyPresentationOptions,
} from './W3cCredentialServiceOptions'
import type {
  W3cVerifiableCredential,
  W3cVerifiablePresentation,
  W3cVerifyCredentialResult,
  W3cVerifyPresentationResult,
} from './models'
import type { AgentContext } from '../../agent/context'
import type { Query, QueryOptions } from '../../storage/StorageService'

import { CredoError } from '../../error'
import { injectable } from '../../plugins'

import { CREDENTIALS_CONTEXT_V1_URL } from './constants'
import { W3cJsonLdVerifiableCredential } from './data-integrity'
import { W3cJsonLdCredentialService } from './data-integrity/W3cJsonLdCredentialService'
import { W3cJsonLdVerifiablePresentation } from './data-integrity/models/W3cJsonLdVerifiablePresentation'
import { W3cJwtVerifiableCredential, W3cJwtVerifiablePresentation } from './jwt-vc'
import { W3cJwtCredentialService } from './jwt-vc/W3cJwtCredentialService'
import { ClaimFormat } from './models'
import { W3cPresentation } from './models/presentation/W3cPresentation'
import { W3cCredentialRecord, W3cCredentialRepository } from './repository'

@injectable()
export class W3cCredentialService {
  private w3cCredentialRepository: W3cCredentialRepository
  private w3cJsonLdCredentialService: W3cJsonLdCredentialService
  private w3cJwtCredentialService: W3cJwtCredentialService

  public constructor(
    w3cCredentialRepository: W3cCredentialRepository,
    w3cJsonLdCredentialService: W3cJsonLdCredentialService,
    w3cJwtCredentialService: W3cJwtCredentialService
  ) {
    this.w3cCredentialRepository = w3cCredentialRepository
    this.w3cJsonLdCredentialService = w3cJsonLdCredentialService
    this.w3cJwtCredentialService = w3cJwtCredentialService
  }

  /**
   * Signs a credential
   *
   * @param credential the credential to be signed
   * @returns the signed credential
   */
  public async signCredential<Format extends ClaimFormat.JwtVc | ClaimFormat.LdpVc>(
    agentContext: AgentContext,
    options: W3cSignCredentialOptions<Format>
  ): Promise<W3cVerifiableCredential<Format>> {
    if (options.format === ClaimFormat.JwtVc) {
      const signed = await this.w3cJwtCredentialService.signCredential(agentContext, options)
      return signed as W3cVerifiableCredential<Format>
    } else if (options.format === ClaimFormat.LdpVc) {
      const signed = await this.w3cJsonLdCredentialService.signCredential(agentContext, options)
      return signed as W3cVerifiableCredential<Format>
    } else {
      throw new CredoError(`Unsupported format in options. Format must be either 'jwt_vc' or 'ldp_vc'`)
    }
  }

  /**
   * Verifies the signature(s) of a credential
   */
  public async verifyCredential(
    agentContext: AgentContext,
    options: W3cVerifyCredentialOptions
  ): Promise<W3cVerifyCredentialResult> {
    if (options.credential instanceof W3cJsonLdVerifiableCredential) {
      return this.w3cJsonLdCredentialService.verifyCredential(agentContext, options as W3cJsonLdVerifyCredentialOptions)
    } else if (options.credential instanceof W3cJwtVerifiableCredential || typeof options.credential === 'string') {
      return this.w3cJwtCredentialService.verifyCredential(agentContext, options as W3cJwtVerifyCredentialOptions)
    } else {
      throw new CredoError(
        `Unsupported credential type in options. Credential must be either a W3cJsonLdVerifiableCredential or a W3cJwtVerifiableCredential`
      )
    }
  }

  /**
   * Utility method that creates a {@link W3cPresentation} from one or more {@link W3cJsonLdVerifiableCredential}s.
   *
   * **NOTE: the presentation that is returned is unsigned.**
   *
   * @returns An instance of {@link W3cPresentation}
   */
  public async createPresentation(options: W3cCreatePresentationOptions): Promise<W3cPresentation> {
    const presentation = new W3cPresentation({
      context: [CREDENTIALS_CONTEXT_V1_URL],
      type: ['VerifiablePresentation'],
      verifiableCredential: options.credentials,
      holder: options.holder,
      id: options.id,
    })

    return presentation
  }

  /**
   * Signs a presentation including the credentials it includes
   *
   * @param presentation the presentation to be signed
   * @returns the signed presentation
   */
  public async signPresentation<Format extends ClaimFormat.JwtVp | ClaimFormat.LdpVp>(
    agentContext: AgentContext,
    options: W3cSignPresentationOptions<Format>
  ): Promise<W3cVerifiablePresentation<Format>> {
    if (options.format === ClaimFormat.JwtVp) {
      const signed = await this.w3cJwtCredentialService.signPresentation(agentContext, options)
      return signed as W3cVerifiablePresentation<Format>
    } else if (options.format === ClaimFormat.LdpVp) {
      const signed = await this.w3cJsonLdCredentialService.signPresentation(agentContext, options)
      return signed as W3cVerifiablePresentation<Format>
    } else {
      throw new CredoError(`Unsupported format in options. Format must be either 'jwt_vp' or 'ldp_vp'`)
    }
  }

  /**
   * Verifies a presentation including the credentials it includes
   *
   * @param presentation the presentation to be verified
   * @returns the verification result
   */
  public async verifyPresentation(
    agentContext: AgentContext,
    options: W3cVerifyPresentationOptions
  ): Promise<W3cVerifyPresentationResult> {
    if (options.presentation instanceof W3cJsonLdVerifiablePresentation) {
      return this.w3cJsonLdCredentialService.verifyPresentation(
        agentContext,
        options as W3cJsonLdVerifyPresentationOptions
      )
    } else if (
      options.presentation instanceof W3cJwtVerifiablePresentation ||
      typeof options.presentation === 'string'
    ) {
      return this.w3cJwtCredentialService.verifyPresentation(agentContext, options as W3cJwtVerifyPresentationOptions)
    } else {
      throw new CredoError(
        'Unsupported credential type in options. Presentation must be either a W3cJsonLdVerifiablePresentation or a W3cJwtVerifiablePresentation'
      )
    }
  }

  /**
   * Writes a credential to storage
   *
   * @param record the credential to be stored
   * @returns the credential record that was written to storage
   */
  public async storeCredential(
    agentContext: AgentContext,
    options: StoreCredentialOptions
  ): Promise<W3cCredentialRecord> {
    let expandedTypes: string[] = []

    // JsonLd credentials need expanded types to be stored.
    if (options.credential instanceof W3cJsonLdVerifiableCredential) {
      expandedTypes = await this.w3cJsonLdCredentialService.getExpandedTypesForCredential(
        agentContext,
        options.credential
      )
    }

    // Create an instance of the w3cCredentialRecord
    const w3cCredentialRecord = new W3cCredentialRecord({
      tags: { expandedTypes },
      credential: options.credential,
    })

    // Store the w3c credential record
    await this.w3cCredentialRepository.save(agentContext, w3cCredentialRecord)

    return w3cCredentialRecord
  }

  public async removeCredentialRecord(agentContext: AgentContext, id: string) {
    await this.w3cCredentialRepository.deleteById(agentContext, id)
  }

  public async getAllCredentialRecords(agentContext: AgentContext): Promise<W3cCredentialRecord[]> {
    return await this.w3cCredentialRepository.getAll(agentContext)
  }

  public async getCredentialRecordById(agentContext: AgentContext, id: string): Promise<W3cCredentialRecord> {
    return await this.w3cCredentialRepository.getById(agentContext, id)
  }

  public async findCredentialsByQuery(
    agentContext: AgentContext,
    query: Query<W3cCredentialRecord>,
    queryOptions?: QueryOptions
  ): Promise<W3cVerifiableCredential[]> {
    const result = await this.w3cCredentialRepository.findByQuery(agentContext, query, queryOptions)
    return result.map((record) => record.credential)
  }

  public async findCredentialRecordByQuery(
    agentContext: AgentContext,
    query: Query<W3cCredentialRecord>
  ): Promise<W3cVerifiableCredential | undefined> {
    const result = await this.w3cCredentialRepository.findSingleByQuery(agentContext, query)
    return result?.credential
  }
}
