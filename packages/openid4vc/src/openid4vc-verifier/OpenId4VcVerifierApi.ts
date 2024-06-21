import type {
  OpenId4VcSiopCreateAuthorizationRequestOptions,
  OpenId4VcSiopVerifyAuthorizationResponseOptions,
  OpenId4VcSiopCreateAuthorizationRequestReturn,
  OpenId4VcSiopCreateVerifierOptions,
} from './OpenId4VcSiopVerifierServiceOptions'
import type { OpenId4VcVerificationSessionRecord } from './repository'
import type { OpenId4VcSiopAuthorizationResponsePayload } from '../shared'
import type { Query, QueryOptions } from '@credo-ts/core'

import { injectable, AgentContext } from '@credo-ts/core'

import { OpenId4VcSiopVerifierService } from './OpenId4VcSiopVerifierService'
import { OpenId4VcVerifierModuleConfig } from './OpenId4VcVerifierModuleConfig'

/**
 * @public
 */
@injectable()
export class OpenId4VcVerifierApi {
  public constructor(
    public readonly config: OpenId4VcVerifierModuleConfig,
    private agentContext: AgentContext,
    private openId4VcSiopVerifierService: OpenId4VcSiopVerifierService
  ) {}

  /**
   * Retrieve all verifier records from storage
   */
  public async getAllVerifiers() {
    return this.openId4VcSiopVerifierService.getAllVerifiers(this.agentContext)
  }

  /**
   * Retrieve a verifier record from storage by its verified id
   */
  public async getVerifierByVerifierId(verifierId: string) {
    return this.openId4VcSiopVerifierService.getVerifierByVerifierId(this.agentContext, verifierId)
  }

  /**
   * Create a new verifier and store the new verifier record.
   */
  public async createVerifier(options?: OpenId4VcSiopCreateVerifierOptions) {
    return this.openId4VcSiopVerifierService.createVerifier(this.agentContext, options)
  }

  public async findVerificationSessionsByQuery(
    query: Query<OpenId4VcVerificationSessionRecord>,
    queryOptions?: QueryOptions
  ) {
    return this.openId4VcSiopVerifierService.findVerificationSessionsByQuery(this.agentContext, query, queryOptions)
  }

  public async getVerificationSessionById(verificationSessionId: string) {
    return this.openId4VcSiopVerifierService.getVerificationSessionById(this.agentContext, verificationSessionId)
  }

  /**
   * Create an authorization request, acting as a Relying Party (RP).
   *
   * Currently two types of requests are supported:
   *  - SIOP Self-Issued ID Token request: request to a Self-Issued OP from an RP
   *  - SIOP Verifiable Presentation Request: request to a Self-Issued OP from an RP, requesting a Verifiable Presentation using OpenID4VP
   *
   * Other flows (non-SIOP) are not supported at the moment, but can be added in the future.
   *
   * See {@link OpenId4VcSiopCreateAuthorizationRequestOptions} for detailed documentation on the options.
   */
  public async createAuthorizationRequest({
    verifierId,
    ...otherOptions
  }: OpenId4VcSiopCreateAuthorizationRequestOptions & {
    verifierId: string
  }): Promise<OpenId4VcSiopCreateAuthorizationRequestReturn> {
    const verifier = await this.getVerifierByVerifierId(verifierId)
    return await this.openId4VcSiopVerifierService.createAuthorizationRequest(this.agentContext, {
      ...otherOptions,
      verifier,
    })
  }

  /**
   * Verifies an authorization response, acting as a Relying Party (RP).
   *
   * It validates the ID Token, VP Token and the signature(s) of the received Verifiable Presentation(s)
   * as well as that the structure of the Verifiable Presentation matches the provided presentation definition.
   */
  public async verifyAuthorizationResponse({
    verificationSessionId,
    ...otherOptions
  }: OpenId4VcSiopVerifyAuthorizationResponseOptions & {
    verificationSessionId: string
  }) {
    const verificationSession = await this.getVerificationSessionById(verificationSessionId)
    return await this.openId4VcSiopVerifierService.verifyAuthorizationResponse(this.agentContext, {
      ...otherOptions,
      verificationSession,
    })
  }

  public async getVerifiedAuthorizationResponse(verificationSessionId: string) {
    const verificationSession = await this.getVerificationSessionById(verificationSessionId)
    return this.openId4VcSiopVerifierService.getVerifiedAuthorizationResponse(verificationSession)
  }

  public async findVerificationSessionForAuthorizationResponse(options: {
    authorizationResponse: OpenId4VcSiopAuthorizationResponsePayload
    verifierId?: string
  }) {
    return this.openId4VcSiopVerifierService.findVerificationSessionForAuthorizationResponse(this.agentContext, options)
  }
}
