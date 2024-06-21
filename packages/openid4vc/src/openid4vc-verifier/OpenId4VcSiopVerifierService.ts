import type {
  OpenId4VcSiopCreateAuthorizationRequestOptions,
  OpenId4VcSiopCreateAuthorizationRequestReturn,
  OpenId4VcSiopCreateVerifierOptions,
  OpenId4VcSiopVerifiedAuthorizationResponse,
  OpenId4VcSiopVerifyAuthorizationResponseOptions,
} from './OpenId4VcSiopVerifierServiceOptions'
import type { OpenId4VcVerificationSessionRecord } from './repository'
import type { OpenId4VcJwtIssuer, OpenId4VcSiopAuthorizationResponsePayload } from '../shared'
import type {
  AgentContext,
  DifPresentationExchangeDefinition,
  Query,
  QueryOptions,
  RecordSavedEvent,
  RecordUpdatedEvent,
} from '@credo-ts/core'
import type { PresentationVerificationCallback } from '@sphereon/did-auth-siop'

import {
  EventEmitter,
  RepositoryEventTypes,
  CredoError,
  inject,
  injectable,
  InjectionSymbols,
  joinUriParts,
  JsonTransformer,
  Logger,
  SdJwtVcApi,
  SignatureSuiteRegistry,
  utils,
  W3cCredentialService,
  W3cJsonLdVerifiablePresentation,
  Hasher,
  DidsApi,
} from '@credo-ts/core'
import {
  AuthorizationRequest,
  AuthorizationResponse,
  CheckLinkedDomain,
  PassBy,
  PropertyTarget,
  ResponseIss,
  ResponseMode,
  ResponseType,
  RevocationVerification,
  RP,
  SupportedVersion,
  VerificationMode,
} from '@sphereon/did-auth-siop'
import { extractPresentationsFromAuthorizationResponse } from '@sphereon/did-auth-siop/dist/authorization-response/OpenID4VP'
import { filter, first, firstValueFrom, map, timeout } from 'rxjs'

import { storeActorIdForContextCorrelationId } from '../shared/router'
import { getVerifiablePresentationFromSphereonWrapped } from '../shared/transform'
import {
  getSphereonDidResolver,
  getSphereonSuppliedSignatureFromJwtIssuer,
  getSupportedJwaSignatureAlgorithms,
} from '../shared/utils'

import { OpenId4VcVerificationSessionState } from './OpenId4VcVerificationSessionState'
import { OpenId4VcVerifierModuleConfig } from './OpenId4VcVerifierModuleConfig'
import {
  OpenId4VcVerificationSessionRepository,
  OpenId4VcVerifierRecord,
  OpenId4VcVerifierRepository,
} from './repository'
import { OpenId4VcRelyingPartyEventHandler } from './repository/OpenId4VcRelyingPartyEventEmitter'
import { OpenId4VcRelyingPartySessionManager } from './repository/OpenId4VcRelyingPartySessionManager'

/**
 * @internal
 */
@injectable()
export class OpenId4VcSiopVerifierService {
  public constructor(
    @inject(InjectionSymbols.Logger) private logger: Logger,
    private w3cCredentialService: W3cCredentialService,
    private openId4VcVerifierRepository: OpenId4VcVerifierRepository,
    private config: OpenId4VcVerifierModuleConfig,
    private openId4VcVerificationSessionRepository: OpenId4VcVerificationSessionRepository
  ) {}

  public async createAuthorizationRequest(
    agentContext: AgentContext,
    options: OpenId4VcSiopCreateAuthorizationRequestOptions & { verifier: OpenId4VcVerifierRecord }
  ): Promise<OpenId4VcSiopCreateAuthorizationRequestReturn> {
    const nonce = await agentContext.wallet.generateNonce()
    const state = await agentContext.wallet.generateNonce()

    // Correlation id will be the id of the verification session record
    const correlationId = utils.uuid()

    const relyingParty = await this.getRelyingParty(agentContext, options.verifier.verifierId, {
      presentationDefinition: options.presentationExchange?.definition,
      requestSigner: options.requestSigner,
    })

    // We always use shortened URIs currently
    const hostedAuthorizationRequestUri = joinUriParts(this.config.baseUrl, [
      options.verifier.verifierId,
      this.config.authorizationRequestEndpoint.endpointPath,
      // It doesn't really matter what the url is, as long as it's unique
      utils.uuid(),
    ])

    // This is very unfortunate, but storing state in sphereon's SiOP-OID4VP library
    // is done async, so we can't be certain yet that the verification session record
    // is created already when we have created the authorization request. So we need to
    // wait for a short while before we can be certain that the verification session record
    // is created. To not use arbitrary timeouts, we wait for the specific RecordSavedEvent
    // that is emitted when the verification session record is created.
    const eventEmitter = agentContext.dependencyManager.resolve(EventEmitter)
    const verificationSessionCreatedPromise = firstValueFrom(
      eventEmitter
        .observable<RecordSavedEvent<OpenId4VcVerificationSessionRecord>>(RepositoryEventTypes.RecordSaved)
        .pipe(
          filter((e) => e.metadata.contextCorrelationId === agentContext.contextCorrelationId),
          filter(
            (e) => e.payload.record.id === correlationId && e.payload.record.verifierId === options.verifier.verifierId
          ),
          first(),
          timeout({
            first: 10000,
            meta: 'OpenId4VcSiopVerifierService.createAuthorizationRequest',
          }),
          map((e) => e.payload.record)
        )
    )

    const authorizationRequest = await relyingParty.createAuthorizationRequest({
      correlationId,
      nonce,
      state,
      requestByReferenceURI: hostedAuthorizationRequestUri,
    })

    // NOTE: it's not possible to set the uri scheme when using the RP to create an auth request, only lower level
    // functions allow this. So we need to replace the uri scheme manually.
    let authorizationRequestUri = (await authorizationRequest.uri()).encodedUri
    if (options.presentationExchange && !options.idToken) {
      authorizationRequestUri = authorizationRequestUri.replace('openid://', 'openid4vp://')
    }

    const verificationSession = await verificationSessionCreatedPromise

    return {
      authorizationRequest: authorizationRequestUri,
      verificationSession,
    }
  }

  public async verifyAuthorizationResponse(
    agentContext: AgentContext,
    options: OpenId4VcSiopVerifyAuthorizationResponseOptions & {
      verificationSession: OpenId4VcVerificationSessionRecord
    }
  ): Promise<OpenId4VcSiopVerifiedAuthorizationResponse & { verificationSession: OpenId4VcVerificationSessionRecord }> {
    // Assert state
    options.verificationSession.assertState([
      OpenId4VcVerificationSessionState.RequestUriRetrieved,
      OpenId4VcVerificationSessionState.RequestCreated,
    ])

    const authorizationRequest = await AuthorizationRequest.fromUriOrJwt(
      options.verificationSession.authorizationRequestJwt
    )

    const requestClientId = await authorizationRequest.getMergedProperty<string>('client_id')
    const requestNonce = await authorizationRequest.getMergedProperty<string>('nonce')
    const requestState = await authorizationRequest.getMergedProperty<string>('state')
    const presentationDefinitionsWithLocation = await authorizationRequest.getPresentationDefinitions()

    if (!requestNonce || !requestClientId || !requestState) {
      throw new CredoError(
        `Unable to find nonce, state, or client_id in authorization request for verification session '${options.verificationSession.id}'`
      )
    }

    const relyingParty = await this.getRelyingParty(agentContext, options.verificationSession.verifierId, {
      presentationDefinition: presentationDefinitionsWithLocation?.[0]?.definition,
      clientId: requestClientId,
    })

    // This is very unfortunate, but storing state in sphereon's SiOP-OID4VP library
    // is done async, so we can't be certain yet that the verification session record
    // is updated already when we have verified the authorization response. So we need to
    // wait for a short while before we can be certain that the verification session record
    // is updated. To not use arbitrary timeouts, we wait for the specific RecordUpdatedEvent
    // that is emitted when the verification session record is updated.
    const eventEmitter = agentContext.dependencyManager.resolve(EventEmitter)
    const verificationSessionUpdatedPromise = firstValueFrom(
      eventEmitter
        .observable<RecordUpdatedEvent<OpenId4VcVerificationSessionRecord>>(RepositoryEventTypes.RecordUpdated)
        .pipe(
          filter((e) => e.metadata.contextCorrelationId === agentContext.contextCorrelationId),
          filter(
            (e) =>
              e.payload.record.id === options.verificationSession.id &&
              e.payload.record.verifierId === options.verificationSession.verifierId &&
              (e.payload.record.state === OpenId4VcVerificationSessionState.ResponseVerified ||
                e.payload.record.state === OpenId4VcVerificationSessionState.Error)
          ),
          first(),
          timeout({
            first: 10000,
            meta: 'OpenId4VcSiopVerifierService.verifyAuthorizationResponse',
          }),
          map((e) => e.payload.record)
        )
    )

    await relyingParty.verifyAuthorizationResponse(options.authorizationResponse, {
      audience: requestClientId,
      correlationId: options.verificationSession.id,
      state: requestState,
      presentationDefinitions: presentationDefinitionsWithLocation,
      verification: {
        presentationVerificationCallback: this.getPresentationVerificationCallback(agentContext, {
          nonce: requestNonce,
          audience: requestClientId,
        }),
        // FIXME: Supplied mode is not implemented.
        // See https://github.com/Sphereon-Opensource/SIOP-OID4VP/issues/55
        mode: VerificationMode.INTERNAL,
        resolveOpts: { noUniversalResolverFallback: true, resolver: getSphereonDidResolver(agentContext) },
      },
    })

    const verificationSession = await verificationSessionUpdatedPromise
    const verifiedAuthorizationResponse = await this.getVerifiedAuthorizationResponse(verificationSession)

    return {
      ...verifiedAuthorizationResponse,

      verificationSession: await verificationSessionUpdatedPromise,
    }
  }

  // TODO: we can also choose to store this in the verification session, however we can easily derive it
  // so it's probably easier to make changes in the future if we just store the raw payload.
  public async getVerifiedAuthorizationResponse(
    verificationSession: OpenId4VcVerificationSessionRecord
  ): Promise<OpenId4VcSiopVerifiedAuthorizationResponse> {
    verificationSession.assertState(OpenId4VcVerificationSessionState.ResponseVerified)

    if (!verificationSession.authorizationResponsePayload) {
      throw new CredoError('No authorization response payload found in the verification session.')
    }

    const authorizationResponse = await AuthorizationResponse.fromPayload(
      verificationSession.authorizationResponsePayload
    )
    const authorizationRequest = await AuthorizationRequest.fromUriOrJwt(verificationSession.authorizationRequestJwt)

    const idToken = authorizationResponse.idToken
      ? { payload: await authorizationResponse.idToken?.payload() }
      : undefined
    let presentationExchange: OpenId4VcSiopVerifiedAuthorizationResponse['presentationExchange'] | undefined = undefined

    const presentationDefinitions = await authorizationRequest.getPresentationDefinitions()
    if (presentationDefinitions && presentationDefinitions.length > 0) {
      const presentations = await extractPresentationsFromAuthorizationResponse(authorizationResponse, {
        hasher: Hasher.hash,
      })

      // TODO: Probably wise to check against request for the location of the submission_data
      const submission =
        idToken?.payload?._vp_token?.presentation_submission ?? authorizationResponse.payload.presentation_submission
      if (!submission) {
        throw new CredoError('Unable to extract submission from the response.')
      }

      presentationExchange = {
        definition: presentationDefinitions[0].definition,
        presentations: presentations.map(getVerifiablePresentationFromSphereonWrapped),
        submission,
      }
    }

    if (!idToken && !presentationExchange) {
      throw new CredoError('No idToken or presentationExchange found in the response.')
    }

    return {
      idToken,
      presentationExchange,
    }
  }

  /**
   * Find the verification session associated with an authorization response. You can optionally provide a verifier id
   * if the verifier that the response is associated with is already known.
   */
  public async findVerificationSessionForAuthorizationResponse(
    agentContext: AgentContext,
    {
      authorizationResponse,
      verifierId,
    }: {
      authorizationResponse: OpenId4VcSiopAuthorizationResponsePayload
      verifierId?: string
    }
  ) {
    const authorizationResponseInstance = await AuthorizationResponse.fromPayload(authorizationResponse).catch(() => {
      throw new CredoError(`Unable to parse authorization response payload. ${JSON.stringify(authorizationResponse)}`)
    })

    const responseNonce = await authorizationResponseInstance.getMergedProperty<string>('nonce', {
      hasher: Hasher.hash,
    })
    const responseState = await authorizationResponseInstance.getMergedProperty<string>('state', {
      hasher: Hasher.hash,
    })

    const verificationSession = await this.openId4VcVerificationSessionRepository.findSingleByQuery(agentContext, {
      nonce: responseNonce,
      payloadState: responseState,
      verifierId,
    })

    return verificationSession
  }

  public async getAllVerifiers(agentContext: AgentContext) {
    return this.openId4VcVerifierRepository.getAll(agentContext)
  }

  public async getVerifierByVerifierId(agentContext: AgentContext, verifierId: string) {
    return this.openId4VcVerifierRepository.getByVerifierId(agentContext, verifierId)
  }

  public async updateVerifier(agentContext: AgentContext, verifier: OpenId4VcVerifierRecord) {
    return this.openId4VcVerifierRepository.update(agentContext, verifier)
  }

  public async createVerifier(agentContext: AgentContext, options?: OpenId4VcSiopCreateVerifierOptions) {
    const openId4VcVerifier = new OpenId4VcVerifierRecord({
      verifierId: options?.verifierId ?? utils.uuid(),
    })

    await this.openId4VcVerifierRepository.save(agentContext, openId4VcVerifier)
    await storeActorIdForContextCorrelationId(agentContext, openId4VcVerifier.verifierId)
    return openId4VcVerifier
  }

  public async findVerificationSessionsByQuery(
    agentContext: AgentContext,
    query: Query<OpenId4VcVerificationSessionRecord>,
    queryOptions?: QueryOptions
  ) {
    return this.openId4VcVerificationSessionRepository.findByQuery(agentContext, query, queryOptions)
  }

  public async getVerificationSessionById(agentContext: AgentContext, verificationSessionId: string) {
    return this.openId4VcVerificationSessionRepository.getById(agentContext, verificationSessionId)
  }

  private async getRelyingParty(
    agentContext: AgentContext,
    verifierId: string,
    {
      idToken,
      presentationDefinition,
      requestSigner,
      clientId,
    }: {
      idToken?: boolean
      presentationDefinition?: DifPresentationExchangeDefinition
      requestSigner?: OpenId4VcJwtIssuer
      clientId?: string
    }
  ) {
    const authorizationResponseUrl = joinUriParts(this.config.baseUrl, [
      verifierId,
      this.config.authorizationEndpoint.endpointPath,
    ])

    const signatureSuiteRegistry = agentContext.dependencyManager.resolve(SignatureSuiteRegistry)

    const supportedAlgs = getSupportedJwaSignatureAlgorithms(agentContext) as string[]
    const supportedProofTypes = signatureSuiteRegistry.supportedProofTypes

    // Check: audience must be set to the issuer with dynamic disc otherwise self-issued.me/v2.
    const builder = RP.builder()

    let _clientId = clientId
    if (requestSigner) {
      const suppliedSignature = await getSphereonSuppliedSignatureFromJwtIssuer(agentContext, requestSigner)
      builder.withSignature(suppliedSignature)

      _clientId = suppliedSignature.did
    }

    if (!_clientId) {
      throw new CredoError("Either 'requestSigner' or 'clientId' must be provided.")
    }

    const responseTypes: ResponseType[] = []
    if (!presentationDefinition && idToken === false) {
      throw new CredoError('Either `presentationExchange` or `idToken` must be enabled')
    }
    if (presentationDefinition) {
      responseTypes.push(ResponseType.VP_TOKEN)
    }
    if (idToken === true || !presentationDefinition) {
      responseTypes.push(ResponseType.ID_TOKEN)
    }

    // FIXME: we now manually remove did:peer, we should probably allow the user to configure this
    const supportedDidMethods = agentContext.dependencyManager
      .resolve(DidsApi)
      .supportedResolverMethods.filter((m) => m !== 'peer')

    // The OpenId4VcRelyingPartyEventHandler is a global event handler that makes sure that
    // all the events are handled, and that the correct context is used for the events.
    const sphereonEventEmitter = agentContext.dependencyManager
      .resolve(OpenId4VcRelyingPartyEventHandler)
      .getEventEmitterForVerifier(agentContext.contextCorrelationId, verifierId)

    builder
      .withRedirectUri(authorizationResponseUrl)
      .withIssuer(ResponseIss.SELF_ISSUED_V2)
      .withSupportedVersions([SupportedVersion.SIOPv2_D11, SupportedVersion.SIOPv2_D12_OID4VP_D18])
      .withCustomResolver(getSphereonDidResolver(agentContext))
      .withResponseMode(ResponseMode.POST)
      .withHasher(Hasher.hash)
      .withCheckLinkedDomain(CheckLinkedDomain.NEVER)
      // FIXME: should allow verification of revocation
      // .withRevocationVerificationCallback()
      .withRevocationVerification(RevocationVerification.NEVER)
      .withSessionManager(new OpenId4VcRelyingPartySessionManager(agentContext, verifierId))
      .withEventEmitter(sphereonEventEmitter)
      .withResponseType(responseTypes)

      // TODO: we should probably allow some dynamic values here
      .withClientMetadata({
        client_id: _clientId,
        passBy: PassBy.VALUE,
        responseTypesSupported: [ResponseType.VP_TOKEN],
        subject_syntax_types_supported: supportedDidMethods.map((m) => `did:${m}`),
        vpFormatsSupported: {
          jwt_vc: {
            alg: supportedAlgs,
          },
          jwt_vc_json: {
            alg: supportedAlgs,
          },
          jwt_vp: {
            alg: supportedAlgs,
          },
          ldp_vc: {
            proof_type: supportedProofTypes,
          },
          ldp_vp: {
            proof_type: supportedProofTypes,
          },
          'vc+sd-jwt': {
            kb_jwt_alg_values: supportedAlgs,
            sd_jwt_alg_values: supportedAlgs,
          },
        },
      })

    if (presentationDefinition) {
      builder.withPresentationDefinition({ definition: presentationDefinition }, [PropertyTarget.REQUEST_OBJECT])
    }
    if (responseTypes.includes(ResponseType.ID_TOKEN)) {
      builder.withScope('openid')
    }

    for (const supportedDidMethod of supportedDidMethods) {
      builder.addDidMethod(supportedDidMethod)
    }

    return builder.build()
  }

  private getPresentationVerificationCallback(
    agentContext: AgentContext,
    options: { nonce: string; audience: string }
  ): PresentationVerificationCallback {
    return async (encodedPresentation, presentationSubmission) => {
      try {
        this.logger.debug(`Presentation response`, JsonTransformer.toJSON(encodedPresentation))
        this.logger.debug(`Presentation submission`, presentationSubmission)

        if (!encodedPresentation) throw new CredoError('Did not receive a presentation for verification.')

        let isValid: boolean

        // TODO: it might be better here to look at the presentation submission to know
        // If presentation includes a ~, we assume it's an SD-JWT-VC
        if (typeof encodedPresentation === 'string' && encodedPresentation.includes('~')) {
          const sdJwtVcApi = agentContext.dependencyManager.resolve(SdJwtVcApi)

          const verificationResult = await sdJwtVcApi.verify({
            compactSdJwtVc: encodedPresentation,
            keyBinding: {
              audience: options.audience,
              nonce: options.nonce,
            },
          })

          isValid = verificationResult.verification.isValid
        } else if (typeof encodedPresentation === 'string') {
          const verificationResult = await this.w3cCredentialService.verifyPresentation(agentContext, {
            presentation: encodedPresentation,
            challenge: options.nonce,
            domain: options.audience,
          })

          isValid = verificationResult.isValid
        } else {
          const verificationResult = await this.w3cCredentialService.verifyPresentation(agentContext, {
            presentation: JsonTransformer.fromJSON(encodedPresentation, W3cJsonLdVerifiablePresentation),
            challenge: options.nonce,
            domain: options.audience,
          })

          isValid = verificationResult.isValid
        }

        // FIXME: we throw an error here as there's a bug in sphereon library where they
        // don't check the returned 'verified' property and only catch errors thrown.
        // Once https://github.com/Sphereon-Opensource/SIOP-OID4VP/pull/70 is merged we
        // can remove this.
        if (!isValid) {
          throw new CredoError('Presentation verification failed.')
        }

        return {
          verified: isValid,
        }
      } catch (error) {
        agentContext.config.logger.warn('Error occurred during verification of presentation', {
          error,
        })
        throw error
      }
    }
  }
}
