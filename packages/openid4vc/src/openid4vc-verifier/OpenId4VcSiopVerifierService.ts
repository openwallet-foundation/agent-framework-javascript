import type {
  OpenId4VcSiopCreateAuthorizationRequestOptions,
  OpenId4VcSiopCreateAuthorizationRequestReturn,
  OpenId4VcSiopCreateVerifierOptions,
  OpenId4VcSiopVerifiedAuthorizationResponse,
  OpenId4VcSiopVerifyAuthorizationResponseOptions,
  ResponseMode,
} from './OpenId4VcSiopVerifierServiceOptions'
import type { OpenId4VcVerificationSessionRecord } from './repository'
import type { OpenId4VcSiopAuthorizationResponsePayload } from '../shared'
import type {
  AgentContext,
  DifPresentationExchangeDefinition,
  JwkJson,
  Query,
  QueryOptions,
  RecordSavedEvent,
  RecordUpdatedEvent,
} from '@credo-ts/core'
import type { ClientIdScheme, JarmClientMetadata, PresentationVerificationCallback } from '@sphereon/did-auth-siop'

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
  X509Service,
  getDomainFromUrl,
  KeyType,
  getJwkFromKey,
  MdocDeviceResponse,
  TypedArrayEncoder,
  Jwt,
  extractPresentationsWithDescriptorsFromSubmission,
} from '@credo-ts/core'
import {
  AuthorizationRequest,
  AuthorizationResponse,
  PassBy,
  PropertyTarget,
  RequestAud,
  ResponseIss,
  ResponseMode as SphereonResponseMode,
  ResponseType,
  RevocationVerification,
  RP,
  SupportedVersion,
} from '@sphereon/did-auth-siop'
import { extractPresentationsFromVpToken } from '@sphereon/did-auth-siop/dist/authorization-response/OpenID4VP'
import { filter, first, firstValueFrom, map, timeout } from 'rxjs'

import { storeActorIdForContextCorrelationId } from '../shared/router'
import { getVerifiablePresentationFromSphereonWrapped } from '../shared/transform'
import {
  getCreateJwtCallback,
  getSupportedJwaSignatureAlgorithms,
  getVerifyJwtCallback,
  openIdTokenIssuerToJwtIssuer,
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

    let authorizationResponseUrl = joinUriParts(this.config.baseUrl, [
      options.verifier.verifierId,
      this.config.authorizationEndpoint.endpointPath,
    ])

    const federationClientId = joinUriParts(this.config.baseUrl, [options.verifier.verifierId])

    const jwtIssuer =
      options.requestSigner.method === 'x5c'
        ? await openIdTokenIssuerToJwtIssuer(agentContext, {
            ...options.requestSigner,
            issuer: authorizationResponseUrl,
          })
        : options.requestSigner.method === 'openid-federation'
        ? await openIdTokenIssuerToJwtIssuer(agentContext, {
            ...options.requestSigner,
            entityId: federationClientId,
          })
        : await openIdTokenIssuerToJwtIssuer(agentContext, options.requestSigner)

    let clientIdScheme: ClientIdScheme
    let clientId: string

    if (jwtIssuer.method === 'x5c') {
      if (jwtIssuer.issuer !== authorizationResponseUrl) {
        throw new CredoError(
          `The jwtIssuer's issuer field must match the verifier's authorizationResponseUrl '${authorizationResponseUrl}'.`
        )
      }
      const leafCertificate = X509Service.getLeafCertificate(agentContext, { certificateChain: jwtIssuer.x5c })

      if (leafCertificate.sanDnsNames.includes(getDomainFromUrl(jwtIssuer.issuer))) {
        clientIdScheme = 'x509_san_dns'
        clientId = getDomainFromUrl(jwtIssuer.issuer)
        authorizationResponseUrl = jwtIssuer.issuer
      } else if (leafCertificate.sanUriNames.includes(jwtIssuer.issuer)) {
        clientIdScheme = 'x509_san_uri'
        clientId = jwtIssuer.issuer
        authorizationResponseUrl = clientId
      } else {
        throw new CredoError(
          `With jwtIssuer 'method' 'x5c' the jwtIssuer's 'issuer' field must either match the match a sanDnsName (FQDN) or sanUriName in the leaf x509 chain's leaf certificate.`
        )
      }
    } else if (jwtIssuer.method === 'did') {
      clientId = jwtIssuer.didUrl.split('#')[0]
      clientIdScheme = 'did'
    } else if (jwtIssuer.method === 'custom') {
      if (jwtIssuer.options?.method === 'openid-federation') {
        clientIdScheme = 'entity_id'
        clientId = federationClientId
      } else {
        throw new CredoError(
          `jwtIssuer 'method' 'custom' must have a 'method' property with value 'openid-federation' when using the 'custom' method.`
        )
      }
    } else {
      throw new CredoError(
        `Unsupported jwt issuer method '${options.requestSigner.method}'. Only 'did', 'x5c' and 'custom' are supported.`
      )
    }

    const relyingParty = await this.getRelyingParty(agentContext, options.verifier, {
      presentationDefinition: options.presentationExchange?.definition,
      authorizationResponseUrl,
      clientId,
      clientIdScheme,
      responseMode: options.responseMode,
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
      jwtIssuer,
    })

    // NOTE: it's not possible to set the uri scheme when using the RP to create an auth request, only lower level
    // functions allow this. So we need to replace the uri scheme manually.
    let authorizationRequestUri = (await authorizationRequest.uri()).encodedUri
    if (options.presentationExchange && !options.idToken) {
      authorizationRequestUri = authorizationRequestUri.replace('openid://', 'openid4vp://')
    } else {
      authorizationRequestUri = authorizationRequestUri.replace('openid4vp://', 'openid://')
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
      jarmHeader?: { apu?: string; apv?: string }
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

    const verifier = await this.getVerifierByVerifierId(agentContext, options.verificationSession.verifierId)
    const requestClientId = await authorizationRequest.getMergedProperty<string>('client_id')
    // TODO: Is this needed for the verification of the federation?
    const requestClientIdScheme = await authorizationRequest.getMergedProperty<ClientIdScheme>('client_id_scheme')
    const requestNonce = await authorizationRequest.getMergedProperty<string>('nonce')
    const requestState = await authorizationRequest.getMergedProperty<string>('state')
    const responseUri = await authorizationRequest.getMergedProperty<string>('response_uri')
    const presentationDefinitionsWithLocation = await authorizationRequest.getPresentationDefinitions()

    if (!requestNonce || !requestClientId || !requestState) {
      throw new CredoError(
        `Unable to find nonce, state, or client_id in authorization request for verification session '${options.verificationSession.id}'`
      )
    }

    const authorizationResponseUrl = joinUriParts(this.config.baseUrl, [
      options.verificationSession.verifierId,
      this.config.authorizationEndpoint.endpointPath,
    ])

    const relyingParty = await this.getRelyingParty(agentContext, verifier, {
      presentationDefinition: presentationDefinitionsWithLocation?.[0]?.definition,
      authorizationResponseUrl,
      clientId: requestClientId,
      clientIdScheme: requestClientIdScheme,
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
          correlationId: options.verificationSession.id,
          nonce: requestNonce,
          audience: requestClientId,
          responseUri,
          mdocGeneratedNonce: options.jarmHeader?.apu
            ? TypedArrayEncoder.toUtf8String(TypedArrayEncoder.fromBase64(options.jarmHeader.apu))
            : undefined,
        }),
      },
    })

    const verificationSession = await verificationSessionUpdatedPromise
    const verifiedAuthorizationResponse = await this.getVerifiedAuthorizationResponse(verificationSession)

    return {
      ...verifiedAuthorizationResponse,

      verificationSession: await verificationSessionUpdatedPromise,
    }
  }

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
      const rawPresentations = authorizationResponse.payload.vp_token
        ? await extractPresentationsFromVpToken(authorizationResponse.payload.vp_token, {
            hasher: Hasher.hash,
          })
        : []

      // TODO: Probably wise to check against request for the location of the submission_data
      const submission =
        idToken?.payload?._vp_token?.presentation_submission ?? authorizationResponse.payload.presentation_submission
      if (!submission) {
        throw new CredoError('Unable to extract submission from the response.')
      }

      // FIXME: should return type be an array? As now it doesn't always match the submission
      const verifiablePresentations = Array.isArray(rawPresentations)
        ? rawPresentations.map(getVerifiablePresentationFromSphereonWrapped)
        : getVerifiablePresentationFromSphereonWrapped(rawPresentations)
      const definition = presentationDefinitions[0].definition

      presentationExchange = {
        definition,
        submission,
        // We always return this as an array
        presentations: Array.isArray(verifiablePresentations) ? verifiablePresentations : [verifiablePresentations],

        descriptors: extractPresentationsWithDescriptorsFromSubmission(verifiablePresentations, submission, definition),
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
      authorizationResponseParams,
      verifierId,
    }:
      | {
          authorizationResponse?: never
          authorizationResponseParams: {
            state?: string
            nonce?: string
          }
          verifierId?: string
        }
      | {
          authorizationResponse: OpenId4VcSiopAuthorizationResponsePayload
          authorizationResponseParams?: never
          verifierId?: string
        }
  ) {
    let nonce: string | undefined
    let state: string | undefined

    if (authorizationResponse) {
      const authorizationResponseInstance = await AuthorizationResponse.fromPayload(authorizationResponse).catch(() => {
        throw new CredoError(`Unable to parse authorization response payload. ${JSON.stringify(authorizationResponse)}`)
      })

      nonce = await authorizationResponseInstance.getMergedProperty<string>('nonce', {
        hasher: Hasher.hash,
      })
      state = await authorizationResponseInstance.getMergedProperty<string>('state', {
        hasher: Hasher.hash,
      })

      if (!nonce && !state) {
        throw new CredoError(
          'Could not extract nonce or state from authorization response. Unable to find OpenId4VcVerificationSession.'
        )
      }
    } else {
      if (authorizationResponseParams?.nonce && !authorizationResponseParams?.state) {
        throw new CredoError(
          'Either nonce or state must be provided if no authorization response is provided. Unable to find OpenId4VcVerificationSession.'
        )
      }
      nonce = authorizationResponseParams?.nonce
      state = authorizationResponseParams?.state
    }

    const verificationSession = await this.openId4VcVerificationSessionRepository.findSingleByQuery(agentContext, {
      nonce,
      payloadState: state,
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
      clientMetadata: options?.clientMetadata,
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

  public async getRelyingParty(
    agentContext: AgentContext,
    verifier: OpenId4VcVerifierRecord,
    {
      idToken,
      presentationDefinition,
      clientId,
      clientIdScheme,
      authorizationResponseUrl,
      responseMode,
    }: {
      responseMode?: ResponseMode
      idToken?: boolean
      presentationDefinition?: DifPresentationExchangeDefinition
      clientId: string
      authorizationResponseUrl: string
      clientIdScheme?: ClientIdScheme
    }
  ) {
    const signatureSuiteRegistry = agentContext.dependencyManager.resolve(SignatureSuiteRegistry)

    const supportedAlgs = getSupportedJwaSignatureAlgorithms(agentContext) as string[]
    const supportedProofTypes = signatureSuiteRegistry.supportedProofTypes

    // Check: audience must be set to the issuer with dynamic disc otherwise self-issued.me/v2.
    const builder = RP.builder()

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
      .getEventEmitterForVerifier(agentContext.contextCorrelationId, verifier.verifierId)

    const mode =
      !responseMode || responseMode === 'direct_post'
        ? SphereonResponseMode.DIRECT_POST
        : SphereonResponseMode.DIRECT_POST_JWT

    type JarmEncryptionJwk = JwkJson & { kid: string; use: 'enc' }
    let jarmEncryptionJwk: JarmEncryptionJwk | undefined

    if (mode === SphereonResponseMode.DIRECT_POST_JWT) {
      const key = await agentContext.wallet.createKey({ keyType: KeyType.P256 })
      jarmEncryptionJwk = { ...getJwkFromKey(key).toJson(), kid: key.fingerprint, use: 'enc' }
    }

    const jarmClientMetadata: (JarmClientMetadata & { jwks: { keys: JarmEncryptionJwk[] } }) | undefined =
      jarmEncryptionJwk
        ? {
            jwks: { keys: [jarmEncryptionJwk] },
            authorization_encrypted_response_alg: 'ECDH-ES',
            authorization_encrypted_response_enc: 'A256GCM',
          }
        : undefined

    builder
      .withClientId(clientId)
      .withResponseUri(authorizationResponseUrl)
      .withIssuer(ResponseIss.SELF_ISSUED_V2)
      .withAudience(RequestAud.SELF_ISSUED_V2)
      .withIssuer(ResponseIss.SELF_ISSUED_V2)
      .withSupportedVersions([
        SupportedVersion.SIOPv2_D11,
        SupportedVersion.SIOPv2_D12_OID4VP_D18,
        SupportedVersion.SIOPv2_D12_OID4VP_D20,
      ])
      .withResponseMode(mode)
      .withHasher(Hasher.hash)
      // FIXME: should allow verification of revocation
      // .withRevocationVerificationCallback()
      .withRevocationVerification(RevocationVerification.NEVER)
      .withSessionManager(new OpenId4VcRelyingPartySessionManager(agentContext, verifier.verifierId))
      .withEventEmitter(sphereonEventEmitter)
      .withResponseType(responseTypes)
      .withCreateJwtCallback(getCreateJwtCallback(agentContext))
      .withVerifyJwtCallback(getVerifyJwtCallback(agentContext))

      // TODO: we should probably allow some dynamic values here
      .withClientMetadata({
        ...jarmClientMetadata,
        ...verifier.clientMetadata,
        // FIXME: not passing client_id here means it will not be added
        // to the authorization request url (not the signed payload). Need
        // to fix that in Sphereon lib
        client_id: clientId,
        passBy: PassBy.VALUE,
        response_types_supported: [ResponseType.VP_TOKEN],
        subject_syntax_types_supported: [
          'urn:ietf:params:oauth:jwk-thumbprint',
          ...supportedDidMethods.map((m) => `did:${m}`),
        ],
        vp_formats: {
          mso_mdoc: {
            alg: supportedAlgs,
          },
          jwt_vc: {
            alg: supportedAlgs,
          },
          jwt_vc_json: {
            alg: supportedAlgs,
          },
          jwt_vp_json: {
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

    if (clientIdScheme) {
      builder.withClientIdScheme(clientIdScheme)
    }

    if (presentationDefinition) {
      builder.withPresentationDefinition({ definition: presentationDefinition }, [PropertyTarget.REQUEST_OBJECT])
    }
    if (responseTypes.includes(ResponseType.ID_TOKEN)) {
      builder.withScope('openid')
    }

    return builder.build()
  }

  private getPresentationVerificationCallback(
    agentContext: AgentContext,
    options: {
      nonce: string
      audience: string
      correlationId: string
      responseUri?: string
      mdocGeneratedNonce?: string
    }
  ): PresentationVerificationCallback {
    return async (encodedPresentation, presentationSubmission) => {
      try {
        this.logger.debug(`Presentation response`, JsonTransformer.toJSON(encodedPresentation))
        this.logger.debug(`Presentation submission`, presentationSubmission)

        if (!encodedPresentation) throw new CredoError('Did not receive a presentation for verification.')

        let isValid: boolean
        let reason: string | undefined = undefined

        if (typeof encodedPresentation === 'string' && encodedPresentation.includes('~')) {
          // TODO: it might be better here to look at the presentation submission to know
          // If presentation includes a ~, we assume it's an SD-JWT-VC

          const sdJwtVcApi = agentContext.dependencyManager.resolve(SdJwtVcApi)

          const verificationResult = await sdJwtVcApi.verify({
            compactSdJwtVc: encodedPresentation,
            keyBinding: {
              audience: options.audience,
              nonce: options.nonce,
            },
          })

          isValid = verificationResult.verification.isValid
          reason = verificationResult.isValid ? undefined : verificationResult.error.message
        } else if (typeof encodedPresentation === 'string' && !Jwt.format.test(encodedPresentation)) {
          if (!options.responseUri || !options.mdocGeneratedNonce) {
            isValid = false
            reason = 'Mdoc device response verification failed. Response uri and the mdocGeneratedNonce are not set'
          } else {
            const mdocDeviceResponse = MdocDeviceResponse.fromBase64Url(encodedPresentation)
            await mdocDeviceResponse.verify(agentContext, {
              sessionTranscriptOptions: {
                clientId: options.audience,
                mdocGeneratedNonce: options.mdocGeneratedNonce,
                responseUri: options.responseUri,
                verifierGeneratedNonce: options.nonce,
              },
              verificationContext: {
                openId4VcVerificationSessionId: options.correlationId,
              },
            })
            isValid = true
          }
        } else if (typeof encodedPresentation === 'string' && Jwt.format.test(encodedPresentation)) {
          const verificationResult = await this.w3cCredentialService.verifyPresentation(agentContext, {
            presentation: encodedPresentation,
            challenge: options.nonce,
            domain: options.audience,
            verificationContext: {
              openId4VcVerificationSessionId: options.correlationId,
            },
          })

          isValid = verificationResult.isValid
          reason = verificationResult.error?.message
        } else {
          const verificationResult = await this.w3cCredentialService.verifyPresentation(agentContext, {
            presentation: JsonTransformer.fromJSON(encodedPresentation, W3cJsonLdVerifiablePresentation),
            challenge: options.nonce,
            domain: options.audience,
          })

          isValid = verificationResult.isValid
          reason = verificationResult.error?.message
        }

        if (!isValid) {
          throw new Error(reason)
        }

        return {
          verified: true,
        }
      } catch (error) {
        agentContext.config.logger.warn('Error occurred during verification of presentation', {
          error,
        })
        return {
          verified: false,
          reason: error.message,
        }
      }
    }
  }
}
