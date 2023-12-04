import type { IInMemoryVerifierSessionManager } from './InMemoryVerifierSessionManager'
import type {
  ProofRequestWithMetadata,
  CreateProofRequestOptions,
  ProofRequestMetadata,
  VerifiedProofResponse,
  EndpointConfig,
} from './OpenId4VcVerifierServiceOptions'
import type { AgentContext, W3cVerifyPresentationResult } from '@aries-framework/core'
import type {
  AuthorizationResponsePayload,
  ClientMetadataOpts,
  PresentationVerificationCallback,
  SigningAlgo,
} from '@sphereon/did-auth-siop'
import type { Router } from 'express'

import {
  InjectionSymbols,
  Logger,
  W3cCredentialService,
  inject,
  injectable,
  AriesFrameworkError,
  W3cJsonLdVerifiablePresentation,
  JsonTransformer,
} from '@aries-framework/core'
import {
  RP,
  ResponseIss,
  RevocationVerification,
  SupportedVersion,
  ResponseMode,
  PropertyTarget,
  ResponseType,
  CheckLinkedDomain,
  PresentationDefinitionLocation,
  PassBy,
  VerificationMode,
  AuthorizationResponse,
} from '@sphereon/did-auth-siop'
import bodyParser from 'body-parser'
import { EventEmitter } from 'events'

import { InMemoryVerifierSessionManager } from './InMemoryVerifierSessionManager'
import { OpenId4VcVerifierModuleConfig } from './OpenId4VcVerifierModuleConfig'
import { staticOpOpenIdConfig, staticOpSiopConfig } from './OpenId4VcVerifierServiceOptions'
import {
  getSupportedDidMethods,
  getSuppliedSignatureFromVerificationMethod,
  getResolver,
  getSupportedJwaSignatureAlgorithms,
} from './utils'

/**
 * @internal
 */
@injectable()
export class OpenId4VcVerifierService {
  private logger: Logger
  private w3cCredentialService: W3cCredentialService
  private openId4VcVerifierModuleConfig: OpenId4VcVerifierModuleConfig
  private sessionManager: IInMemoryVerifierSessionManager
  private eventEmitter: EventEmitter

  public constructor(
    @inject(InjectionSymbols.Logger) logger: Logger,
    w3cCredentialService: W3cCredentialService,
    openId4VcVerifierModuleConfig: OpenId4VcVerifierModuleConfig
  ) {
    this.w3cCredentialService = w3cCredentialService
    this.logger = logger
    this.openId4VcVerifierModuleConfig = openId4VcVerifierModuleConfig
    this.eventEmitter = new EventEmitter()
    this.sessionManager =
      openId4VcVerifierModuleConfig.sessionManager ?? new InMemoryVerifierSessionManager(this.eventEmitter, logger)
  }

  public async getRelyingParty(
    agentContext: AgentContext,
    createProofRequestOptions: CreateProofRequestOptions,
    proofRequestMetadata?: ProofRequestMetadata
  ) {
    const {
      holderIdentifier,
      redirectUri,
      presentationDefinition,
      verificationMethod,
      holderMetadata: _holderClientMetadata,
    } = createProofRequestOptions

    const isVpRequest = presentationDefinition !== undefined

    let holderClientMetadata: ClientMetadataOpts
    if (_holderClientMetadata) {
      // use the provided client metadata
      holderClientMetadata = _holderClientMetadata
    } else if (holderIdentifier) {
      // Use OpenId Discovery to get the client metadata
      let reference_uri = holderIdentifier
      if (!holderIdentifier.endsWith('/.well-known/openid-configuration')) {
        reference_uri = holderIdentifier + '/.well-known/openid-configuration'
      }
      holderClientMetadata = { reference_uri, passBy: PassBy.REFERENCE, targets: PropertyTarget.REQUEST_OBJECT }
    } else if (isVpRequest) {
      // if neither clientMetadata nor issuer is provided, use a static config
      holderClientMetadata = staticOpOpenIdConfig
    } else {
      // if neither clientMetadata nor issuer is provided, use a static config
      holderClientMetadata = staticOpSiopConfig
    }

    const { signature, did, kid, alg } = await getSuppliedSignatureFromVerificationMethod(
      agentContext,
      verificationMethod
    )

    // Check if the OpenId Provider (Holder) can validate the request signature provided by the Relying Party (Verifier)
    const requestObjectSigningAlgValuesSupported = holderClientMetadata.requestObjectSigningAlgValuesSupported
    if (requestObjectSigningAlgValuesSupported && !requestObjectSigningAlgValuesSupported.includes(alg)) {
      throw new AriesFrameworkError(
        [
          `Cannot sign authorization request with '${alg}' that isn't supported by the OpenId Provider.`,
          `Supported algorithms are ${requestObjectSigningAlgValuesSupported}`,
        ].join('\n')
      )
    }

    // Check if the Relying Party (Verifier) can validate the IdToken provided by the OpenId Provider (Holder)
    const idTokenSigningAlgValuesSupported = holderClientMetadata.idTokenSigningAlgValuesSupported
    const rpSupportedSignatureAlgorithms = getSupportedJwaSignatureAlgorithms(agentContext) as unknown as SigningAlgo[]

    if (idTokenSigningAlgValuesSupported) {
      const possibleIdTokenSigningAlgValues = Array.isArray(idTokenSigningAlgValuesSupported)
        ? idTokenSigningAlgValuesSupported.filter((value) => rpSupportedSignatureAlgorithms.includes(value))
        : [idTokenSigningAlgValuesSupported].filter((value) => rpSupportedSignatureAlgorithms.includes(value))

      if (!possibleIdTokenSigningAlgValues) {
        throw new AriesFrameworkError(
          [
            `The OpenId Provider supports no signature algorithms that are supported by the Relying Party.`,
            `Relying Party supported algorithms are ${rpSupportedSignatureAlgorithms}.`,
            `OpenId Provider supported algorithms are ${idTokenSigningAlgValuesSupported}.`,
          ].join('\n')
        )
      }
    }

    const authorizationEndpoint = holderClientMetadata.authorization_endpoint ?? (isVpRequest ? 'openid:' : 'siopv2:')

    // Check: audience must be set to the issuer with dynamic disc otherwise self-issed.me/v2.
    const builder = RP.builder()
      .withClientId(verificationMethod.id)
      .withRedirectUri(redirectUri)
      .withIssuer(ResponseIss.SELF_ISSUED_V2)
      .withSuppliedSignature(signature, did, kid, alg)
      .withSupportedVersions([SupportedVersion.SIOPv2_D11, SupportedVersion.SIOPv2_D12_OID4VP_D18])
      .withClientMetadata(holderClientMetadata)
      .withCustomResolver(getResolver(agentContext))
      .withResponseMode(ResponseMode.POST)
      .withResponseType(isVpRequest ? [ResponseType.ID_TOKEN, ResponseType.VP_TOKEN] : ResponseType.ID_TOKEN)
      .withScope('openid')
      .withRequestBy(PassBy.VALUE)
      .withAuthorizationEndpoint(authorizationEndpoint)
      .withCheckLinkedDomain(CheckLinkedDomain.NEVER)
      .withRevocationVerification(RevocationVerification.NEVER)
      .withSessionManager(this.sessionManager)
      .withEventEmitter(this.eventEmitter)
    // .withWellknownDIDVerifyCallback

    if (proofRequestMetadata) {
      builder.withPresentationVerification(
        this.getPresentationVerificationCallback(agentContext, { challenge: proofRequestMetadata.challenge })
      )
    }

    if (isVpRequest) {
      builder.withPresentationDefinition({ definition: presentationDefinition }, [
        PropertyTarget.REQUEST_OBJECT,
        PropertyTarget.AUTHORIZATION_REQUEST,
      ])
    }

    const supportedDidMethods = getSupportedDidMethods(agentContext)
    for (const supportedDidMethod of supportedDidMethods) {
      builder.addDidMethod(supportedDidMethod)
    }

    return builder.build()
  }

  public async createProofRequest(
    agentContext: AgentContext,
    options: CreateProofRequestOptions
  ): Promise<ProofRequestWithMetadata> {
    const [noncePart1, noncePart2, state, correlationId] = await generateRandomValues(agentContext, 4)
    const challenge = noncePart1 + noncePart2

    const relyingParty = await this.getRelyingParty(agentContext, options)

    const authorizationRequest = await relyingParty.createAuthorizationRequest({
      correlationId,
      nonce: challenge,
      state,
    })

    const authorizationRequestUri = await authorizationRequest.uri()
    const encodedAuthorizationRequestUri = authorizationRequestUri.encodedUri

    const proofRequestMetadata = { correlationId, challenge, state }

    await this.sessionManager.saveVerifyProofResponseOptions(correlationId, {
      createProofRequestOptions: options,
      proofRequestMetadata,
    })

    return {
      proofRequest: encodedAuthorizationRequestUri,
      proofRequestMetadata,
    }
  }

  public async verifyProofResponse(
    agentContext: AgentContext,
    authorizationResponsePayload: AuthorizationResponsePayload
  ): Promise<VerifiedProofResponse> {
    let authorizationResponse: AuthorizationResponse
    try {
      authorizationResponse = await AuthorizationResponse.fromPayload(authorizationResponsePayload)
    } catch (error: unknown) {
      throw new AriesFrameworkError(
        `Unable to parse authorization response payload. ${JSON.stringify(authorizationResponsePayload)}`
      )
    }

    let correlationId: string | undefined
    const resNonce = (await authorizationResponse.getMergedProperty('nonce', false)) as string
    const resState = (await authorizationResponse.getMergedProperty('state', false)) as string
    correlationId = await this.sessionManager.getCorrelationIdByNonce(resNonce, false)
    if (!correlationId) {
      correlationId = await this.sessionManager.getCorrelationIdByState(resState, false)
    }

    if (!correlationId) {
      throw new AriesFrameworkError(`Unable to find correlationId for nonce '${resNonce}' or state '${resState}'`)
    }
    const result = await this.sessionManager.getVerifiyProofResponseOptions(correlationId)

    if (!result) {
      throw new AriesFrameworkError(`Unable to associate a request to the response correlationId '${correlationId}'`)
    }

    const { createProofRequestOptions, proofRequestMetadata } = result
    const presentationDefinition = createProofRequestOptions.presentationDefinition

    const presentationDefinitionsWithLocation = presentationDefinition
      ? [
          {
            definition: presentationDefinition,
            location: PresentationDefinitionLocation.CLAIMS_VP_TOKEN, // For now we always use the VP_TOKEN
          },
        ]
      : undefined

    const relyingParty = await this.getRelyingParty(agentContext, createProofRequestOptions, proofRequestMetadata)

    const response = await relyingParty.verifyAuthorizationResponse(authorizationResponsePayload, {
      audience: createProofRequestOptions.verificationMethod.id,
      correlationId,
      nonce: proofRequestMetadata.challenge,
      state: proofRequestMetadata.state,
      presentationDefinitions: presentationDefinitionsWithLocation,
      verification: {
        mode: VerificationMode.INTERNAL,
        resolveOpts: { noUniversalResolverFallback: true, resolver: getResolver(agentContext) },
      },
    })

    const idTokenPayload = await response.authorizationResponse.idToken.payload()

    return {
      idTokenPayload: idTokenPayload,
      submission: presentationDefinition ? response.oid4vpSubmission : undefined,
    }
  }

  private getPresentationVerificationCallback(
    agentContext: AgentContext,
    options: { challenge: string }
  ): PresentationVerificationCallback {
    const { challenge } = options
    return async (encodedPresentation, presentationSubmission) => {
      this.logger.debug(`Presentation response`, JsonTransformer.toJSON(encodedPresentation))
      this.logger.debug(`Presentation submission`, presentationSubmission)

      if (!encodedPresentation) {
        throw new AriesFrameworkError('Did not receive a presentation for verification')
      }

      let verificationResult: W3cVerifyPresentationResult
      if (typeof encodedPresentation === 'string') {
        const presentation = encodedPresentation
        verificationResult = await this.w3cCredentialService.verifyPresentation(agentContext, {
          presentation: presentation,
          challenge,
        })
      } else {
        const presentation = JsonTransformer.fromJSON(encodedPresentation, W3cJsonLdVerifiablePresentation)
        verificationResult = await this.w3cCredentialService.verifyPresentation(agentContext, {
          presentation: presentation,
          challenge,
        })
      }

      return { verified: verificationResult.isValid }
    }
  }

  public configureRouter = (agentContext: AgentContext, router: Router, endpointConfig: EndpointConfig) => {
    // parse application/x-www-form-urlencoded
    router.use(bodyParser.urlencoded({ extended: false }))

    // parse application/json
    router.use(bodyParser.json())

    if (endpointConfig.verificationEndpointConfig?.enabled) {
      router.post(
        endpointConfig.verificationEndpointConfig.verificationEndpointPath,
        async (request, response, next) => {
          try {
            const isVpRequest = request.body.presentation_submission !== undefined
            const verifierService = await agentContext.dependencyManager.resolve(OpenId4VcVerifierService)

            const authorizationResponse: AuthorizationResponsePayload = request.body
            if (isVpRequest)
              authorizationResponse.presentation_submission = JSON.parse(request.body.presentation_submission)

            const verifiedProofResponse = await verifierService.verifyProofResponse(agentContext, request.body)
            if (!endpointConfig.verificationEndpointConfig.proofResponseHandler) return response.status(200).send()

            const { status } = await endpointConfig.verificationEndpointConfig.proofResponseHandler(
              verifiedProofResponse
            )
            return response.status(status).send()
          } catch (error: unknown) {
            next(error)
          }

          return response.status(200).send()
        }
      )
    }

    return router
  }
}

async function generateRandomValues(agentContext: AgentContext, count: number) {
  const randomValuesPromises = Array.from({ length: count }, () => agentContext.wallet.generateNonce())
  return await Promise.all(randomValuesPromises)
}