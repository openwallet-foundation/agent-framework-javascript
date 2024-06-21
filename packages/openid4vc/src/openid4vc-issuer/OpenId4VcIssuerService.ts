import type {
  OpenId4VciCreateCredentialResponseOptions,
  OpenId4VciCreateCredentialOfferOptions,
  OpenId4VciCreateIssuerOptions,
  OpenId4VciPreAuthorizedCodeFlowConfig,
  OpenId4VcIssuerMetadata,
  OpenId4VciSignSdJwtCredential,
  OpenId4VciSignW3cCredential,
} from './OpenId4VcIssuerServiceOptions'
import type { OpenId4VcIssuanceSessionRecord } from './repository'
import type {
  OpenId4VcCredentialHolderBinding,
  OpenId4VciCredentialOfferPayload,
  OpenId4VciCredentialRequest,
  OpenId4VciCredentialSupported,
  OpenId4VciCredentialSupportedWithId,
} from '../shared'
import type { AgentContext, DidDocument, Query, QueryOptions } from '@credo-ts/core'
import type { Grant, JWTVerifyCallback } from '@sphereon/oid4vci-common'
import type {
  CredentialDataSupplier,
  CredentialDataSupplierArgs,
  CredentialIssuanceInput,
  CredentialSignerCallback,
} from '@sphereon/oid4vci-issuer'
import type { ICredential } from '@sphereon/ssi-types'

import {
  SdJwtVcApi,
  CredoError,
  ClaimFormat,
  DidsApi,
  equalsIgnoreOrder,
  getJwkFromJson,
  getJwkFromKey,
  getKeyFromVerificationMethod,
  injectable,
  joinUriParts,
  JsonEncoder,
  JsonTransformer,
  JwsService,
  Jwt,
  KeyType,
  utils,
  W3cCredentialService,
} from '@credo-ts/core'
import { VcIssuerBuilder } from '@sphereon/oid4vci-issuer'

import { getOfferedCredentials, OpenId4VciCredentialFormatProfile } from '../shared'
import { storeActorIdForContextCorrelationId } from '../shared/router'
import { getSphereonVerifiableCredential } from '../shared/transform'
import { getProofTypeFromKey } from '../shared/utils'

import { OpenId4VcIssuanceSessionState } from './OpenId4VcIssuanceSessionState'
import { OpenId4VcIssuerModuleConfig } from './OpenId4VcIssuerModuleConfig'
import { OpenId4VcIssuerRepository, OpenId4VcIssuerRecord, OpenId4VcIssuanceSessionRepository } from './repository'
import { OpenId4VcCNonceStateManager } from './repository/OpenId4VcCNonceStateManager'
import { OpenId4VcCredentialOfferSessionStateManager } from './repository/OpenId4VcCredentialOfferSessionStateManager'
import { OpenId4VcCredentialOfferUriStateManager } from './repository/OpenId4VcCredentialOfferUriStateManager'
import { getCNonceFromCredentialRequest } from './util/credentialRequest'

const w3cOpenId4VcFormats = [
  OpenId4VciCredentialFormatProfile.JwtVcJson,
  OpenId4VciCredentialFormatProfile.JwtVcJsonLd,
  OpenId4VciCredentialFormatProfile.LdpVc,
]

/**
 * @internal
 */
@injectable()
export class OpenId4VcIssuerService {
  private w3cCredentialService: W3cCredentialService
  private jwsService: JwsService
  private openId4VcIssuerConfig: OpenId4VcIssuerModuleConfig
  private openId4VcIssuerRepository: OpenId4VcIssuerRepository
  private openId4VcIssuanceSessionRepository: OpenId4VcIssuanceSessionRepository

  public constructor(
    w3cCredentialService: W3cCredentialService,
    jwsService: JwsService,
    openId4VcIssuerConfig: OpenId4VcIssuerModuleConfig,
    openId4VcIssuerRepository: OpenId4VcIssuerRepository,
    openId4VcIssuanceSessionRepository: OpenId4VcIssuanceSessionRepository
  ) {
    this.w3cCredentialService = w3cCredentialService
    this.jwsService = jwsService
    this.openId4VcIssuerConfig = openId4VcIssuerConfig
    this.openId4VcIssuerRepository = openId4VcIssuerRepository
    this.openId4VcIssuanceSessionRepository = openId4VcIssuanceSessionRepository
  }

  public async createCredentialOffer(
    agentContext: AgentContext,
    options: OpenId4VciCreateCredentialOfferOptions & { issuer: OpenId4VcIssuerRecord }
  ) {
    const { preAuthorizedCodeFlowConfig, issuer, offeredCredentials } = options

    const vcIssuer = this.getVcIssuer(agentContext, issuer)

    // this checks if the structure of the credentials is correct
    // it throws an error if a offered credential cannot be found in the credentialsSupported
    getOfferedCredentials(options.offeredCredentials, vcIssuer.issuerMetadata.credentials_supported)

    const uniqueOfferedCredentials = Array.from(new Set(options.offeredCredentials))
    if (uniqueOfferedCredentials.length !== offeredCredentials.length) {
      throw new CredoError('All offered credentials must have unique ids.')
    }

    // We always use shortened URIs currently
    const hostedCredentialOfferUri = joinUriParts(vcIssuer.issuerMetadata.credential_issuer, [
      this.openId4VcIssuerConfig.credentialOfferEndpoint.endpointPath,
      // It doesn't really matter what the url is, as long as it's unique
      utils.uuid(),
    ])

    let { uri } = await vcIssuer.createCredentialOfferURI({
      grants: await this.getGrantsFromConfig(agentContext, preAuthorizedCodeFlowConfig),
      credentials: offeredCredentials,
      credentialOfferUri: hostedCredentialOfferUri,
      baseUri: options.baseUri,
      credentialDataSupplierInput: options.issuanceMetadata,
    })

    // FIXME: https://github.com/Sphereon-Opensource/OID4VCI/issues/102
    if (uri.includes(hostedCredentialOfferUri)) {
      uri = uri.replace(hostedCredentialOfferUri, encodeURIComponent(hostedCredentialOfferUri))
    }

    const issuanceSession = await this.openId4VcIssuanceSessionRepository.getSingleByQuery(agentContext, {
      credentialOfferUri: hostedCredentialOfferUri,
    })

    return {
      issuanceSession,
      credentialOffer: uri,
    }
  }

  /**
   * find the issuance session associated with a credential request. You can optionally provide a issuer id if
   * the issuer that the request is associated with is already known.
   */
  public async findIssuanceSessionForCredentialRequest(
    agentContext: AgentContext,
    { credentialRequest, issuerId }: { credentialRequest: OpenId4VciCredentialRequest; issuerId?: string }
  ) {
    const cNonce = getCNonceFromCredentialRequest(credentialRequest)

    const issuanceSession = await this.openId4VcIssuanceSessionRepository.findSingleByQuery(agentContext, {
      issuerId,
      cNonce,
    })

    return issuanceSession
  }

  public async createCredentialResponse(
    agentContext: AgentContext,
    options: OpenId4VciCreateCredentialResponseOptions & { issuanceSession: OpenId4VcIssuanceSessionRecord }
  ) {
    options.issuanceSession.assertState([
      OpenId4VcIssuanceSessionState.AccessTokenCreated,
      OpenId4VcIssuanceSessionState.CredentialRequestReceived,
      // It is possible to issue multiple credentials in one session
      OpenId4VcIssuanceSessionState.CredentialsPartiallyIssued,
    ])
    const { credentialRequest, issuanceSession } = options
    if (!credentialRequest.proof) throw new CredoError('No proof defined in the credentialRequest.')

    const issuer = await this.getIssuerByIssuerId(agentContext, options.issuanceSession.issuerId)

    const cNonce = getCNonceFromCredentialRequest(credentialRequest)
    if (issuanceSession.cNonce !== cNonce) {
      throw new CredoError('The cNonce in the credential request does not match the cNonce in the issuance session.')
    }

    if (!issuanceSession.cNonceExpiresAt) {
      throw new CredoError('Missing required cNonceExpiresAt in the issuance session. Assuming cNonce is not valid')
    }
    if (Date.now() > issuanceSession.cNonceExpiresAt.getTime()) {
      throw new CredoError('The cNonce has expired.')
    }

    const vcIssuer = this.getVcIssuer(agentContext, issuer)

    const credentialResponse = await vcIssuer.issueCredential({
      credentialRequest,
      tokenExpiresIn: this.openId4VcIssuerConfig.accessTokenEndpoint.tokenExpiresInSeconds,

      // This can just be combined with signing callback right?
      credentialDataSupplier: this.getCredentialDataSupplier(agentContext, { ...options, issuer }),
      credentialDataSupplierInput: issuanceSession.issuanceMetadata,
      responseCNonce: undefined,
    })

    const updatedIssuanceSession = await this.openId4VcIssuanceSessionRepository.getById(
      agentContext,
      issuanceSession.id
    )
    if (!credentialResponse.credential) {
      updatedIssuanceSession.state = OpenId4VcIssuanceSessionState.Error
      updatedIssuanceSession.errorMessage = 'No credential found in the issueCredentialResponse.'
      await this.openId4VcIssuanceSessionRepository.update(agentContext, updatedIssuanceSession)
      throw new CredoError(updatedIssuanceSession.errorMessage)
    }

    if (credentialResponse.acceptance_token) {
      updatedIssuanceSession.state = OpenId4VcIssuanceSessionState.Error
      updatedIssuanceSession.errorMessage = 'Acceptance token not yet supported.'
      await this.openId4VcIssuanceSessionRepository.update(agentContext, updatedIssuanceSession)
      throw new CredoError(updatedIssuanceSession.errorMessage)
    }

    return {
      credentialResponse,
      issuanceSession: updatedIssuanceSession,
    }
  }

  public async findIssuanceSessionsByQuery(
    agentContext: AgentContext,
    query: Query<OpenId4VcIssuanceSessionRecord>,
    queryOptions?: QueryOptions
  ) {
    return this.openId4VcIssuanceSessionRepository.findByQuery(agentContext, query, queryOptions)
  }

  public async getIssuanceSessionById(agentContext: AgentContext, issuanceSessionId: string) {
    return this.openId4VcIssuanceSessionRepository.getById(agentContext, issuanceSessionId)
  }

  public async getAllIssuers(agentContext: AgentContext) {
    return this.openId4VcIssuerRepository.getAll(agentContext)
  }

  public async getIssuerByIssuerId(agentContext: AgentContext, issuerId: string) {
    return this.openId4VcIssuerRepository.getByIssuerId(agentContext, issuerId)
  }

  public async updateIssuer(agentContext: AgentContext, issuer: OpenId4VcIssuerRecord) {
    return this.openId4VcIssuerRepository.update(agentContext, issuer)
  }

  public async createIssuer(agentContext: AgentContext, options: OpenId4VciCreateIssuerOptions) {
    // TODO: ideally we can store additional data with a key, such as:
    // - createdAt
    // - purpose
    const accessTokenSignerKey = await agentContext.wallet.createKey({
      keyType: KeyType.Ed25519,
    })
    const openId4VcIssuer = new OpenId4VcIssuerRecord({
      issuerId: options.issuerId ?? utils.uuid(),
      display: options.display,
      accessTokenPublicKeyFingerprint: accessTokenSignerKey.fingerprint,
      credentialsSupported: options.credentialsSupported,
    })

    await this.openId4VcIssuerRepository.save(agentContext, openId4VcIssuer)
    await storeActorIdForContextCorrelationId(agentContext, openId4VcIssuer.issuerId)
    return openId4VcIssuer
  }

  public async rotateAccessTokenSigningKey(agentContext: AgentContext, issuer: OpenId4VcIssuerRecord) {
    const accessTokenSignerKey = await agentContext.wallet.createKey({
      keyType: KeyType.Ed25519,
    })

    // TODO: ideally we can remove the previous key
    issuer.accessTokenPublicKeyFingerprint = accessTokenSignerKey.fingerprint
    await this.openId4VcIssuerRepository.update(agentContext, issuer)
  }

  public getIssuerMetadata(agentContext: AgentContext, issuerRecord: OpenId4VcIssuerRecord): OpenId4VcIssuerMetadata {
    const config = agentContext.dependencyManager.resolve(OpenId4VcIssuerModuleConfig)
    const issuerUrl = joinUriParts(config.baseUrl, [issuerRecord.issuerId])

    const issuerMetadata = {
      issuerUrl,
      tokenEndpoint: joinUriParts(issuerUrl, [config.accessTokenEndpoint.endpointPath]),
      credentialEndpoint: joinUriParts(issuerUrl, [config.credentialEndpoint.endpointPath]),
      credentialsSupported: issuerRecord.credentialsSupported,
      issuerDisplay: issuerRecord.display,
    } satisfies OpenId4VcIssuerMetadata

    return issuerMetadata
  }

  private getJwtVerifyCallback = (agentContext: AgentContext): JWTVerifyCallback<DidDocument> => {
    return async (opts) => {
      let didDocument = undefined as DidDocument | undefined
      const { isValid, jws } = await this.jwsService.verifyJws(agentContext, {
        jws: opts.jwt,
        // Only handles kid as did resolution. JWK is handled by jws service
        jwkResolver: async ({ protectedHeader: { kid } }) => {
          if (!kid) throw new CredoError('Missing kid in protected header.')
          if (!kid.startsWith('did:')) throw new CredoError('Only did is supported for kid identifier')

          const didsApi = agentContext.dependencyManager.resolve(DidsApi)
          didDocument = await didsApi.resolveDidDocument(kid)
          const verificationMethod = didDocument.dereferenceKey(kid, ['authentication', 'assertionMethod'])
          const key = getKeyFromVerificationMethod(verificationMethod)
          return getJwkFromKey(key)
        },
      })

      if (!isValid) throw new CredoError('Could not verify JWT signature.')

      // TODO: the jws service should return some better decoded metadata also from the resolver
      // as currently is less useful if you afterwards need properties from the JWS
      const firstJws = jws.signatures[0]
      const protectedHeader = JsonEncoder.fromBase64(firstJws.protected)
      return {
        jwt: { header: protectedHeader, payload: JsonEncoder.fromBase64(jws.payload) },
        kid: protectedHeader.kid,
        jwk: protectedHeader.jwk ? getJwkFromJson(protectedHeader.jwk) : undefined,
        did: didDocument?.id,
        alg: protectedHeader.alg,
        didDocument,
      }
    }
  }

  private getVcIssuer(agentContext: AgentContext, issuer: OpenId4VcIssuerRecord) {
    const issuerMetadata = this.getIssuerMetadata(agentContext, issuer)

    const builder = new VcIssuerBuilder()
      .withCredentialIssuer(issuerMetadata.issuerUrl)
      .withCredentialEndpoint(issuerMetadata.credentialEndpoint)
      .withTokenEndpoint(issuerMetadata.tokenEndpoint)
      .withCredentialsSupported(issuerMetadata.credentialsSupported)
      .withCNonceStateManager(new OpenId4VcCNonceStateManager(agentContext, issuer.issuerId))
      .withCredentialOfferStateManager(new OpenId4VcCredentialOfferSessionStateManager(agentContext, issuer.issuerId))
      .withCredentialOfferURIStateManager(new OpenId4VcCredentialOfferUriStateManager(agentContext, issuer.issuerId))
      .withJWTVerifyCallback(this.getJwtVerifyCallback(agentContext))
      .withCredentialSignerCallback(() => {
        throw new CredoError('Credential signer callback should be overwritten. This is a no-op')
      })

    if (issuerMetadata.authorizationServer) {
      builder.withAuthorizationServer(issuerMetadata.authorizationServer)
    }

    if (issuerMetadata.issuerDisplay) {
      builder.withIssuerDisplay(issuerMetadata.issuerDisplay)
    }

    return builder.build()
  }

  private async getGrantsFromConfig(
    agentContext: AgentContext,
    preAuthorizedCodeFlowConfig: OpenId4VciPreAuthorizedCodeFlowConfig
  ) {
    const grants: Grant = {
      'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
        'pre-authorized_code':
          preAuthorizedCodeFlowConfig.preAuthorizedCode ?? (await agentContext.wallet.generateNonce()),
        user_pin_required: preAuthorizedCodeFlowConfig.userPinRequired ?? false,
      },
    }

    return grants
  }

  private findOfferedCredentialsMatchingRequest(
    credentialOffer: OpenId4VciCredentialOfferPayload,
    credentialRequest: OpenId4VciCredentialRequest,
    credentialsSupported: OpenId4VciCredentialSupported[],
    issuanceSession: OpenId4VcIssuanceSessionRecord
  ): OpenId4VciCredentialSupportedWithId[] {
    const offeredCredentials = getOfferedCredentials(credentialOffer.credentials, credentialsSupported)

    return offeredCredentials.filter((offeredCredential) => {
      if (offeredCredential.format !== credentialRequest.format) return false
      if (issuanceSession.issuedCredentials.includes(offeredCredential.id)) return false

      if (
        credentialRequest.format === OpenId4VciCredentialFormatProfile.JwtVcJson &&
        offeredCredential.format === credentialRequest.format
      ) {
        return equalsIgnoreOrder(offeredCredential.types, credentialRequest.types)
      } else if (
        credentialRequest.format === OpenId4VciCredentialFormatProfile.JwtVcJsonLd &&
        offeredCredential.format === credentialRequest.format
      ) {
        return equalsIgnoreOrder(offeredCredential.types, credentialRequest.credential_definition.types)
      } else if (
        credentialRequest.format === OpenId4VciCredentialFormatProfile.LdpVc &&
        offeredCredential.format === credentialRequest.format
      ) {
        return equalsIgnoreOrder(offeredCredential.types, credentialRequest.credential_definition.types)
      } else if (
        credentialRequest.format === OpenId4VciCredentialFormatProfile.SdJwtVc &&
        offeredCredential.format === credentialRequest.format
      ) {
        return offeredCredential.vct === credentialRequest.vct
      }

      return false
    })
  }

  private getSdJwtVcCredentialSigningCallback = (
    agentContext: AgentContext,
    options: OpenId4VciSignSdJwtCredential
  ): CredentialSignerCallback<DidDocument> => {
    return async () => {
      const sdJwtVcApi = agentContext.dependencyManager.resolve(SdJwtVcApi)

      const sdJwtVc = await sdJwtVcApi.sign(options)
      return getSphereonVerifiableCredential(sdJwtVc)
    }
  }

  private getW3cCredentialSigningCallback = (
    agentContext: AgentContext,
    options: OpenId4VciSignW3cCredential
  ): CredentialSignerCallback<DidDocument> => {
    return async (opts) => {
      const { jwtVerifyResult, format } = opts
      const { kid, didDocument: holderDidDocument } = jwtVerifyResult

      if (!kid) throw new CredoError('Missing Kid. Cannot create the holder binding')
      if (!holderDidDocument) throw new CredoError('Missing did document. Cannot create the holder binding.')
      if (!format) throw new CredoError('Missing format. Cannot issue credential.')

      const formatMap: Record<string, ClaimFormat.JwtVc | ClaimFormat.LdpVc> = {
        [OpenId4VciCredentialFormatProfile.JwtVcJson]: ClaimFormat.JwtVc,
        [OpenId4VciCredentialFormatProfile.JwtVcJsonLd]: ClaimFormat.JwtVc,
        [OpenId4VciCredentialFormatProfile.LdpVc]: ClaimFormat.LdpVc,
      }
      const w3cServiceFormat = formatMap[format]

      // Set the binding on the first credential subject if not set yet
      // on any subject
      if (!options.credential.credentialSubjectIds.includes(holderDidDocument.id)) {
        const credentialSubject = Array.isArray(options.credential.credentialSubject)
          ? options.credential.credentialSubject[0]
          : options.credential.credentialSubject
        credentialSubject.id = holderDidDocument.id
      }

      const didsApi = agentContext.dependencyManager.resolve(DidsApi)
      const issuerDidDocument = await didsApi.resolveDidDocument(options.verificationMethod)
      const verificationMethod = issuerDidDocument.dereferenceVerificationMethod(options.verificationMethod)

      if (w3cServiceFormat === ClaimFormat.JwtVc) {
        const key = getKeyFromVerificationMethod(verificationMethod)
        const alg = getJwkFromKey(key).supportedSignatureAlgorithms[0]

        if (!alg) {
          throw new CredoError(`No supported JWA signature algorithms for key type ${key.keyType}`)
        }

        const signed = await this.w3cCredentialService.signCredential(agentContext, {
          format: w3cServiceFormat,
          credential: options.credential,
          verificationMethod: options.verificationMethod,
          alg,
        })

        return getSphereonVerifiableCredential(signed)
      } else {
        const key = getKeyFromVerificationMethod(verificationMethod)
        const proofType = getProofTypeFromKey(agentContext, key)

        const signed = await this.w3cCredentialService.signCredential(agentContext, {
          format: w3cServiceFormat,
          credential: options.credential,
          verificationMethod: options.verificationMethod,
          proofType: proofType,
        })

        return getSphereonVerifiableCredential(signed)
      }
    }
  }

  private async getHolderBindingFromRequest(credentialRequest: OpenId4VciCredentialRequest) {
    if (!credentialRequest.proof?.jwt) throw new CredoError('Received a credential request without a proof')

    const jwt = Jwt.fromSerializedJwt(credentialRequest.proof.jwt)

    if (jwt.header.kid) {
      if (!jwt.header.kid.startsWith('did:')) {
        throw new CredoError("Only did is supported for 'kid' identifier")
      } else if (!jwt.header.kid.includes('#')) {
        throw new CredoError(
          `kid containing did MUST point to a specific key within the did document: ${jwt.header.kid}`
        )
      }

      return {
        method: 'did',
        didUrl: jwt.header.kid,
      } satisfies OpenId4VcCredentialHolderBinding
    } else if (jwt.header.jwk) {
      return {
        method: 'jwk',
        jwk: getJwkFromJson(jwt.header.jwk),
      } satisfies OpenId4VcCredentialHolderBinding
    } else {
      throw new CredoError('Either kid or jwk must be present in credential request proof header')
    }
  }

  private getCredentialDataSupplier = (
    agentContext: AgentContext,
    options: OpenId4VciCreateCredentialResponseOptions & {
      issuer: OpenId4VcIssuerRecord
      issuanceSession: OpenId4VcIssuanceSessionRecord
    }
  ): CredentialDataSupplier => {
    return async (args: CredentialDataSupplierArgs) => {
      const { issuanceSession, issuer } = options
      const { credentialRequest } = args

      const issuerMetadata = this.getIssuerMetadata(agentContext, issuer)

      const offeredCredentialsMatchingRequest = this.findOfferedCredentialsMatchingRequest(
        options.issuanceSession.credentialOfferPayload,
        credentialRequest as OpenId4VciCredentialRequest,
        issuerMetadata.credentialsSupported,
        issuanceSession
      )

      if (offeredCredentialsMatchingRequest.length === 0) {
        throw new CredoError('No offered credentials match the credential request.')
      }

      if (offeredCredentialsMatchingRequest.length > 1) {
        agentContext.config.logger.debug(
          'Multiple credentials from credentials supported matching request, picking first one.'
        )
      }

      const mapper =
        options.credentialRequestToCredentialMapper ??
        this.openId4VcIssuerConfig.credentialEndpoint.credentialRequestToCredentialMapper

      const holderBinding = await this.getHolderBindingFromRequest(credentialRequest as OpenId4VciCredentialRequest)
      const signOptions = await mapper({
        agentContext,
        issuanceSession,
        holderBinding,
        credentialOffer: { credential_offer: issuanceSession.credentialOfferPayload },
        credentialRequest: credentialRequest as OpenId4VciCredentialRequest,
        credentialsSupported: offeredCredentialsMatchingRequest,
      })

      const credentialHasAlreadyBeenIssued = issuanceSession.issuedCredentials.includes(
        signOptions.credentialSupportedId
      )
      if (credentialHasAlreadyBeenIssued) {
        throw new CredoError(
          `The requested credential with id '${signOptions.credentialSupportedId}' has already been issued.`
        )
      }

      const updatedIssuanceSession = await this.openId4VcIssuanceSessionRepository.getById(
        agentContext,
        issuanceSession.id
      )
      updatedIssuanceSession.issuedCredentials.push(signOptions.credentialSupportedId)
      await this.openId4VcIssuanceSessionRepository.update(agentContext, updatedIssuanceSession)

      if (signOptions.format === ClaimFormat.JwtVc || signOptions.format === ClaimFormat.LdpVc) {
        if (!w3cOpenId4VcFormats.includes(credentialRequest.format as OpenId4VciCredentialFormatProfile)) {
          throw new CredoError(
            `The credential to be issued does not match the request. Cannot issue a W3cCredential if the client expects a credential of format '${credentialRequest.format}'.`
          )
        }

        return {
          format: credentialRequest.format,
          credential: JsonTransformer.toJSON(signOptions.credential) as ICredential,
          signCallback: this.getW3cCredentialSigningCallback(agentContext, signOptions),
        }
      } else if (signOptions.format === ClaimFormat.SdJwtVc) {
        if (credentialRequest.format !== OpenId4VciCredentialFormatProfile.SdJwtVc) {
          throw new CredoError(
            `Invalid credential format. Expected '${OpenId4VciCredentialFormatProfile.SdJwtVc}', received '${credentialRequest.format}'.`
          )
        }
        if (credentialRequest.vct !== signOptions.payload.vct) {
          throw new CredoError(
            `The types of the offered credentials do not match the types of the requested credential. Offered '${signOptions.payload.vct}' Requested '${credentialRequest.vct}'.`
          )
        }

        return {
          format: credentialRequest.format,
          // NOTE: we don't use the credential value here as we pass the credential directly to the singer
          credential: { ...signOptions.payload } as unknown as CredentialIssuanceInput,
          signCallback: this.getSdJwtVcCredentialSigningCallback(agentContext, signOptions),
        }
      } else {
        throw new CredoError(`Unsupported credential format`)
      }
    }
  }
}
