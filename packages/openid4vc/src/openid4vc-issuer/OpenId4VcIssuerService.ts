import type {
  OpenId4VciCreateCredentialResponseOptions,
  OpenId4VciCreateCredentialOfferOptions,
  OpenId4VciCreateIssuerOptions,
  OpenId4VciPreAuthorizedCodeFlowConfig,
  OpenId4VciSignW3cCredentials,
  OpenId4VciAuthorizationCodeFlowConfig,
  OpenId4VciCredentialRequestAuthorization,
  OpenId4VciCreateStatelessCredentialOfferOptions,
  OpenId4VciCredentialRequestToCredentialMapperOptions,
} from './OpenId4VcIssuerServiceOptions'
import type {
  OpenId4VcCredentialHolderBindingWithKey,
  OpenId4VciCredentialConfigurationsSupportedWithFormats,
  OpenId4VciMetadata,
} from '../shared'
import type { AgentContext, Query, QueryOptions } from '@credo-ts/core'

import {
  AuthorizationServerMetadata,
  JwtSigner,
  Oauth2AuthorizationServer,
  Oauth2Client,
  Oauth2ErrorCodes,
  Oauth2ResourceServer,
  Oauth2ServerErrorResponseError,
  PkceCodeChallengeMethod,
  preAuthorizedCodeGrantIdentifier,
} from '@animo-id/oauth2'
import {
  CredentialIssuerMetadata,
  CredentialRequestFormatSpecific,
  extractScopesForCredentialConfigurationIds,
  getCredentialConfigurationsMatchingRequestFormat,
  Oid4vciDraftVersion,
  Oid4vciIssuer,
} from '@animo-id/oid4vci'
import {
  SdJwtVcApi,
  CredoError,
  ClaimFormat,
  getJwkFromJson,
  getJwkFromKey,
  injectable,
  joinUriParts,
  JwsService,
  KeyType,
  utils,
  W3cCredentialService,
  MdocApi,
  Key,
  JwtPayload,
  Jwt,
  EventEmitter,
  TypedArrayEncoder,
} from '@credo-ts/core'

import { OpenId4VcVerifierApi } from '../openid4vc-verifier'
import { OpenId4VciCredentialFormatProfile } from '../shared'
import { dynamicOid4vciClientAuthentication, getOid4vciCallbacks } from '../shared/callbacks'
import { getCredentialConfigurationsSupportedForScopes, getOfferedCredentials } from '../shared/issuerMetadataUtils'
import { storeActorIdForContextCorrelationId } from '../shared/router'
import { addSecondsToDate, dateToSeconds, getKeyFromDid, getProofTypeFromKey } from '../shared/utils'

import { OpenId4VcIssuanceSessionState } from './OpenId4VcIssuanceSessionState'
import { OpenId4VcIssuanceSessionStateChangedEvent, OpenId4VcIssuerEvents } from './OpenId4VcIssuerEvents'
import { OpenId4VcIssuerModuleConfig } from './OpenId4VcIssuerModuleConfig'
import {
  OpenId4VcIssuerRepository,
  OpenId4VcIssuerRecord,
  OpenId4VcIssuanceSessionRepository,
  OpenId4VcIssuanceSessionRecord,
} from './repository'
import { generateTxCode } from './util/txCode'

/**
 * @internal
 */
@injectable()
export class OpenId4VcIssuerService {
  private w3cCredentialService: W3cCredentialService
  private openId4VcIssuerConfig: OpenId4VcIssuerModuleConfig
  private openId4VcIssuerRepository: OpenId4VcIssuerRepository
  private openId4VcIssuanceSessionRepository: OpenId4VcIssuanceSessionRepository

  public constructor(
    w3cCredentialService: W3cCredentialService,
    openId4VcIssuerConfig: OpenId4VcIssuerModuleConfig,
    openId4VcIssuerRepository: OpenId4VcIssuerRepository,
    openId4VcIssuanceSessionRepository: OpenId4VcIssuanceSessionRepository
  ) {
    this.w3cCredentialService = w3cCredentialService
    this.openId4VcIssuerConfig = openId4VcIssuerConfig
    this.openId4VcIssuerRepository = openId4VcIssuerRepository
    this.openId4VcIssuanceSessionRepository = openId4VcIssuanceSessionRepository
  }

  public async createStatelessCredentialOffer(
    agentContext: AgentContext,
    options: OpenId4VciCreateStatelessCredentialOfferOptions & { issuer: OpenId4VcIssuerRecord }
  ) {
    const { authorizationCodeFlowConfig, issuer, offeredCredentials } = options
    const vcIssuer = this.getIssuer(agentContext)
    const issuerMetadata = await this.getIssuerMetadata(agentContext, issuer)

    const uniqueOfferedCredentials = Array.from(new Set(options.offeredCredentials))
    if (uniqueOfferedCredentials.length !== offeredCredentials.length) {
      throw new CredoError('All offered credentials must have unique ids.')
    }

    // Check if all the offered credential configuration ids have a scope value. If not, it won't be possible to actually request
    // issuance of the crednetial later on
    extractScopesForCredentialConfigurationIds({
      credentialConfigurationIds: options.offeredCredentials,
      issuerMetadata,
      throwOnConfigurationWithoutScope: true,
    })

    if (authorizationCodeFlowConfig.authorizationServerUrl === issuerMetadata.credentialIssuer.credential_issuer) {
      throw new CredoError(
        'Stateless offers can only be created for external authorization servers. Make sure to configure an external authorization server on the issuer record, and provide the authoriation server url.'
      )
    }

    const { credentialOffer, credentialOfferObject } = await vcIssuer.createCredentialOffer({
      credentialConfigurationIds: options.offeredCredentials,
      grants: {
        authorization_code: {
          authorization_server: authorizationCodeFlowConfig.authorizationServerUrl,
        },
      },
      credentialOfferScheme: options.baseUri,
      issuerMetadata,
    })

    return {
      credentialOffer,
      credentialOfferObject,
    }
  }

  public async createCredentialOffer(
    agentContext: AgentContext,
    options: OpenId4VciCreateCredentialOfferOptions & { issuer: OpenId4VcIssuerRecord }
  ) {
    const {
      preAuthorizedCodeFlowConfig,
      authorizationCodeFlowConfig,
      issuer,
      offeredCredentials,
      version = 'v1.draft11-13',
    } = options
    if (!preAuthorizedCodeFlowConfig && !authorizationCodeFlowConfig) {
      throw new CredoError('Authorization Config or Pre-Authorized Config must be provided.')
    }

    const vcIssuer = this.getIssuer(agentContext)
    const issuerMetadata = await this.getIssuerMetadata(agentContext, issuer)

    const uniqueOfferedCredentials = Array.from(new Set(options.offeredCredentials))
    if (uniqueOfferedCredentials.length !== offeredCredentials.length) {
      throw new CredoError('All offered credentials must have unique ids.')
    }

    if (uniqueOfferedCredentials.length === 0) {
      throw new CredoError('You need to offer at least one credential.')
    }

    // We always use shortened URIs currently
    const hostedCredentialOfferUri = joinUriParts(issuerMetadata.credentialIssuer.credential_issuer, [
      this.openId4VcIssuerConfig.credentialOfferEndpointPath,
      // It doesn't really matter what the url is, as long as it's unique
      utils.uuid(),
    ])

    // Check if all the offered credential configuration ids have a scope value. If not, it won't be possible to actually request
    // issuance of the crednetial later on. For pre-auth it's not needed to add a scope.
    if (options.authorizationCodeFlowConfig) {
      extractScopesForCredentialConfigurationIds({
        credentialConfigurationIds: options.offeredCredentials,
        issuerMetadata,
        throwOnConfigurationWithoutScope: true,
      })
    }

    const grants = await this.getGrantsFromConfig(agentContext, {
      issuerMetadata,
      preAuthorizedCodeFlowConfig,
      authorizationCodeFlowConfig,
    })

    const { credentialOffer, credentialOfferObject } = await vcIssuer.createCredentialOffer({
      credentialConfigurationIds: options.offeredCredentials,
      grants,
      credentialOfferUri: hostedCredentialOfferUri,
      credentialOfferScheme: options.baseUri,
      issuerMetadata: {
        originalDraftVersion: version === 'v1.draft11-13' ? Oid4vciDraftVersion.Draft11 : Oid4vciDraftVersion.Draft14,
        ...issuerMetadata,
      },
    })

    const issuanceSessionRepository = this.openId4VcIssuanceSessionRepository
    const issuanceSession = new OpenId4VcIssuanceSessionRecord({
      credentialOfferPayload: credentialOfferObject,
      credentialOfferUri: hostedCredentialOfferUri,
      issuerId: issuer.issuerId,
      state: OpenId4VcIssuanceSessionState.OfferCreated,
      authorization: credentialOfferObject.grants?.authorization_code?.issuer_state
        ? {
            issuerState: credentialOfferObject.grants?.authorization_code?.issuer_state,
          }
        : undefined,
      presentation: authorizationCodeFlowConfig?.requirePresentationDuringIssuance
        ? {
            required: true,
          }
        : undefined,
      // TODO: how to mix pre-auth and auth? Need to do state checks
      preAuthorizedCode: credentialOfferObject.grants?.[preAuthorizedCodeGrantIdentifier]?.['pre-authorized_code'],
      userPin: preAuthorizedCodeFlowConfig?.txCode
        ? generateTxCode(agentContext, preAuthorizedCodeFlowConfig.txCode)
        : undefined,
      issuanceMetadata: options.issuanceMetadata,
    })
    await issuanceSessionRepository.save(agentContext, issuanceSession)
    this.emitStateChangedEvent(agentContext, issuanceSession, null)

    return {
      issuanceSession,
      credentialOffer,
    }
  }

  public async createCredentialResponse(
    agentContext: AgentContext,
    options: OpenId4VciCreateCredentialResponseOptions & { issuanceSession: OpenId4VcIssuanceSessionRecord }
  ) {
    options.issuanceSession.assertState([
      // OfferUriRetrieved is valid when doing auth flow (we should add a check)
      OpenId4VcIssuanceSessionState.OfferUriRetrieved,
      OpenId4VcIssuanceSessionState.AccessTokenCreated,
      OpenId4VcIssuanceSessionState.CredentialRequestReceived,
      // It is possible to issue multiple credentials in one session
      OpenId4VcIssuanceSessionState.CredentialsPartiallyIssued,
    ])
    const { issuanceSession } = options
    const issuer = await this.getIssuerByIssuerId(agentContext, options.issuanceSession.issuerId)
    const vcIssuer = this.getIssuer(agentContext)
    const issuerMetadata = await this.getIssuerMetadata(agentContext, issuer)

    const parsedCredentialRequest = vcIssuer.parseCredentialRequest({
      credentialRequest: options.credentialRequest,
    })
    const { credentialRequest, credentialIdentifier, format, proofs } = parsedCredentialRequest
    if (credentialIdentifier) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidCredentialRequest,
        error_description: `Using unsupported 'credential_identifier'`,
      })
    }

    if (!format) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.UnsupportedCredentialFormat,
        error_description: `Unsupported credential format '${credentialRequest.format}'`,
      })
    }

    if (!proofs?.jwt || proofs.jwt.length === 0) {
      const { cNonce, cNonceExpiresInSeconds } = await this.createNonce(agentContext, issuer)
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidProof,
        error_description: 'Missing required proof(s) in credential request',
        c_nonce: cNonce,
        c_nonce_expires_in: cNonceExpiresInSeconds,
      })
    }
    await this.updateState(agentContext, issuanceSession, OpenId4VcIssuanceSessionState.CredentialRequestReceived)

    let previousNonce: string | undefined = undefined
    const proofSigners: JwtSigner[] = []
    for (const jwt of proofs.jwt) {
      const { signer, payload } = await vcIssuer.verifyCredentialRequestJwtProof({
        issuerMetadata,
        jwt,
        clientId: options.issuanceSession.clientId,
      })

      if (!payload.nonce) {
        const { cNonce, cNonceExpiresInSeconds } = await this.createNonce(agentContext, issuer)
        throw new Oauth2ServerErrorResponseError({
          error: Oauth2ErrorCodes.InvalidProof,
          error_description: 'Missing nonce in proof(s) in credential request',
          c_nonce: cNonce,
          c_nonce_expires_in: cNonceExpiresInSeconds,
        })
      }

      // Set previous nonce if not yet set (first iteration)
      if (!previousNonce) previousNonce = payload.nonce
      if (previousNonce !== payload.nonce) {
        const { cNonce, cNonceExpiresInSeconds } = await this.createNonce(agentContext, issuer)
        throw new Oauth2ServerErrorResponseError({
          error: Oauth2ErrorCodes.InvalidProof,
          error_description: 'Not all nonce values in proofs are equal',
          c_nonce: cNonce,
          c_nonce_expires_in: cNonceExpiresInSeconds,
        })
      }

      // Verify the nonce
      await this.verifyNonce(agentContext, issuer, payload.nonce).catch(async (error) => {
        const { cNonce, cNonceExpiresInSeconds } = await this.createNonce(agentContext, issuer)
        throw new Oauth2ServerErrorResponseError(
          {
            error: Oauth2ErrorCodes.InvalidNonce,
            error_description: 'Invalid nonce in credential request',
            c_nonce: cNonce,
            c_nonce_expires_in: cNonceExpiresInSeconds,
          },
          {
            cause: error,
          }
        )
      })

      proofSigners.push(signer)
    }

    const signedCredentials = await this.getSignedCredentials(agentContext, {
      credentialRequest,
      issuanceSession,
      issuer,
      requestFormat: format,
      authorization: options.authorization,
      credentialRequestToCredentialMapper: options.credentialRequestToCredentialMapper,
      proofSigners,
    })

    // NOTE: nonce in credential response is deprecated in newer drafts, but for now we keep it in
    const { cNonce, cNonceExpiresInSeconds } = await this.createNonce(agentContext, issuer)
    const credentialResponse = vcIssuer.createCredentialResponse({
      credential: credentialRequest.proof ? signedCredentials.credentials[0] : undefined,
      credentials: credentialRequest.proofs ? signedCredentials.credentials : undefined,
      cNonce,
      cNonceExpiresInSeconds,
      credentialRequest: parsedCredentialRequest,
    })

    issuanceSession.issuedCredentials.push(signedCredentials.credentialConfigurationId)
    const newState =
      issuanceSession.issuedCredentials.length >=
      issuanceSession.credentialOfferPayload.credential_configuration_ids.length
        ? OpenId4VcIssuanceSessionState.Completed
        : OpenId4VcIssuanceSessionState.CredentialsPartiallyIssued
    await this.updateState(agentContext, issuanceSession, newState)

    return {
      credentialResponse,
      issuanceSession,
    }
  }

  public async findIssuanceSessionsByQuery(
    agentContext: AgentContext,
    query: Query<OpenId4VcIssuanceSessionRecord>,
    queryOptions?: QueryOptions
  ) {
    return this.openId4VcIssuanceSessionRepository.findByQuery(agentContext, query, queryOptions)
  }

  public async findSingleIssuancSessionByQuery(
    agentContext: AgentContext,
    query: Query<OpenId4VcIssuanceSessionRecord>
  ) {
    return this.openId4VcIssuanceSessionRepository.findSingleByQuery(agentContext, query)
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
      keyType: options.accessTokenSignerKeyType ?? KeyType.Ed25519,
    })

    const openId4VcIssuer = new OpenId4VcIssuerRecord({
      issuerId: options.issuerId ?? utils.uuid(),
      display: options.display,
      dpopSigningAlgValuesSupported: options.dpopSigningAlgValuesSupported,
      accessTokenPublicKeyFingerprint: accessTokenSignerKey.fingerprint,
      authorizationServerConfigs: options.authorizationServerConfigs,
      credentialConfigurationsSupported: options.credentialConfigurationsSupported,
      batchCredentialIssuance: options.batchCredentialIssuance,
    })

    await this.openId4VcIssuerRepository.save(agentContext, openId4VcIssuer)
    await storeActorIdForContextCorrelationId(agentContext, openId4VcIssuer.issuerId)
    return openId4VcIssuer
  }

  public async rotateAccessTokenSigningKey(
    agentContext: AgentContext,
    issuer: OpenId4VcIssuerRecord,
    options?: Pick<OpenId4VciCreateIssuerOptions, 'accessTokenSignerKeyType'>
  ) {
    const accessTokenSignerKey = await agentContext.wallet.createKey({
      keyType: options?.accessTokenSignerKeyType ?? KeyType.Ed25519,
    })

    // TODO: ideally we can remove the previous key
    issuer.accessTokenPublicKeyFingerprint = accessTokenSignerKey.fingerprint
    await this.openId4VcIssuerRepository.update(agentContext, issuer)
  }

  /**
   * @param fetchExternalAuthorizationServerMetadata defaults to false
   */
  public async getIssuerMetadata(
    agentContext: AgentContext,
    issuerRecord: OpenId4VcIssuerRecord,
    fetchExternalAuthorizationServerMetadata = false
  ): Promise<OpenId4VciMetadata> {
    const config = agentContext.dependencyManager.resolve(OpenId4VcIssuerModuleConfig)
    const issuerUrl = joinUriParts(config.baseUrl, [issuerRecord.issuerId])
    const oauth2Client = this.getOauth2Client(agentContext)

    const extraAuthorizationServers: AuthorizationServerMetadata[] =
      fetchExternalAuthorizationServerMetadata && issuerRecord.authorizationServerConfigs
        ? await Promise.all(
            issuerRecord.authorizationServerConfigs.map(async (server) => {
              const metadata = await oauth2Client.fetchAuthorizationServerMetadata(server.issuer)
              if (!metadata)
                throw new CredoError(`Authorization server metadata not found for issuer '${server.issuer}'`)
              return metadata
            })
          )
        : []

    const authorizationServers =
      issuerRecord.authorizationServerConfigs && issuerRecord.authorizationServerConfigs.length > 0
        ? [
            ...issuerRecord.authorizationServerConfigs.map((authorizationServer) => authorizationServer.issuer),
            // Our issuer is also a valid authorization server (only for pre-auth)
            issuerUrl,
          ]
        : undefined

    const credentialIssuerMetadata = {
      credential_issuer: issuerUrl,
      credential_endpoint: joinUriParts(issuerUrl, [config.credentialEndpointPath]),
      credential_configurations_supported: issuerRecord.credentialConfigurationsSupported ?? {},
      authorization_servers: authorizationServers,
      display: issuerRecord.display,
      nonce_endpoint: joinUriParts(issuerUrl, [config.nonceEndpointPath]),
      batch_credential_issuance: issuerRecord.batchCredentialIssuance
        ? {
            batch_size: issuerRecord.batchCredentialIssuance.batchSize,
          }
        : undefined,
    } satisfies CredentialIssuerMetadata

    const issuerAuthorizationServer = {
      issuer: issuerUrl,
      token_endpoint: joinUriParts(issuerUrl, [config.accessTokenEndpointPath]),
      'pre-authorized_grant_anonymous_access_supported': true,

      jwks_uri: joinUriParts(issuerUrl, [config.jwksEndpointPath]),
      authorization_challenge_endpoint: joinUriParts(issuerUrl, [config.authorizationChallengeEndpointPath]),

      // TODO: PAR (maybe not needed as we only use this auth server for presentation during issuance)
      // pushed_authorization_request_endpoint: '',
      // require_pushed_authorization_requests: true

      code_challenge_methods_supported: [PkceCodeChallengeMethod.S256],
      dpop_signing_alg_values_supported: issuerRecord.dpopSigningAlgValuesSupported,
    } satisfies AuthorizationServerMetadata

    return {
      credentialIssuer: credentialIssuerMetadata,
      authorizationServers: [issuerAuthorizationServer, ...extraAuthorizationServers],
    }
  }

  public async createNonce(agentContext: AgentContext, issuer: OpenId4VcIssuerRecord) {
    const issuerMetadata = await this.getIssuerMetadata(agentContext, issuer)
    const jwsService = agentContext.dependencyManager.resolve(JwsService)

    const cNonceExpiresInSeconds = this.openId4VcIssuerConfig.cNonceExpiresInSeconds
    const cNonceExpiresAt = addSecondsToDate(new Date(), cNonceExpiresInSeconds)

    const key = Key.fromFingerprint(issuer.accessTokenPublicKeyFingerprint)
    const jwk = getJwkFromKey(key)

    const cNonce = await jwsService.createJwsCompact(agentContext, {
      key,
      payload: JwtPayload.fromJson({
        iss: issuerMetadata.credentialIssuer.credential_issuer,
        exp: dateToSeconds(cNonceExpiresAt),
      }),
      protectedHeaderOptions: {
        typ: 'credo+cnonce',
        kid: issuer.accessTokenPublicKeyFingerprint,
        alg: jwk.supportedSignatureAlgorithms[0],
      },
    })

    return {
      cNonce,
      cNonceExpiresAt,
      cNonceExpiresInSeconds,
    }
  }

  /**
   * @todo nonces are very short lived (1 min), but it might be nice to also cache the nonces
   * in the cache if we have 'seen' them. They will only be in the cache for a short time
   * and it will prevent replay
   */
  private async verifyNonce(agentContext: AgentContext, issuer: OpenId4VcIssuerRecord, cNonce: string) {
    const issuerMetadata = await this.getIssuerMetadata(agentContext, issuer)
    const jwsService = agentContext.dependencyManager.resolve(JwsService)

    const key = Key.fromFingerprint(issuer.accessTokenPublicKeyFingerprint)
    const jwk = getJwkFromKey(key)

    const jwt = Jwt.fromSerializedJwt(cNonce)
    jwt.payload.validate()

    if (jwt.payload.iss !== issuerMetadata.credentialIssuer.credential_issuer) {
      throw new CredoError(`Invalid 'iss' claim in cNonce jwt`)
    }
    if (jwt.header.typ !== 'credo+cnonce') {
      throw new CredoError(`Invalid 'typ' claim in cNonce jwt header`)
    }

    const verification = await jwsService.verifyJws(agentContext, {
      jws: cNonce,
      jwkResolver: () => jwk,
    })

    if (
      !verification.signerKeys
        .map((singerKey) => singerKey.fingerprint)
        .includes(issuer.accessTokenPublicKeyFingerprint)
    ) {
      throw new CredoError('Invalid nonce')
    }
  }

  public getIssuer(agentContext: AgentContext) {
    return new Oid4vciIssuer({
      callbacks: getOid4vciCallbacks(agentContext),
    })
  }

  public getOauth2Client(agentContext: AgentContext) {
    return new Oauth2Client({
      callbacks: getOid4vciCallbacks(agentContext),
    })
  }

  public getOauth2AuthorizationServer(agentContext: AgentContext) {
    return new Oauth2AuthorizationServer({
      callbacks: getOid4vciCallbacks(agentContext),
    })
  }

  public getResourceServer(agentContext: AgentContext, issuerRecord: OpenId4VcIssuerRecord) {
    return new Oauth2ResourceServer({
      callbacks: {
        ...getOid4vciCallbacks(agentContext),
        clientAuthentication: dynamicOid4vciClientAuthentication(agentContext, issuerRecord),
      },
    })
  }

  /**
   * Update the record to a new state and emit an state changed event. Also updates the record
   * in storage.
   */
  public async updateState(
    agentContext: AgentContext,
    issuanceSession: OpenId4VcIssuanceSessionRecord,
    newState: OpenId4VcIssuanceSessionState
  ) {
    agentContext.config.logger.debug(
      `Updating openid4vc issuance session record ${issuanceSession.id} to state ${newState} (previous=${issuanceSession.state})`
    )

    const previousState = issuanceSession.state
    issuanceSession.state = newState
    await this.openId4VcIssuanceSessionRepository.update(agentContext, issuanceSession)

    this.emitStateChangedEvent(agentContext, issuanceSession, previousState)
  }

  public emitStateChangedEvent(
    agentContext: AgentContext,
    issuanceSession: OpenId4VcIssuanceSessionRecord,
    previousState: OpenId4VcIssuanceSessionState | null
  ) {
    const eventEmitter = agentContext.dependencyManager.resolve(EventEmitter)

    eventEmitter.emit<OpenId4VcIssuanceSessionStateChangedEvent>(agentContext, {
      type: OpenId4VcIssuerEvents.IssuanceSessionStateChanged,
      payload: {
        issuanceSession: issuanceSession.clone(),
        previousState: previousState,
      },
    })
  }

  private async getGrantsFromConfig(
    agentContext: AgentContext,
    config: {
      issuerMetadata: OpenId4VciMetadata
      preAuthorizedCodeFlowConfig?: OpenId4VciPreAuthorizedCodeFlowConfig
      authorizationCodeFlowConfig?: OpenId4VciAuthorizationCodeFlowConfig
    }
  ) {
    const { preAuthorizedCodeFlowConfig, authorizationCodeFlowConfig, issuerMetadata } = config

    // TOOD: export type
    const grants: Parameters<Oid4vciIssuer['createCredentialOffer']>[0]['grants'] = {}

    // Pre auth
    if (preAuthorizedCodeFlowConfig) {
      const { txCode, authorizationServerUrl, preAuthorizedCode } = preAuthorizedCodeFlowConfig

      grants[preAuthorizedCodeGrantIdentifier] = {
        'pre-authorized_code': preAuthorizedCode ?? (await agentContext.wallet.generateNonce()),
        tx_code: txCode,
        authorization_server: config.issuerMetadata.credentialIssuer.authorization_servers
          ? authorizationServerUrl
          : undefined,
      }
    }

    // Auth
    if (authorizationCodeFlowConfig) {
      const { requirePresentationDuringIssuance } = authorizationCodeFlowConfig
      let authorizationServerUrl = authorizationCodeFlowConfig.authorizationServerUrl

      if (requirePresentationDuringIssuance) {
        if (authorizationServerUrl && authorizationServerUrl !== issuerMetadata.credentialIssuer.credential_issuer) {
          throw new CredoError(
            `When 'requirePresentationDuringIssuance' is set, 'authorizationServerUrl' must be undefined or match the credential issuer identifier`
          )
        }

        authorizationServerUrl = issuerMetadata.credentialIssuer.credential_issuer
      }

      grants.authorization_code = {
        issuer_state:
          // TODO: the issuer_state should not be guessable, so it's best if we generate it and now allow the user to provide it?
          // but same is true for the pre-auth code and users of credo can also provide that value. We can't easily do unique constraint with askat
          authorizationCodeFlowConfig.issuerState ??
          TypedArrayEncoder.toBase64URL(agentContext.wallet.getRandomValues(32)),
        authorization_server: config.issuerMetadata.credentialIssuer.authorization_servers
          ? authorizationServerUrl
          : undefined,
      }
    }

    return grants
  }

  private async getHolderBindingFromRequestProofs(agentContext: AgentContext, proofSigners: JwtSigner[]) {
    const credentialHolderBindings: OpenId4VcCredentialHolderBindingWithKey[] = []
    for (const signer of proofSigners) {
      if (signer.method === 'custom' || signer.method === 'x5c') {
        throw new CredoError(`Only 'jwk' and 'did' based holder binding is supported`)
      }

      if (signer.method === 'jwk') {
        const jwk = getJwkFromJson(signer.publicJwk)
        credentialHolderBindings.push({
          method: 'jwk',
          jwk,
          key: jwk.key,
        })
      }

      if (signer.method === 'did') {
        const key = await getKeyFromDid(agentContext, signer.didUrl)
        credentialHolderBindings.push({
          method: 'did',
          didUrl: signer.didUrl,
          key,
        })
      }
    }

    return credentialHolderBindings
  }

  private getCredentialConfigurationsForRequest(options: {
    requestFormat: CredentialRequestFormatSpecific
    issuerMetadata: OpenId4VciMetadata
    issuanceSession: OpenId4VcIssuanceSessionRecord
    authorization: OpenId4VciCredentialRequestAuthorization
  }) {
    const { requestFormat, issuanceSession, issuerMetadata, authorization } = options

    // Check against all credential configurations
    const configurationsMatchingRequest = getCredentialConfigurationsMatchingRequestFormat({
      requestFormat,
      credentialConfigurations: issuerMetadata.credentialIssuer.credential_configurations_supported,
    })
    if (Object.keys(configurationsMatchingRequest).length === 0) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidCredentialRequest,
        error_description: 'Credential request does not match any credential configuration',
      })
    }

    // Limit to offered configurations
    const configurationsMatchingRequestAndOffer = getOfferedCredentials(
      issuanceSession.credentialOfferPayload.credential_configuration_ids,
      configurationsMatchingRequest,
      { ignoreNotFoundIds: true }
    )
    if (Object.keys(configurationsMatchingRequestAndOffer).length === 0) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidCredentialRequest,
        error_description: 'Credential request does not match any credential configurations from credential offer',
      })
    }

    // Limit to not-issued configurations
    const configurationsMatchingRequestAndOfferNotIssued = getOfferedCredentials(
      issuanceSession.credentialOfferPayload.credential_configuration_ids.filter(
        (id) => !issuanceSession.issuedCredentials.includes(id)
      ),
      configurationsMatchingRequestAndOffer,
      { ignoreNotFoundIds: true }
    )
    if (Object.keys(configurationsMatchingRequestAndOfferNotIssued).length === 0) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidCredentialRequest,
        error_description:
          'Credential request does not match any credential configurations from credential offer that have not been issued yet',
      })
    }

    // For pre-auth we allow all ids from the offer
    if (authorization.accessToken.payload['pre-authorized_code']) {
      return {
        credentialConfigurations:
          configurationsMatchingRequestAndOfferNotIssued as OpenId4VciCredentialConfigurationsSupportedWithFormats,
        credentialConfigurationIds: Object.keys(configurationsMatchingRequestAndOfferNotIssued) as [
          string,
          ...string[]
        ],
      }
    }

    // Limit to scopes from the token
    // We only do this for auth flow, so it's not required to add a scope for every configuration.
    const configurationsMatchingRequestOfferScope = getCredentialConfigurationsSupportedForScopes(
      configurationsMatchingRequestAndOfferNotIssued,
      authorization.accessToken.payload.scope?.split(' ') ?? []
    )
    if (Object.keys(configurationsMatchingRequestOfferScope).length === 0) {
      throw new Oauth2ServerErrorResponseError(
        {
          error: Oauth2ErrorCodes.InsufficientScope,
          error_description:
            'Scope does not grant issuance for any requested credential configurations from credential offer',
        },
        {
          status: 403,
        }
      )
    }

    return {
      credentialConfigurations:
        configurationsMatchingRequestOfferScope as OpenId4VciCredentialConfigurationsSupportedWithFormats,
      credentialConfigurationIds: Object.keys(configurationsMatchingRequestOfferScope) as [string, ...string[]],
    }
  }

  private async getSignedCredentials(
    agentContext: AgentContext,
    options: OpenId4VciCreateCredentialResponseOptions & {
      issuer: OpenId4VcIssuerRecord
      issuanceSession: OpenId4VcIssuanceSessionRecord
      requestFormat: CredentialRequestFormatSpecific
      proofSigners: JwtSigner[]
    }
  ): Promise<{
    credentials: string[] | Record<string, unknown>[]
    format: `${OpenId4VciCredentialFormatProfile}`
    credentialConfigurationId: string
  }> {
    const { issuanceSession, issuer, requestFormat, authorization } = options
    const issuerMetadata = await this.getIssuerMetadata(agentContext, issuer)

    const { credentialConfigurations, credentialConfigurationIds } = this.getCredentialConfigurationsForRequest({
      issuanceSession,
      issuerMetadata,
      requestFormat,
      authorization,
    })

    const mapper =
      options.credentialRequestToCredentialMapper ?? this.openId4VcIssuerConfig.credentialRequestToCredentialMapper

    let verification: OpenId4VciCredentialRequestToCredentialMapperOptions['verification'] = undefined

    // NOTE: this will throw an error if the verifier module is not registered and there is a
    // verification session. But you can't get here without the verifier module anyway
    if (issuanceSession.presentation?.openId4VcVerificationSessionId) {
      const verifierApi = agentContext.dependencyManager.resolve(OpenId4VcVerifierApi)
      const session = await verifierApi.getVerificationSessionById(
        issuanceSession.presentation.openId4VcVerificationSessionId
      )

      const response = await verifierApi.getVerifiedAuthorizationResponse(
        issuanceSession.presentation.openId4VcVerificationSessionId
      )

      if (response.presentationExchange) {
        verification = {
          session,
          presentationExchange: response.presentationExchange,
        }
      } else if (response.dcql) {
        verification = {
          session,
          dcql: response.dcql,
        }
      } else {
        throw new CredoError(
          `Verified authorization response for verification session with id '${session.id}' does not have presenationExchange or dcql defined.`
        )
      }
    }

    const holderBindings = await this.getHolderBindingFromRequestProofs(agentContext, options.proofSigners)
    const signOptions = await mapper({
      agentContext,
      issuanceSession,
      holderBindings,
      credentialOffer: issuanceSession.credentialOfferPayload,

      verification,

      credentialRequest: options.credentialRequest,
      credentialRequestFormat: options.requestFormat,

      // Macthing credential configuration ids
      credentialConfigurationsSupported: credentialConfigurations,
      credentialConfigurationIds,

      // Authorization
      authorization: options.authorization,
    })

    if (!credentialConfigurationIds.includes(signOptions.credentialConfigurationId)) {
      throw new CredoError(
        `Credential request to credential mapper returned credential configuration id '${
          signOptions.credentialConfigurationId
        }' but is not part of provided input credential configuration ids. Allowed values are '${credentialConfigurationIds.join(
          ', '
        )}'.`
      )
    }

    // NOTE: we may want to allow a mismatch between this (as with new attestations not every key
    // needs a separate proof), but for now it needs to match
    if (signOptions.credentials.length !== holderBindings.length) {
      throw new CredoError(
        `Credential request to credential mapper returned '${signOptions.credentials.length}' to be signed, while only '${holderBindings.length}' holder binding entries were provided. Make sure to return one credential for each holder binding entry`
      )
    }

    if (signOptions.format === ClaimFormat.JwtVc || signOptions.format === ClaimFormat.LdpVc) {
      const oid4vciFormatMap: Record<string, ClaimFormat.JwtVc | ClaimFormat.LdpVc> = {
        [OpenId4VciCredentialFormatProfile.JwtVcJson]: ClaimFormat.JwtVc,
        [OpenId4VciCredentialFormatProfile.JwtVcJsonLd]: ClaimFormat.JwtVc,
        [OpenId4VciCredentialFormatProfile.LdpVc]: ClaimFormat.LdpVc,
      }

      const expectedClaimFormat = oid4vciFormatMap[options.requestFormat.format]
      if (signOptions.format !== expectedClaimFormat) {
        throw new CredoError(
          `Invalid credential format returned by sign options. Expected '${expectedClaimFormat}', received '${signOptions.format}'.`
        )
      }

      return {
        credentialConfigurationId: signOptions.credentialConfigurationId,
        format: requestFormat.format,
        credentials: (await Promise.all(
          signOptions.credentials.map((credential) =>
            this.signW3cCredential(agentContext, signOptions.format, credential).then((signed) => signed.encoded)
          )
        )) as string[] | Record<string, unknown>[],
      }
    } else if (signOptions.format === ClaimFormat.SdJwtVc) {
      if (signOptions.format !== requestFormat.format) {
        throw new CredoError(
          `Invalid credential format returned by sign options. Expected '${requestFormat.format}', received '${signOptions.format}'.`
        )
      }

      if (!signOptions.credentials.every((c) => c.payload.vct === requestFormat.vct)) {
        throw new CredoError(
          `One or more vct values of the offered credential(s) do not match the vct of the requested credential. Offered ${Array.from(
            new Set(signOptions.credentials.map((c) => `'${c.payload.vct}'`))
          ).join(', ')} Requested '${requestFormat.vct}'.`
        )
      }

      const sdJwtVcApi = agentContext.dependencyManager.resolve(SdJwtVcApi)
      return {
        credentialConfigurationId: signOptions.credentialConfigurationId,
        format: OpenId4VciCredentialFormatProfile.SdJwtVc,
        credentials: await Promise.all(
          signOptions.credentials.map((credential) => sdJwtVcApi.sign(credential).then((signed) => signed.compact))
        ),
      }
    } else if (signOptions.format === ClaimFormat.MsoMdoc) {
      if (signOptions.format !== requestFormat.format) {
        throw new CredoError(
          `Invalid credential format returned by sign options. Expected '${requestFormat.format}', received '${signOptions.format}'.`
        )
      }
      if (!signOptions.credentials.every((c) => c.docType === requestFormat.doctype)) {
        throw new CredoError(
          `One or more doctype values of the offered credential(s) do not match the doctype of the requested credential. Offered ${Array.from(
            new Set(signOptions.credentials.map((c) => `'${c.docType}'`))
          ).join(', ')} Requested '${requestFormat.doctype}'.`
        )
      }

      const mdocApi = agentContext.dependencyManager.resolve(MdocApi)
      return {
        credentialConfigurationId: signOptions.credentialConfigurationId,
        format: OpenId4VciCredentialFormatProfile.MsoMdoc,
        credentials: await Promise.all(
          signOptions.credentials.map((credential) => mdocApi.sign(credential).then((signed) => signed.base64Url))
        ),
      }
    } else {
      throw new CredoError(`Unsupported credential format ${signOptions.format}`)
    }
  }

  private async signW3cCredential(
    agentContext: AgentContext,
    format: `${ClaimFormat.JwtVc}` | `${ClaimFormat.LdpVc}`,
    options: OpenId4VciSignW3cCredentials['credentials'][number]
  ) {
    const key = await getKeyFromDid(agentContext, options.verificationMethod)
    if (format === ClaimFormat.JwtVc) {
      const supportedSignatureAlgorithms = getJwkFromKey(key).supportedSignatureAlgorithms
      if (supportedSignatureAlgorithms.length === 0) {
        throw new CredoError(`No supported JWA signature algorithms found for key with keyType ${key.keyType}`)
      }

      const alg = supportedSignatureAlgorithms[0]
      if (!alg) {
        throw new CredoError(`No supported JWA signature algorithms for key type ${key.keyType}`)
      }

      return await this.w3cCredentialService.signCredential(agentContext, {
        format: ClaimFormat.JwtVc,
        credential: options.credential,
        verificationMethod: options.verificationMethod,
        alg,
      })
    } else {
      const proofType = getProofTypeFromKey(agentContext, key)

      return await this.w3cCredentialService.signCredential(agentContext, {
        format: ClaimFormat.LdpVc,
        credential: options.credential,
        verificationMethod: options.verificationMethod,
        proofType: proofType,
      })
    }
  }
}
