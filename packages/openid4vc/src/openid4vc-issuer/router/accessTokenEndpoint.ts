import type { OpenId4VcIssuanceRequest } from './requestContext'
import type { AgentContext } from '@credo-ts/core'
import type { AccessTokenRequest, JWTSignerCallback } from '@sphereon/oid4vci-common'
import type { NextFunction, Response, Router } from 'express'

import { getJwkFromKey, CredoError, JwsService, JwtPayload, getJwkClassFromKeyType, Key } from '@credo-ts/core'
import {
  GrantTypes,
  IssueStatus,
  PRE_AUTHORIZED_CODE_REQUIRED_ERROR,
  PRE_AUTH_CODE_LITERAL,
  TokenError,
  TokenErrorResponse,
} from '@sphereon/oid4vci-common'
import { assertValidAccessTokenRequest, createAccessTokenResponse } from '@sphereon/oid4vci-issuer'

import { getRequestContext, sendErrorResponse } from '../../shared/router'
import { OpenId4VcIssuerService } from '../OpenId4VcIssuerService'
import { OpenId4VcCNonceStateManager } from '../repository/OpenId4VcCNonceStateManager'
import { OpenId4VcCredentialOfferSessionStateManager } from '../repository/OpenId4VcCredentialOfferSessionStateManager'

export interface OpenId4VciAccessTokenEndpointConfig {
  /**
   * The path at which the token endpoint should be made available. Note that it will be
   * hosted at a subpath to take into account multiple tenants and issuers.
   *
   * @default /token
   */
  endpointPath: string

  /**
   * The maximum amount of time in seconds that the pre-authorized code is valid.
   * @default 360 (5 minutes)
   */
  preAuthorizedCodeExpirationInSeconds: number

  /**
   * The time after which the cNonce from the access token response will
   * expire.
   *
   * @default 360 (5 minutes)
   */
  cNonceExpiresInSeconds: number

  /**
   * The time after which the token will expire.
   *
   * @default 360 (5 minutes)
   */
  tokenExpiresInSeconds: number
}

export function configureAccessTokenEndpoint(router: Router, config: OpenId4VciAccessTokenEndpointConfig) {
  router.post(
    config.endpointPath,
    verifyTokenRequest({ preAuthorizedCodeExpirationInSeconds: config.preAuthorizedCodeExpirationInSeconds }),
    handleTokenRequest(config)
  )
}

function getJwtSignerCallback(
  agentContext: AgentContext,
  signerPublicKey: Key,
  config: OpenId4VciAccessTokenEndpointConfig
): JWTSignerCallback {
  return async (jwt, _kid) => {
    if (_kid) {
      throw new CredoError('Kid should not be supplied externally.')
    }
    if (jwt.header.kid || jwt.header.jwk) {
      throw new CredoError('kid or jwk should not be present in access token header before signing')
    }

    const jwsService = agentContext.dependencyManager.resolve(JwsService)

    const alg = getJwkClassFromKeyType(signerPublicKey.keyType)?.supportedSignatureAlgorithms[0]
    if (!alg) {
      throw new CredoError(`No supported signature algorithms for key type: ${signerPublicKey.keyType}`)
    }

    // FIXME: the iat and exp implementation in OID4VCI is incorrect so we override the values here
    // https://github.com/Sphereon-Opensource/OID4VCI/pull/99
    // https://github.com/Sphereon-Opensource/OID4VCI/pull/101
    const iat = Math.floor(new Date().getTime() / 1000)
    jwt.payload.iat = iat
    jwt.payload.exp = iat + config.tokenExpiresInSeconds

    const jwk = getJwkFromKey(signerPublicKey)
    const signedJwt = await jwsService.createJwsCompact(agentContext, {
      protectedHeaderOptions: { ...jwt.header, jwk, alg },
      payload: JwtPayload.fromJson(jwt.payload),
      key: signerPublicKey,
    })

    return signedJwt
  }
}

export function handleTokenRequest(config: OpenId4VciAccessTokenEndpointConfig) {
  const { tokenExpiresInSeconds, cNonceExpiresInSeconds } = config

  return async (request: OpenId4VcIssuanceRequest, response: Response, next: NextFunction) => {
    response.set({ 'Cache-Control': 'no-store', Pragma: 'no-cache' })

    const requestContext = getRequestContext(request)
    const { agentContext, issuer } = requestContext

    const body = request.body as AccessTokenRequest
    if (body.grant_type !== GrantTypes.PRE_AUTHORIZED_CODE) {
      return sendErrorResponse(
        response,
        agentContext.config.logger,
        400,
        TokenErrorResponse.invalid_request,
        PRE_AUTHORIZED_CODE_REQUIRED_ERROR
      )
    }

    const openId4VcIssuerService = agentContext.dependencyManager.resolve(OpenId4VcIssuerService)
    const issuerMetadata = openId4VcIssuerService.getIssuerMetadata(agentContext, issuer)
    const accessTokenSigningKey = Key.fromFingerprint(issuer.accessTokenPublicKeyFingerprint)

    try {
      const accessTokenResponse = await createAccessTokenResponse(request.body, {
        credentialOfferSessions: new OpenId4VcCredentialOfferSessionStateManager(agentContext, issuer.issuerId),
        tokenExpiresIn: tokenExpiresInSeconds,
        accessTokenIssuer: issuerMetadata.issuerUrl,
        cNonce: await agentContext.wallet.generateNonce(),
        cNonceExpiresIn: cNonceExpiresInSeconds,
        cNonces: new OpenId4VcCNonceStateManager(agentContext, issuer.issuerId),
        accessTokenSignerCallback: getJwtSignerCallback(agentContext, accessTokenSigningKey, config),
      })
      response.status(200).json(accessTokenResponse)
    } catch (error) {
      sendErrorResponse(response, agentContext.config.logger, 400, TokenErrorResponse.invalid_request, error)
    }

    // NOTE: if we don't call next, the agentContext session handler will NOT be called
    next()
  }
}

export function verifyTokenRequest(options: { preAuthorizedCodeExpirationInSeconds: number }) {
  return async (request: OpenId4VcIssuanceRequest, response: Response, next: NextFunction) => {
    const { agentContext, issuer } = getRequestContext(request)

    try {
      const credentialOfferSessions = new OpenId4VcCredentialOfferSessionStateManager(agentContext, issuer.issuerId)
      const credentialOfferSession = await credentialOfferSessions.getAsserted(request.body[PRE_AUTH_CODE_LITERAL])
      if (![IssueStatus.OFFER_CREATED, IssueStatus.OFFER_URI_RETRIEVED].includes(credentialOfferSession.status)) {
        throw new TokenError(400, TokenErrorResponse.invalid_request, 'Access token has already been retrieved')
      }
      const { preAuthSession } = await assertValidAccessTokenRequest(request.body, {
        // It should actually be in seconds. but the oid4vci library has some bugs related
        // to seconds vs milliseconds. We pass it as ms for now, but once the fix is released
        // we should pass it as seconds. We have an extra check below, so that we won't have
        // an security issue once the fix is released.
        // FIXME: https://github.com/Sphereon-Opensource/OID4VCI/pull/104
        expirationDuration: options.preAuthorizedCodeExpirationInSeconds * 1000,
        credentialOfferSessions,
      })

      // TODO: remove once above PR is merged and released
      const expiresAt = preAuthSession.createdAt + options.preAuthorizedCodeExpirationInSeconds * 1000
      if (Date.now() > expiresAt) {
        throw new TokenError(400, TokenErrorResponse.invalid_grant, 'Pre-authorized code has expired')
      }
    } catch (error) {
      if (error instanceof TokenError) {
        sendErrorResponse(
          response,
          agentContext.config.logger,
          error.statusCode,
          error.responseError,
          error.getDescription()
        )
      } else {
        sendErrorResponse(response, agentContext.config.logger, 400, TokenErrorResponse.invalid_request, error)
      }
    }

    // NOTE: if we don't call next, the agentContext session handler will NOT be called
    next()
  }
}
