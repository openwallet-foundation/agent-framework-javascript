import type { OpenId4VcIssuanceRequest } from './requestContext'
import type { Buffer } from '@credo-ts/core'
import type { Router, Response } from 'express'

import { Key, getJwkFromKey, KeyType } from '@credo-ts/core'
import { createEntityConfiguration } from '@openid-federation/core'

import { getRequestContext, sendErrorResponse } from '../../shared/router'

// TODO: It's also possible that the issuer and the verifier can have the same openid-federation endpoint. In that case we need to combine them.

export function configureFederationEndpoint(router: Router) {
  // TODO: this whole result needs to be cached and the ttl should be the expires of this node

  router.get('/.well-known/openid-federation', async (request: OpenId4VcIssuanceRequest, response: Response, next) => {
    const { agentContext, issuer } = getRequestContext(request)

    try {
      // TODO: Should be only created once per issuer and be used between instances
      const federationKey = await agentContext.wallet.createKey({
        keyType: KeyType.Ed25519,
      })

      const now = new Date()
      const expires = new Date(now.getTime() + 1000 * 60 * 60 * 24) // 1 day from now

      // TODO: We need to generate a key and always use that for the entity configuration

      const jwk = getJwkFromKey(federationKey)

      const kid = federationKey.fingerprint
      const alg = jwk.supportedSignatureAlgorithms[0]

      const issuerDisplay = issuer.display?.[0]

      const accessTokenSigningKey = Key.fromFingerprint(issuer.accessTokenPublicKeyFingerprint)

      const entityConfiguration = await createEntityConfiguration({
        claims: {
          sub: issuer.issuerId,
          iss: issuer.issuerId,
          iat: now,
          exp: expires,
          jwks: {
            keys: [{ kid, alg, ...jwk.toJson() }],
          },
          metadata: {
            federation_entity: issuerDisplay
              ? {
                  organization_name: issuerDisplay.name,
                  logo_uri: issuerDisplay.logo?.uri,
                }
              : undefined,
            openid_provider: {
              // TODO: The type isn't correct yet down the line so that needs to be updated before
              // credential_issuer: issuerMetadata.issuerUrl,
              // token_endpoint: issuerMetadata.tokenEndpoint,
              // credential_endpoint: issuerMetadata.credentialEndpoint,
              // authorization_server: issuerMetadata.authorizationServer,
              // authorization_servers: issuerMetadata.authorizationServer
              //   ? [issuerMetadata.authorizationServer]
              //   : undefined,
              // credentials_supported: issuerMetadata.credentialsSupported,
              // credential_configurations_supported: issuerMetadata.credentialConfigurationsSupported,
              // display: issuerMetadata.issuerDisplay,
              // dpop_signing_alg_values_supported: issuerMetadata.dpopSigningAlgValuesSupported,

              client_registration_types_supported: ['automatic'],
              jwks: {
                keys: [
                  {
                    // TODO: Not 100% sure if this is the right key that we want to expose here or a different one
                    kid: accessTokenSigningKey.fingerprint,
                    ...getJwkFromKey(accessTokenSigningKey).toJson(),
                  },
                ],
              },
            },
          },
        },
        header: {
          kid,
          alg,
          typ: 'entity-statement+jwt',
        },
        signJwtCallback: ({ toBeSigned }) =>
          agentContext.wallet.sign({
            data: toBeSigned as Buffer,
            key: federationKey,
          }),
      })

      response.writeHead(200, { 'Content-Type': 'application/entity-statement+jwt' }).end(entityConfiguration)
    } catch (error) {
      agentContext.config.logger.error('Failed to create entity configuration', {
        error,
      })
      sendErrorResponse(response, next, agentContext.config.logger, 500, 'invalid_request', error)
      return
    }

    // NOTE: if we don't call next, the agentContext session handler will NOT be called
    next()
  })
}
