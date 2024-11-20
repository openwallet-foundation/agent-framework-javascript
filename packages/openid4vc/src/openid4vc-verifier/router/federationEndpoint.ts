import type { OpenId4VcVerificationRequest } from './requestContext'
import type { Key, Buffer } from '@credo-ts/core'
import type { RPRegistrationMetadataPayload } from '@sphereon/did-auth-siop'
import type { Router, Response } from 'express'

import { getJwkFromKey, KeyType } from '@credo-ts/core'
import { createEntityConfiguration } from '@openid-federation/core'
import { LanguageTagUtils, removeNullUndefined } from '@sphereon/did-auth-siop'

import { getRequestContext, sendErrorResponse } from '../../shared/router'
import { OpenId4VcSiopVerifierService } from '../OpenId4VcSiopVerifierService'
import { OpenId4VcVerifierModuleConfig } from '../OpenId4VcVerifierModuleConfig'

// TODO: Add types but this function is originally from the @
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const createRPRegistrationMetadataPayload = (opts: any): RPRegistrationMetadataPayload => {
  const rpRegistrationMetadataPayload: RPRegistrationMetadataPayload = {
    id_token_signing_alg_values_supported: opts.idTokenSigningAlgValuesSupported,
    request_object_signing_alg_values_supported: opts.requestObjectSigningAlgValuesSupported,
    response_types_supported: opts.responseTypesSupported,
    scopes_supported: opts.scopesSupported,
    subject_types_supported: opts.subjectTypesSupported,
    subject_syntax_types_supported: opts.subject_syntax_types_supported || ['did:web:', 'did:ion:'],
    vp_formats: opts.vpFormatsSupported,
    client_name: opts.clientName,
    logo_uri: opts.logo_uri,
    tos_uri: opts.tos_uri,
    client_purpose: opts.clientPurpose,
    client_id: opts.client_id,
  }

  const languageTagEnabledFieldsNamesMapping = new Map<string, string>()
  languageTagEnabledFieldsNamesMapping.set('clientName', 'client_name')
  languageTagEnabledFieldsNamesMapping.set('clientPurpose', 'client_purpose')

  //   TODO: Do we need this?
  const languageTaggedFields: Map<string, string> = LanguageTagUtils.getLanguageTaggedPropertiesMapped(
    opts,
    languageTagEnabledFieldsNamesMapping
  )

  languageTaggedFields.forEach((value: string, key: string) => {
    const _key = key as keyof typeof rpRegistrationMetadataPayload
    rpRegistrationMetadataPayload[_key] = value
  })

  return removeNullUndefined(rpRegistrationMetadataPayload)
}

export function configureFederationEndpoint(router: Router) {
  // TODO: this whole result needs to be cached and the ttl should be the expires of this node

  // TODO: This will not work for multiple instances so we have to save it in the database.
  const federationKeyMapping = new Map<string, Key>()
  const rpSigningKeyMapping = new Map<string, Key>()

  router.get(
    '/.well-known/openid-federation',
    async (request: OpenId4VcVerificationRequest, response: Response, next) => {
      const { agentContext, verifier } = getRequestContext(request)
      const verifierService = agentContext.dependencyManager.resolve(OpenId4VcSiopVerifierService)
      const verifierConfig = agentContext.dependencyManager.resolve(OpenId4VcVerifierModuleConfig)

      try {
        let federationKey = federationKeyMapping.get(verifier.verifierId)
        if (!federationKey) {
          federationKey = await agentContext.wallet.createKey({
            keyType: KeyType.Ed25519,
          })
          federationKeyMapping.set(verifier.verifierId, federationKey)
        }

        let rpSigningKey = rpSigningKeyMapping.get(verifier.verifierId)
        if (!rpSigningKey) {
          rpSigningKey = await agentContext.wallet.createKey({
            keyType: KeyType.Ed25519,
          })
          rpSigningKeyMapping.set(verifier.verifierId, rpSigningKey)
        }

        const relyingParty = await verifierService.getRelyingParty(agentContext, verifier, {
          clientId: verifierConfig.baseUrl,
          clientIdScheme: 'entity_id',
          authorizationResponseUrl: `${verifierConfig.baseUrl}/siop/${verifier.verifierId}/authorize`,
        })

        const verifierEntityId = `${verifierConfig.baseUrl}/${verifier.verifierId}`

        const rpMetadata = createRPRegistrationMetadataPayload(relyingParty.createRequestOptions.clientMetadata)

        // TODO: We also need to cache the entity configuration until it expires
        const now = new Date()
        // TODO: We also need to check if the x509 certificate is still valid until this expires
        const expires = new Date(now.getTime() + 1000 * 60 * 60 * 24) // 1 day

        const jwk = getJwkFromKey(federationKey)
        const alg = jwk.supportedSignatureAlgorithms[0]
        const kid = federationKey.fingerprint

        const entityConfiguration = await createEntityConfiguration({
          header: {
            kid,
            alg,
            typ: 'entity-statement+jwt',
          },
          claims: {
            sub: verifierEntityId,
            iss: verifierEntityId,
            iat: now,
            exp: expires,
            jwks: {
              keys: [{ kid, alg, ...jwk.toJson() }],
            },
            metadata: {
              federation_entity: {
                organization_name: rpMetadata.client_name,
                logo_uri: rpMetadata.logo_uri,
              },
              openid_relying_party: {
                ...rpMetadata,
                jwks: {
                  keys: [{ kid, alg, ...getJwkFromKey(rpSigningKey).toJson() }],
                },
                client_registration_types: ['automatic'], // TODO: Not really sure why we need to provide this manually
              },
            },
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
    }
  )
}
