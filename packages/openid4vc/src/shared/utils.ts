import type { OpenId4VcIssuerX5c, OpenId4VcJwtIssuer, OpenId4VcJwtIssuerFederation } from './models'
import type { AgentContext, DidPurpose, JwaSignatureAlgorithm, JwkJson, Key } from '@credo-ts/core'
import type { JwtIssuerWithContext as VpJwtIssuerWithContext, VerifyJwtCallback } from '@sphereon/did-auth-siop'
import type { DPoPJwtIssuerWithContext, CreateJwtCallback, JwtIssuer } from '@sphereon/oid4vc-common'

import {
  CredoError,
  DidsApi,
  JwsService,
  JwtPayload,
  SignatureSuiteRegistry,
  X509Service,
  getDomainFromUrl,
  getJwkClassFromKeyType,
  getJwkFromJson,
  getJwkFromKey,
  getKeyFromVerificationMethod,
} from '@credo-ts/core'
import { fetchEntityConfiguration, resolveTrustChains } from '@openid-federation/core'

/**
 * Returns the JWA Signature Algorithms that are supported by the wallet.
 *
 * This is an approximation based on the supported key types of the wallet.
 * This is not 100% correct as a supporting a key type does not mean you support
 * all the algorithms for that key type. However, this needs refactoring of the wallet
 * that is planned for the 0.5.0 release.
 */
export function getSupportedJwaSignatureAlgorithms(agentContext: AgentContext): JwaSignatureAlgorithm[] {
  const supportedKeyTypes = agentContext.wallet.supportedKeyTypes

  // Extract the supported JWS algs based on the key types the wallet support.
  const supportedJwaSignatureAlgorithms = supportedKeyTypes
    // Map the supported key types to the supported JWK class
    .map(getJwkClassFromKeyType)
    // Filter out the undefined values
    .filter((jwkClass): jwkClass is Exclude<typeof jwkClass, undefined> => jwkClass !== undefined)
    // Extract the supported JWA signature algorithms from the JWK class
    .flatMap((jwkClass) => jwkClass.supportedSignatureAlgorithms)

  return supportedJwaSignatureAlgorithms
}

export async function getKeyFromDid(
  agentContext: AgentContext,
  didUrl: string,
  allowedPurposes: DidPurpose[] = ['authentication']
) {
  const didsApi = agentContext.dependencyManager.resolve(DidsApi)
  const didDocument = await didsApi.resolveDidDocument(didUrl)
  const verificationMethod = didDocument.dereferenceKey(didUrl, allowedPurposes)

  return getKeyFromVerificationMethod(verificationMethod)
}

type VerifyJwtCallbackOptions = {
  federation?: {
    trustedEntityIds?: string[]
  }
}

export function getVerifyJwtCallback(
  agentContext: AgentContext,
  options: VerifyJwtCallbackOptions = {}
): VerifyJwtCallback {
  const logger = agentContext.config.logger

  return async (jwtVerifier, jwt) => {
    const jwsService = agentContext.dependencyManager.resolve(JwsService)

    if (jwtVerifier.method === 'did') {
      const key = await getKeyFromDid(agentContext, jwtVerifier.didUrl)
      const jwk = getJwkFromKey(key)

      const res = await jwsService.verifyJws(agentContext, { jws: jwt.raw, jwkResolver: () => jwk })
      return res.isValid
    }

    if (jwtVerifier.method === 'x5c' || jwtVerifier.method === 'jwk') {
      const res = await jwsService.verifyJws(agentContext, { jws: jwt.raw })
      return res.isValid
    }

    if (jwtVerifier.method === 'openid-federation') {
      const { entityId } = jwtVerifier
      const trustedEntityIds = options.federation?.trustedEntityIds
      if (!trustedEntityIds) {
        logger.error('No trusted entity ids provided but is required for the "openid-federation" method.')
        return false
      }

      const validTrustChains = await resolveTrustChains({
        entityId,
        trustAnchorEntityIds: trustedEntityIds,
        verifyJwtCallback: async ({ jwt, jwk }) => {
          const res = await jwsService.verifyJws(agentContext, {
            jws: jwt,
            jwkResolver: () => getJwkFromJson(jwk),
          })

          return res.isValid
        },
      })
      // When the chain is already invalid we can return false immediately
      if (validTrustChains.length === 0) {
        logger.error(`${entityId} is not part of a trusted federation.`)
        return false
      }

      // Pick the first valid trust chain for validation of the leaf entity jwks
      const { leafEntityConfiguration } = validTrustChains[0]
      // TODO: No support yet for signed jwks and external jwks
      const rpSigningKeys = leafEntityConfiguration?.metadata?.openid_relying_party?.jwks?.keys
      if (!rpSigningKeys || rpSigningKeys.length === 0)
        throw new CredoError('No rp signing keys found in the entity configuration.')

      const res = await jwsService.verifyJws(agentContext, {
        jws: jwt.raw,
        jwkResolver: () => getJwkFromJson(rpSigningKeys[0]),
      })
      if (!res.isValid) {
        logger.error(`${entityId} does not match the expected signing key.`)
      }

      // TODO: There is no check yet for the policies

      return res.isValid
    }

    throw new Error(`Unsupported jwt verifier method: '${jwtVerifier.method}'`)
  }
}

export function getCreateJwtCallback(
  agentContext: AgentContext
): CreateJwtCallback<DPoPJwtIssuerWithContext | VpJwtIssuerWithContext> {
  return async (jwtIssuer, jwt) => {
    const jwsService = agentContext.dependencyManager.resolve(JwsService)

    if (jwtIssuer.method === 'did') {
      const key = await getKeyFromDid(agentContext, jwtIssuer.didUrl)
      const jws = await jwsService.createJwsCompact(agentContext, {
        protectedHeaderOptions: { ...jwt.header, alg: jwtIssuer.alg, jwk: undefined },
        payload: JwtPayload.fromJson(jwt.payload),
        key,
      })

      return jws
    }

    if (jwtIssuer.method === 'jwk') {
      if (!jwtIssuer.jwk.kty) {
        throw new CredoError('Missing required key type (kty) in the jwk.')
      }
      const jwk = getJwkFromJson(jwtIssuer.jwk as JwkJson)
      const key = jwk.key
      const jws = await jwsService.createJwsCompact(agentContext, {
        protectedHeaderOptions: { ...jwt.header, jwk, alg: jwtIssuer.alg },
        payload: JwtPayload.fromJson(jwt.payload),
        key,
      })

      return jws
    }

    if (jwtIssuer.method === 'x5c') {
      const leafCertificate = X509Service.getLeafCertificate(agentContext, { certificateChain: jwtIssuer.x5c })

      const jws = await jwsService.createJwsCompact(agentContext, {
        protectedHeaderOptions: { ...jwt.header, alg: jwtIssuer.alg, jwk: undefined },
        payload: JwtPayload.fromJson(jwt.payload),
        key: leafCertificate.publicKey,
      })

      return jws
    }

    if (jwtIssuer.method === 'custom') {
      // TODO: This could be used as the issuer and verifier. Based on that we need to search for a jwk in the entity configuration
      const { options } = jwtIssuer
      if (!options) throw new CredoError(`Custom jwtIssuer must have options defined.`)
      if (!options.method) throw new CredoError(`Custom jwtIssuer's options must have a 'method' property defined.`)
      if (options.method !== 'openid-federation')
        throw new CredoError(
          `Custom jwtIssuer's options 'method' property must be 'openid-federation' when using the 'custom' method.`
        )
      if (!options.entityId) throw new CredoError(`Custom jwtIssuer must have entityId defined.`)
      if (typeof options.entityId !== 'string') throw new CredoError(`Custom jwtIssuer's entityId must be a string.`)

      const { entityId } = options

      const entityConfiguration = await fetchEntityConfiguration({
        entityId,
        verifyJwtCallback: async ({ jwt, jwk }) => {
          const res = await jwsService.verifyJws(agentContext, { jws: jwt, jwkResolver: () => getJwkFromJson(jwk) })
          return res.isValid
        },
      })

      // TODO: Not really sure if this is also used for the issuer so if so we need to change this logic. But currently it's not possible to specify a issuer method with issuance so I think it's fine.

      // NOTE: Hardcoded part for the verifier
      const openIdRelyingParty = entityConfiguration.metadata?.openid_relying_party
      if (!openIdRelyingParty) throw new CredoError('No openid-relying-party found in the entity configuration.')

      // NOTE: No support for signed jwks and external jwks
      const jwks = openIdRelyingParty.jwks
      if (!jwks) throw new CredoError('No jwks found in the openid-relying-party.')

      // TODO: Not 100% sure what key to pick here I think the one that matches the kid in the jwt header of the entity configuration or we should pass a alg and pick a jwk based on that?
      const jwk = getJwkFromJson(jwks.keys[0])

      // TODO: This gives a weird error when the private key is not available in the wallet so we should handle that better
      const jws = await jwsService.createJwsCompact(agentContext, {
        protectedHeaderOptions: { ...jwt.header, jwk, alg: jwk.supportedSignatureAlgorithms[0] },
        payload: JwtPayload.fromJson(jwt.payload),
        key: jwk.key,
      })

      return jws
    }

    // @ts-expect-error - All methods are supported currently so there is no unsupported method anymore
    throw new Error(`Unsupported jwt issuer method '${jwtIssuer.method}'`)
  }
}

export async function openIdTokenIssuerToJwtIssuer(
  agentContext: AgentContext,
  openId4VcTokenIssuer:
    | Exclude<OpenId4VcJwtIssuer, OpenId4VcIssuerX5c | OpenId4VcJwtIssuerFederation>
    | (OpenId4VcIssuerX5c & { issuer: string })
    | (OpenId4VcJwtIssuerFederation & { entityId: string })
): Promise<JwtIssuer> {
  if (openId4VcTokenIssuer.method === 'did') {
    const key = await getKeyFromDid(agentContext, openId4VcTokenIssuer.didUrl)
    const alg = getJwkClassFromKeyType(key.keyType)?.supportedSignatureAlgorithms[0]
    if (!alg) throw new CredoError(`No supported signature algorithms for key type: ${key.keyType}`)

    return {
      method: openId4VcTokenIssuer.method,
      didUrl: openId4VcTokenIssuer.didUrl,
      alg,
    }
  }

  if (openId4VcTokenIssuer.method === 'x5c') {
    const leafCertificate = X509Service.getLeafCertificate(agentContext, {
      certificateChain: openId4VcTokenIssuer.x5c,
    })

    const jwk = getJwkFromKey(leafCertificate.publicKey)
    const alg = jwk.supportedSignatureAlgorithms[0]
    if (!alg) {
      throw new CredoError(`No supported signature algorithms found key type: '${jwk.keyType}'`)
    }

    if (
      !openId4VcTokenIssuer.issuer.startsWith('https://') &&
      !(openId4VcTokenIssuer.issuer.startsWith('http://') && agentContext.config.allowInsecureHttpUrls)
    ) {
      throw new CredoError('The X509 certificate issuer must be a HTTPS URI.')
    }

    if (
      !leafCertificate.sanUriNames.includes(openId4VcTokenIssuer.issuer) &&
      !leafCertificate.sanDnsNames.includes(getDomainFromUrl(openId4VcTokenIssuer.issuer))
    ) {
      const sanUriMessage =
        leafCertificate.sanUriNames.length > 0
          ? `SAN-URI names are ${leafCertificate.sanUriNames.join(', ')}`
          : 'there are no SAN-URI names'
      const sanDnsMessage =
        leafCertificate.sanDnsNames.length > 0
          ? `SAN-DNS names are ${leafCertificate.sanDnsNames.join(', ')}`
          : 'there are no SAN-DNS names'
      throw new Error(
        `The 'iss' claim in the payload does not match a 'SAN-URI' or 'SAN-DNS' name in the x5c certificate. 'iss' value is '${openId4VcTokenIssuer.issuer}', ${sanUriMessage}, ${sanDnsMessage} (for SAN-DNS only domain has to match)`
      )
    }

    return {
      ...openId4VcTokenIssuer,
      alg,
    }
  }

  if (openId4VcTokenIssuer.method === 'jwk') {
    const alg = openId4VcTokenIssuer.jwk.supportedSignatureAlgorithms[0]
    if (!alg) {
      throw new CredoError(`No supported signature algorithms for key type: '${openId4VcTokenIssuer.jwk.keyType}'`)
    }
    return {
      ...openId4VcTokenIssuer,
      jwk: openId4VcTokenIssuer.jwk.toJson(),
      alg,
    }
  }

  if (openId4VcTokenIssuer.method === 'openid-federation') {
    // TODO: Not sure what we want here if we need to add a new type to the sphereon library or that we can do it with the custom issuer
    return {
      method: 'custom',
      options: {
        method: 'openid-federation',
        entityId: openId4VcTokenIssuer.entityId,
      },
    }
  }

  throw new CredoError(`Unsupported jwt issuer method '${(openId4VcTokenIssuer as OpenId4VcJwtIssuer).method}'`)
}

export function getProofTypeFromKey(agentContext: AgentContext, key: Key) {
  const signatureSuiteRegistry = agentContext.dependencyManager.resolve(SignatureSuiteRegistry)

  const supportedSignatureSuites = signatureSuiteRegistry.getAllByKeyType(key.keyType)
  if (supportedSignatureSuites.length === 0) {
    throw new CredoError(`Couldn't find a supported signature suite for the given key type '${key.keyType}'.`)
  }

  return supportedSignatureSuites[0].proofType
}

export function addSecondsToDate(date: Date, seconds: number) {
  return new Date(date.getTime() + seconds * 1000)
}

export function dateToSeconds(date: Date) {
  return Math.floor(date.getTime() / 1000)
}
