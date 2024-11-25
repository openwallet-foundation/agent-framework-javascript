import type { Key, SdJwtVc } from '@credo-ts/core'

import {
  getJwkFromKey,
  Agent,
  DidKey,
  JwaSignatureAlgorithm,
  KeyType,
  TypedArrayEncoder,
  W3cJwtVerifiableCredential,
} from '@credo-ts/core'
import nock, { cleanAll, enableNetConnect } from 'nock'

import { AskarModule } from '../../../../askar/src'
import { askarModuleConfig } from '../../../../askar/tests/helpers'
import { agentDependencies } from '../../../../node/src'
import { OpenId4VcHolderModule } from '../OpenId4VcHolderModule'
import { OpenId4VciAuthorizationFlow } from '../OpenId4VciHolderServiceOptions'

import { animoOpenIdPlaygroundDraft11SdJwtVc, matrrLaunchpadDraft11JwtVcJson, waltIdDraft11JwtVcJson } from './fixtures'

const holder = new Agent({
  config: {
    label: 'OpenId4VcHolder Test28',
    walletConfig: { id: 'openid4vc-holder-test27', key: 'openid4vc-holder-test27' },
  },
  dependencies: agentDependencies,
  modules: {
    openId4VcHolder: new OpenId4VcHolderModule(),
    askar: new AskarModule(askarModuleConfig),
  },
})

describe('OpenId4VcHolder', () => {
  let holderKey: Key
  let holderDid: string
  let holderVerificationMethod: string

  beforeEach(async () => {
    await holder.initialize()

    holderKey = await holder.wallet.createKey({
      keyType: KeyType.Ed25519,
      privateKey: TypedArrayEncoder.fromString('96213c3d7fc8d4d6754c7a0fd969598e'),
    })
    const holderDidKey = new DidKey(holderKey)
    holderDid = holderDidKey.did
    holderVerificationMethod = `${holderDidKey.did}#${holderDidKey.key.fingerprint}`
  })

  afterEach(async () => {
    await holder.shutdown()
    await holder.wallet.delete()
  })

  describe('[DRAFT 11]: Pre-authorized flow', () => {
    afterEach(() => {
      cleanAll()
      enableNetConnect()
    })

    it('Should successfully receive credential from MATTR launchpad using the pre-authorized flow using a did:key Ed25519 subject and jwt_vc_json credential', async () => {
      const fixture = matrrLaunchpadDraft11JwtVcJson

      /**
       *  Below we're setting up some mock HTTP responses.
       *  These responses are based on the openid-initiate-issuance URI above
       * */
      // setup temporary redirect mock
      nock('https://launchpad.mattrlabs.com').get('/.well-known/openid-credential-issuer').reply(307, undefined, {
        Location: 'https://launchpad.vii.electron.mattrlabs.io/.well-known/openid-credential-issuer',
      })

      // setup server metadata response
      nock('https://launchpad.vii.electron.mattrlabs.io')
        .get('/.well-known/did.json')
        .reply(200, fixture.wellKnownDid)

        .get('/.well-known/openid-configuration')
        .reply(404)

        .get('/.well-known/oauth-authorization-server')
        .reply(404)

        .get('/.well-known/openid-credential-issuer')
        .reply(200, fixture.getMetadataResponse)

        // setup access token response
        .post('/oidc/v1/auth/token')
        .reply(200, fixture.acquireAccessTokenResponse)

        // setup credential request response
        .post('/oidc/v1/auth/credential')
        .reply(200, fixture.credentialResponse)

        .get('/.well-known/did.json')
        .reply(200, fixture.wellKnownDid)

      const resolved = await holder.modules.openId4VcHolder.resolveCredentialOffer(fixture.credentialOffer)
      const accessTokenResponse = await holder.modules.openId4VcHolder.requestToken({
        resolvedCredentialOffer: resolved,
      })
      const credentialsResult = await holder.modules.openId4VcHolder.requestCredentials({
        resolvedCredentialOffer: resolved,
        ...accessTokenResponse,

        verifyCredentialStatus: false,
        // We only allow EdDSa, as we've created a did with keyType ed25519. If we create
        // or determine the did dynamically we could use any signature algorithm
        allowedProofOfPossessionSignatureAlgorithms: [JwaSignatureAlgorithm.EdDSA],
        credentialConfigurationIds: Object.entries(resolved.offeredCredentialConfigurations)
          .filter(([, configuration]) => configuration.format === 'jwt_vc_json')
          .map(([id]) => id),
        credentialBindingResolver: () => ({ method: 'did', didUrl: holderVerificationMethod }),
      })

      expect(credentialsResult.credentials).toHaveLength(1)
      const w3cCredential = credentialsResult.credentials[0].credentials[0] as W3cJwtVerifiableCredential
      expect(w3cCredential).toBeInstanceOf(W3cJwtVerifiableCredential)

      expect(w3cCredential.credential.type).toEqual(['VerifiableCredential', 'OpenBadgeCredential'])
      expect(w3cCredential.credential.credentialSubjectIds[0]).toEqual(holderDid)
    })

    it('Should successfully receive credential from walt.id using the pre-authorized flow using a did:key Ed25519 subject and jwt_vc_json credential', async () => {
      const fixture = waltIdDraft11JwtVcJson

      // setup server metadata response
      nock('https://issuer.portal.walt.id')
        // openid configuration is same as issuer metadata for walt.id
        .get('/.well-known/openid-configuration')
        .reply(200, fixture.getMetadataResponse)

        .get('/.well-known/oauth-authorization-server')
        .reply(404)

        .get('/.well-known/openid-credential-issuer')
        .reply(200, fixture.getMetadataResponse)

        // setup access token response
        .post('/token')
        .reply(200, fixture.acquireAccessTokenResponse)

        // setup credential request response
        .post('/credential')
        .reply(200, fixture.credentialResponse)

      const resolved = await holder.modules.openId4VcHolder.resolveCredentialOffer(fixture.credentialOfferPreAuth)
      const accessTokenResponse = await holder.modules.openId4VcHolder.requestToken({
        resolvedCredentialOffer: resolved,
      })

      await expect(() =>
        holder.modules.openId4VcHolder.requestCredentials({
          resolvedCredentialOffer: resolved,
          ...accessTokenResponse,
          verifyCredentialStatus: false,
          // We only allow EdDSa, as we've created a did with keyType ed25519. If we create
          // or determine the did dynamically we could use any signature algorithm
          allowedProofOfPossessionSignatureAlgorithms: [JwaSignatureAlgorithm.EdDSA],
          credentialConfigurationIds: Object.entries(resolved.offeredCredentialConfigurations)
            .filter(([, configuration]) => configuration.format === 'jwt_vc_json')
            .map(([id]) => id),
          credentialBindingResolver: () => ({ method: 'did', didUrl: holderVerificationMethod }),
        })
      )
        // FIXME: walt.id issues jwt where nbf and issuanceDate do not match
        .rejects.toThrow('JWT nbf and vc.issuanceDate do not match')
    })

    it('Should successfully receive credential from animo openid4vc playground using the pre-authorized flow using a jwk EdDSA subject and vc+sd-jwt credential', async () => {
      const fixture = animoOpenIdPlaygroundDraft11SdJwtVc

      // setup server metadata response
      nock('https://openid4vc.animo.id/oid4vci/0bbfb1c0-9f45-478c-a139-08f6ed610a37')
        .get('/.well-known/openid-configuration')
        .reply(404)

        .get('/.well-known/oauth-authorization-server')
        .reply(404)

        .get('/.well-known/openid-credential-issuer')
        .reply(200, fixture.getMetadataResponse)

        // setup access token response
        .post('/token')
        .reply(200, fixture.acquireAccessTokenResponse)

        // setup credential request response
        .post('/credential')
        .reply(200, fixture.credentialResponse)

        .post('/notification')
        .reply(204, 'No Content')

      const resolvedCredentialOffer = await holder.modules.openId4VcHolder.resolveCredentialOffer(
        fixture.credentialOffer
      )

      const tokenResponse = await holder.modules.openId4VcHolder.requestToken({
        resolvedCredentialOffer,
      })

      const credentialResponse = await holder.modules.openId4VcHolder.requestCredentials({
        resolvedCredentialOffer,
        ...tokenResponse,
        verifyCredentialStatus: false,
        // We only allow EdDSa, as we've created a did with keyType ed25519. If we create
        // or determine the did dynamically we could use any signature algorithm
        allowedProofOfPossessionSignatureAlgorithms: [JwaSignatureAlgorithm.EdDSA],
        credentialConfigurationIds: Object.entries(resolvedCredentialOffer.offeredCredentialConfigurations)
          .filter(([, configuration]) => configuration.format === 'vc+sd-jwt')
          .map(([id]) => id),
        credentialBindingResolver: () => ({ method: 'jwk', jwk: getJwkFromKey(holderKey) }),
      })

      if (!credentialResponse.credentials[0]?.notificationId) throw new Error("Notification metadata wasn't returned")

      await holder.modules.openId4VcHolder.sendNotification({
        accessToken: tokenResponse.accessToken,
        notificationEvent: 'credential_accepted',
        notificationId: credentialResponse.credentials[0]?.notificationId,
        metadata: resolvedCredentialOffer.metadata,
        dpop: credentialResponse.dpop,
      })

      expect(credentialResponse.credentials).toHaveLength(1)
      const credential = credentialResponse.credentials[0].credentials[0] as SdJwtVc
      expect(credential).toEqual({
        claimFormat: 'vc+sd-jwt',
        compact:
          'eyJhbGciOiJFZERTQSIsInR5cCI6InZjK3NkLWp3dCIsImtpZCI6IiN6Nk1raDVITlBDQ0pXWm42V1JMalJQdHR5dllaQnNrWlVkU0pmVGlad2NVU2llcXgifQ.eyJ2Y3QiOiJBbmltb09wZW5JZDRWY1BsYXlncm91bmQiLCJwbGF5Z3JvdW5kIjp7ImZyYW1ld29yayI6IkFyaWVzIEZyYW1ld29yayBKYXZhU2NyaXB0IiwiY3JlYXRlZEJ5IjoiQW5pbW8gU29sdXRpb25zIiwiX3NkIjpbImZZM0ZqUHpZSEZOcHlZZnRnVl9kX25DMlRHSVh4UnZocE00VHdrMk1yMDQiLCJwTnNqdmZJeVBZOEQwTks1c1l0alR2Nkc2R0FNVDNLTjdaZDNVNDAwZ1pZIl19LCJjbmYiOnsiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4Ijoia2MydGxwaGNadzFBSUt5a3pNNnBjY2k2UXNLQW9jWXpGTC01RmUzNmg2RSJ9fSwiaXNzIjoiZGlkOmtleTp6Nk1raDVITlBDQ0pXWm42V1JMalJQdHR5dllaQnNrWlVkU0pmVGlad2NVU2llcXgiLCJpYXQiOjE3MDU4NDM1NzQsIl9zZF9hbGciOiJzaGEtMjU2In0.2iAjaCFcuiHXTfQsrxXo6BghtwzqTrfDmhmarAAJAhY8r9yKXY3d10JY1dry2KnaEYWpq2R786thjdA5BXlPAQ~WyI5MzM3MTM0NzU4NDM3MjYyODY3NTE4NzkiLCJsYW5ndWFnZSIsIlR5cGVTY3JpcHQiXQ~WyIxMTQ3MDA5ODk2Nzc2MDYzOTc1MDUwOTMxIiwidmVyc2lvbiIsIjEuMCJd~',
        encoded:
          'eyJhbGciOiJFZERTQSIsInR5cCI6InZjK3NkLWp3dCIsImtpZCI6IiN6Nk1raDVITlBDQ0pXWm42V1JMalJQdHR5dllaQnNrWlVkU0pmVGlad2NVU2llcXgifQ.eyJ2Y3QiOiJBbmltb09wZW5JZDRWY1BsYXlncm91bmQiLCJwbGF5Z3JvdW5kIjp7ImZyYW1ld29yayI6IkFyaWVzIEZyYW1ld29yayBKYXZhU2NyaXB0IiwiY3JlYXRlZEJ5IjoiQW5pbW8gU29sdXRpb25zIiwiX3NkIjpbImZZM0ZqUHpZSEZOcHlZZnRnVl9kX25DMlRHSVh4UnZocE00VHdrMk1yMDQiLCJwTnNqdmZJeVBZOEQwTks1c1l0alR2Nkc2R0FNVDNLTjdaZDNVNDAwZ1pZIl19LCJjbmYiOnsiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4Ijoia2MydGxwaGNadzFBSUt5a3pNNnBjY2k2UXNLQW9jWXpGTC01RmUzNmg2RSJ9fSwiaXNzIjoiZGlkOmtleTp6Nk1raDVITlBDQ0pXWm42V1JMalJQdHR5dllaQnNrWlVkU0pmVGlad2NVU2llcXgiLCJpYXQiOjE3MDU4NDM1NzQsIl9zZF9hbGciOiJzaGEtMjU2In0.2iAjaCFcuiHXTfQsrxXo6BghtwzqTrfDmhmarAAJAhY8r9yKXY3d10JY1dry2KnaEYWpq2R786thjdA5BXlPAQ~WyI5MzM3MTM0NzU4NDM3MjYyODY3NTE4NzkiLCJsYW5ndWFnZSIsIlR5cGVTY3JpcHQiXQ~WyIxMTQ3MDA5ODk2Nzc2MDYzOTc1MDUwOTMxIiwidmVyc2lvbiIsIjEuMCJd~',
        header: {
          alg: 'EdDSA',
          kid: '#z6Mkh5HNPCCJWZn6WRLjRPttyvYZBskZUdSJfTiZwcUSieqx',
          typ: 'vc+sd-jwt',
        },
        payload: {
          _sd_alg: 'sha-256',
          cnf: {
            jwk: {
              crv: 'Ed25519',
              kty: 'OKP',
              x: 'kc2tlphcZw1AIKykzM6pcci6QsKAocYzFL-5Fe36h6E',
            },
          },
          iat: 1705843574,
          iss: 'did:key:z6Mkh5HNPCCJWZn6WRLjRPttyvYZBskZUdSJfTiZwcUSieqx',
          playground: {
            _sd: ['fY3FjPzYHFNpyYftgV_d_nC2TGIXxRvhpM4Twk2Mr04', 'pNsjvfIyPY8D0NK5sYtjTv6G6GAMT3KN7Zd3U400gZY'],
            createdBy: 'Animo Solutions',
            framework: 'Aries Framework JavaScript',
          },
          vct: 'AnimoOpenId4VcPlayground',
        },
        prettyClaims: {
          cnf: {
            jwk: {
              crv: 'Ed25519',
              kty: 'OKP',
              x: 'kc2tlphcZw1AIKykzM6pcci6QsKAocYzFL-5Fe36h6E',
            },
          },
          iat: 1705843574,
          iss: 'did:key:z6Mkh5HNPCCJWZn6WRLjRPttyvYZBskZUdSJfTiZwcUSieqx',
          playground: {
            createdBy: 'Animo Solutions',
            framework: 'Aries Framework JavaScript',
            language: 'TypeScript',
            version: '1.0',
          },
          vct: 'AnimoOpenId4VcPlayground',
        },
      })
    })
  })

  describe('[DRAFT 11]: Authorization flow', () => {
    afterAll(() => {
      cleanAll()
      enableNetConnect()
    })

    it('Should successfully receive credential from walt.id using the authorized flow using a did:key Ed25519 subject and jwt_vc_json credential', async () => {
      const fixture = waltIdDraft11JwtVcJson

      // setup temporary redirect mock
      nock('https://issuer.portal.walt.id')
        .get('/.well-known/openid-credential-issuer')
        .reply(200, fixture.getMetadataResponse)
        .get('/.well-known/openid-configuration')
        .reply(200, fixture.getMetadataResponse)
        .get('/.well-known/oauth-authorization-server')
        .reply(404)
        .post('/par')
        .reply(200, fixture.par)
        // setup access token response
        .post('/token')
        .reply(200, fixture.acquireAccessTokenResponse)
        // setup credential request response
        .post('/credential')
        .reply(200, fixture.credentialResponse)

        .get('/.well-known/oauth-authorization-server')
        .reply(404)

      const resolvedCredentialOffer = await holder.modules.openId4VcHolder.resolveCredentialOffer(
        fixture.credentialOfferAuth
      )

      const resolvedAuthorizationRequest = await holder.modules.openId4VcHolder.resolveIssuanceAuthorizationRequest(
        resolvedCredentialOffer,
        {
          clientId: 'test-client',
          redirectUri: 'http://example.com',
          scope: ['openid', 'UniversityDegree'],
        }
      )

      if (resolvedAuthorizationRequest.authorizationFlow === OpenId4VciAuthorizationFlow.PresentationDuringIssuance) {
        throw new Error('unexpected authorization flow')
      }

      const tokenResponse = await holder.modules.openId4VcHolder.requestToken({
        resolvedCredentialOffer,
        clientId: 'test-client',
        redirectUri: 'https://example.com',
        code: fixture.authorizationCode,
      })

      await expect(
        holder.modules.openId4VcHolder.requestCredentials({
          resolvedCredentialOffer,
          ...tokenResponse,
          allowedProofOfPossessionSignatureAlgorithms: [JwaSignatureAlgorithm.EdDSA],
          credentialBindingResolver: () => ({ method: 'did', didUrl: holderVerificationMethod }),
          verifyCredentialStatus: false,
        })
      )
        // FIXME: credential returned by walt.id has nbf and issuanceDate that do not match
        // but we know that we at least received the credential if we got to this error
        .rejects.toThrow('JWT nbf and vc.issuanceDate do not match')
    })
  })
})
