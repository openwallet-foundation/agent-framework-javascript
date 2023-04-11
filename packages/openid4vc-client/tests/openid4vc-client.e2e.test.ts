import type { KeyDidCreateOptions } from '@aries-framework/core'

import { Agent, KeyType, TypedArrayEncoder, W3cCredentialRecord, W3cCredentialsModule } from '@aries-framework/core'
import nock, { cleanAll, enableNetConnect } from 'nock'

import { didKeyToInstanceOfKey } from '../../core/src/modules/dids/helpers'
import { customDocumentLoader } from '../../core/src/modules/vc/__tests__/documentLoader'
import { getAgentOptions, indySdk } from '../../core/tests'
import { IndySdkModule } from '../../indy-sdk/src'

import { acquireAccessTokenResponse, credentialRequestResponse, getMetadataResponse } from './fixtures'

import { OpenId4VcClientModule } from '@aries-framework/openid4vc-client'

const modules = {
  openId4VcClient: new OpenId4VcClientModule(),
  w3cCredentials: new W3cCredentialsModule({
    documentLoader: customDocumentLoader,
  }),
  indySdk: new IndySdkModule({
    indySdk,
  }),
}

describe('OpenId4VcClient', () => {
  let agent: Agent<typeof modules>

  beforeEach(async () => {
    const agentOptions = getAgentOptions('OpenId4VcClient Agent', {}, modules)

    agent = new Agent(agentOptions)

    await agent.initialize()
  })

  afterEach(async () => {
    await agent.shutdown()
    await agent.wallet.delete()
  })

  describe('Pre-authorized flow', () => {
    const issuerUri =
      'openid-initiate-issuance://?issuer=https://launchpad.mattrlabs.com&credential_type=OpenBadgeCredential&pre-authorized_code=krBcsBIlye2T-G4-rHHnRZUCah9uzDKwohJK6ABNvL-'
    beforeAll(async () => {
      /**
       *  Below we're setting up some mock HTTP responses.
       *  These responses are based on the openid-initiate-issuance URI above
       * */

      // setup temporary redirect mock
      nock('https://launchpad.mattrlabs.com').get('/.well-known/openid-credential-issuer').reply(307, undefined, {
        Location: 'https://launchpad.vii.electron.mattrlabs.io/.well-known/openid-credential-issuer',
      })

      // setup server metadata response
      const httpMock = nock('https://launchpad.vii.electron.mattrlabs.io')
        .get('/.well-known/openid-credential-issuer')
        .reply(200, getMetadataResponse)

      // setup access token response
      httpMock.post('/oidc/v1/auth/token').reply(200, acquireAccessTokenResponse)

      // setup credential request response
      httpMock.post('/oidc/v1/auth/credential').reply(200, credentialRequestResponse)
    })

    afterAll(async () => {
      cleanAll()
      enableNetConnect()
    })

    it('Should successfully execute the pre-authorized flow', async () => {
      const did = await agent.dids.create<KeyDidCreateOptions>({
        method: 'key',
        options: {
          keyType: KeyType.Ed25519,
        },
        secret: {
          privateKey: TypedArrayEncoder.fromString('96213c3d7fc8d4d6754c7a0fd969598e'),
        },
      })

      const keyInstance = didKeyToInstanceOfKey(did.didState.did as string)

      const kid = `${did.didState.did as string}#${keyInstance.fingerprint as string}`

      const w3cCredentialRecord = await agent.modules.openId4VcClient.requestCredentialUsingPreAuthorizedCode({
        issuerUri,
        kid,
        verifyRevocationState: false,
      })

      expect(w3cCredentialRecord).toBeInstanceOf(W3cCredentialRecord)

      expect(w3cCredentialRecord.credential.type).toEqual([
        'VerifiableCredential',
        'VerifiableCredentialExtension',
        'OpenBadgeCredential',
      ])

      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-ignore
      expect(w3cCredentialRecord.credential.credentialSubject.id).toEqual(did.didState.did)
    })
  })
  describe('Authorization flow', () => {
    beforeAll(async () => {
      /**
       *  Below we're setting up some mock HTTP responses.
       *  These responses are based on the openid-initiate-issuance URI above
       * */

      // setup temporary redirect mock
      nock('https://launchpad.mattrlabs.com').get('/.well-known/openid-credential-issuer').reply(307, undefined, {
        Location: 'https://launchpad.vii.electron.mattrlabs.io/.well-known/openid-credential-issuer',
      })

      // setup server metadata response
      const httpMock = nock('https://launchpad.vii.electron.mattrlabs.io')
        .get('/.well-known/openid-credential-issuer')
        .reply(200, getMetadataResponse)

      // setup access token response
      httpMock.post('/oidc/v1/auth/token').reply(200, acquireAccessTokenResponse)

      // setup credential request response
      httpMock.post('/oidc/v1/auth/credential').reply(200, credentialRequestResponse)
    })

    afterAll(async () => {
      cleanAll()
      enableNetConnect()
    })

    it('should generate a valid authorization url', async () => {
      const clientId = 'test-client'

      const redirectUri = 'https://example.com/cb'
      const scope = ['TestCredential']
      const initiationUri =
        'openid-initiate-issuance://?issuer=https://launchpad.mattrlabs.com&credential_type=OpenBadgeCredential'
      const { authorizationUrl } = await agent.modules.openId4VcClient.generateAuthorizationUrl({
        clientId,
        redirectUri,
        scope,
        initiationUri,
      })

      const parsedUrl = new URL(authorizationUrl)
      expect(authorizationUrl.startsWith('https://launchpad.vii.electron.mattrlabs.io/oidc/v1/auth/authorize')).toBe(
        true
      )
      expect(parsedUrl.searchParams.get('response_type')).toBe('code')
      expect(parsedUrl.searchParams.get('client_id')).toBe(clientId)
      expect(parsedUrl.searchParams.get('code_challenge_method')).toBe('S256')
      expect(parsedUrl.searchParams.get('redirect_uri')).toBe(redirectUri)
    })
    it('should throw if no scope is provided', async () => {
      // setup temporary redirect mock
      nock('https://launchpad.mattrlabs.com').get('/.well-known/openid-credential-issuer').reply(307, undefined, {
        Location: 'https://launchpad.vii.electron.mattrlabs.io/.well-known/openid-credential-issuer',
      })

      // setup server metadata response
      nock('https://launchpad.vii.electron.mattrlabs.io')
        .get('/.well-known/openid-credential-issuer')
        .reply(200, getMetadataResponse)

      const clientId = 'test-client'
      const redirectUri = 'https://example.com/cb'
      const initiationUri =
        'openid-initiate-issuance://?issuer=https://launchpad.mattrlabs.com&credential_type=OpenBadgeCredential'
      expect(
        agent.modules.openId4VcClient.generateAuthorizationUrl({
          clientId,
          redirectUri,
          scope: [],
          initiationUri,
        })
      ).rejects.toThrow()
    })
    it('should successfully execute request a credential', async () => {
      // setup temporary redirect mock
      nock('https://launchpad.mattrlabs.com').get('/.well-known/openid-credential-issuer').reply(307, undefined, {
        Location: 'https://launchpad.vii.electron.mattrlabs.io/.well-known/openid-credential-issuer',
      })

      // setup server metadata response
      nock('https://launchpad.vii.electron.mattrlabs.io')
        .get('/.well-known/openid-credential-issuer')
        .reply(200, getMetadataResponse)

      const did = await agent.dids.create<KeyDidCreateOptions>({
        method: 'key',
        options: {
          keyType: KeyType.Ed25519,
        },
        secret: {
          privateKey: TypedArrayEncoder.fromString('96213c3d7fc8d4d6754c7a0fd969598e'),
        },
      })

      const keyInstance = didKeyToInstanceOfKey(did.didState.did as string)

      const kid = `${did.didState.did as string}#${keyInstance.fingerprint as string}`

      const clientId = 'test-client'

      const redirectUri = 'https://example.com/cb'
      const initiationUri =
        'openid-initiate-issuance://?issuer=https://launchpad.mattrlabs.com&credential_type=OpenBadgeCredential'

      const scope = ['TestCredential']
      const { codeVerifier } = await agent.modules.openId4VcClient.generateAuthorizationUrl({
        clientId,
        redirectUri,
        scope,
        initiationUri,
      })
      const w3cCredentialRecord = await agent.modules.openId4VcClient.requestCredentialUsingAuthorizationCode({
        clientId: clientId,
        authorizationCode: 'test-code',
        codeVerifier: codeVerifier,
        verifyRevocationState: false,
        kid: kid,
        issuerUri: initiationUri,
        redirectUri: redirectUri,
      })

      expect(w3cCredentialRecord).toBeInstanceOf(W3cCredentialRecord)

      expect(w3cCredentialRecord.credential.type).toEqual([
        'VerifiableCredential',
        'VerifiableCredentialExtension',
        'OpenBadgeCredential',
      ])

      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-ignore
      expect(w3cCredentialRecord.credential.credentialSubject.id).toEqual(did.didState.did)
    })
  })
})
