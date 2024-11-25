import type { AgentType, TenantType } from './utils'
import type { OpenId4VciSignMdocCredentials, OpenId4VcVerifierModuleConfig } from '../src'
import type { OpenId4VciCredentialBindingResolver } from '../src/openid4vc-holder'
import type { AuthorizationServerMetadata } from '@animo-id/oauth2'
import type { DifPresentationExchangeDefinitionV2, JwkJson, Mdoc, MdocDeviceResponse, SdJwtVc } from '@credo-ts/core'
import type { Server } from 'http'

import {
  calculateJwkThumbprint,
  clientAuthenticationNone,
  HashAlgorithm,
  Oauth2AuthorizationServer,
  preAuthorizedCodeGrantIdentifier,
} from '@animo-id/oauth2'
import { AuthorizationFlow } from '@animo-id/oid4vci'
import {
  CredoError,
  ClaimFormat,
  DidsApi,
  DifPresentationExchangeService,
  getJwkFromKey,
  getKeyFromVerificationMethod,
  JsonEncoder,
  JwaSignatureAlgorithm,
  W3cCredential,
  W3cCredentialSubject,
  w3cDate,
  W3cIssuer,
  X509Module,
  KeyType,
  Jwt,
  Jwk,
  X509ModuleConfig,
  parseDid,
  X509Service,
  Hasher,
  JwsService,
  JwtPayload,
} from '@credo-ts/core'
import express, { type Express } from 'express'

import { AskarModule } from '../../askar/src'
import { askarModuleConfig } from '../../askar/tests/helpers'
import { TenantsModule } from '../../tenants/src'
import {
  OpenId4VcHolderModule,
  OpenId4VcIssuanceSessionState,
  OpenId4VcIssuerModule,
  OpenId4VcVerificationSessionState,
  OpenId4VcVerifierModule,
} from '../src'
import { getOid4vciCallbacks } from '../src/shared/callbacks'

import {
  waitForVerificationSessionRecordSubject,
  waitForCredentialIssuanceSessionRecordSubject,
  createAgentFromModules,
  createTenantForAgent,
} from './utils'
import {
  universityDegreeCredentialConfigurationSupported,
  universityDegreeCredentialConfigurationSupportedMdoc,
  universityDegreeCredentialSdJwt2,
} from './utilsVci'
import { openBadgePresentationDefinition, universityDegreePresentationDefinition } from './utilsVp'

const serverPort = 1234
const baseUrl = `http://localhost:${serverPort}`
const issuanceBaseUrl = `${baseUrl}/oid4vci`
const verificationBaseUrl = `${baseUrl}/oid4vp`

describe('OpenId4Vc', () => {
  let expressApp: Express
  let expressServer: Server

  let issuer: AgentType<{
    openId4VcIssuer: OpenId4VcIssuerModule
    tenants: TenantsModule<{ openId4VcIssuer: OpenId4VcIssuerModule }>
    x509: X509Module
  }>
  let issuer1: TenantType
  let issuer2: TenantType

  let holder: AgentType<{
    openId4VcHolder: OpenId4VcHolderModule
    tenants: TenantsModule<{ openId4VcHolder: OpenId4VcHolderModule }>
  }>
  let holder1: TenantType

  let verifier: AgentType<{
    openId4VcVerifier: OpenId4VcVerifierModule
    tenants: TenantsModule<{ openId4VcVerifier: OpenId4VcVerifierModule }>
  }>
  let verifier1: TenantType
  let verifier2: TenantType

  beforeEach(async () => {
    expressApp = express()

    issuer = (await createAgentFromModules(
      'issuer',
      {
        x509: new X509Module(),
        openId4VcIssuer: new OpenId4VcIssuerModule({
          baseUrl: issuanceBaseUrl,
          credentialRequestToCredentialMapper: async ({
            agentContext,
            credentialRequest,
            holderBindings,
            credentialConfigurationIds,
          }) => {
            // We sign the request with the first did:key did we have
            const didsApi = agentContext.dependencyManager.resolve(DidsApi)
            const [firstDidKeyDid] = await didsApi.getCreatedDids({ method: 'key' })
            const didDocument = await didsApi.resolveDidDocument(firstDidKeyDid.did)
            const verificationMethod = didDocument.verificationMethod?.[0]
            if (!verificationMethod) {
              throw new Error('No verification method found')
            }
            const credentialConfigurationId = credentialConfigurationIds[0]

            if (credentialRequest.format === 'vc+sd-jwt') {
              return {
                credentialConfigurationId,
                format: credentialRequest.format,
                credentials: holderBindings.map((holderBinding) => ({
                  payload: { vct: credentialRequest.vct, university: 'innsbruck', degree: 'bachelor' },
                  holder: holderBinding,
                  issuer: {
                    method: 'did',
                    didUrl: verificationMethod.id,
                  },
                  disclosureFrame: { _sd: ['university', 'degree'] },
                })),
              }
            } else if (credentialRequest.format === 'mso_mdoc') {
              const trustedCertificates = agentContext.dependencyManager.resolve(X509ModuleConfig).trustedCertificates
              if (trustedCertificates?.length !== 1) {
                throw new Error('Expected exactly one trusted certificate. Received 0.')
              }

              return {
                credentialConfigurationId,
                format: ClaimFormat.MsoMdoc,
                credentials: holderBindings.map((holderBinding) => ({
                  docType: universityDegreeCredentialConfigurationSupportedMdoc.doctype,
                  issuerCertificate: trustedCertificates[0],
                  holderKey: holderBinding.key,
                  namespaces: {
                    'Leopold-Franzens-University': {
                      degree: 'bachelor',
                    },
                  },
                })),
              } satisfies OpenId4VciSignMdocCredentials
            } else {
              throw new Error('Invalid request')
            }
          },
        }),
        askar: new AskarModule(askarModuleConfig),
        tenants: new TenantsModule(),
      },
      '96213c3d7fc8d4d6754c7a0fd969598g'
    )) as unknown as typeof issuer
    issuer1 = await createTenantForAgent(issuer.agent, 'iTenant1')
    issuer2 = await createTenantForAgent(issuer.agent, 'iTenant2')

    holder = (await createAgentFromModules(
      'holder',
      {
        openId4VcHolder: new OpenId4VcHolderModule(),
        askar: new AskarModule(askarModuleConfig),
        tenants: new TenantsModule(),
        x509: new X509Module(),
      },
      '96213c3d7fc8d4d6754c7a0fd969598e'
    )) as unknown as typeof holder
    holder1 = await createTenantForAgent(holder.agent, 'hTenant1')

    verifier = (await createAgentFromModules(
      'verifier',
      {
        openId4VcVerifier: new OpenId4VcVerifierModule({
          baseUrl: verificationBaseUrl,
          federation: {},
        }),
        askar: new AskarModule(askarModuleConfig),
        tenants: new TenantsModule(),
      },
      '96213c3d7fc8d4d6754c7a0fd969598f'
    )) as unknown as typeof verifier
    verifier1 = await createTenantForAgent(verifier.agent, 'vTenant1')
    verifier2 = await createTenantForAgent(verifier.agent, 'vTenant2')

    // We let AFJ create the router, so we have a fresh one each time
    expressApp.use('/oid4vci', issuer.agent.modules.openId4VcIssuer.config.router)
    expressApp.use('/oid4vp', verifier.agent.modules.openId4VcVerifier.config.router)

    expressServer = expressApp.listen(serverPort)
  })

  afterEach(async () => {
    expressServer?.close()

    await issuer.agent.shutdown()
    await issuer.agent.wallet.delete()

    await holder.agent.shutdown()
    await holder.agent.wallet.delete()

    await verifier.agent.shutdown()
    await verifier.agent.wallet.delete()
  })

  const credentialBindingResolver: OpenId4VciCredentialBindingResolver = ({ supportsJwk, supportedDidMethods }) => {
    // prefer did:key
    if (supportedDidMethods?.includes('did:key')) {
      return {
        method: 'did',
        didUrl: holder1.verificationMethod.id,
      }
    }

    // otherwise fall back to JWK
    if (supportsJwk) {
      return {
        method: 'jwk',
        jwk: getJwkFromKey(getKeyFromVerificationMethod(holder1.verificationMethod)),
      }
    }

    // otherwise throw an error
    throw new CredoError('Issuer does not support did:key or JWK for credential binding')
  }

  it('e2e flow with tenants, issuer endpoints requesting a sd-jwt-vc', async () => {
    const issuerTenant1 = await issuer.agent.modules.tenants.getTenantAgent({ tenantId: issuer1.tenantId })
    const issuerTenant2 = await issuer.agent.modules.tenants.getTenantAgent({ tenantId: issuer2.tenantId })

    const openIdIssuerTenant1 = await issuerTenant1.modules.openId4VcIssuer.createIssuer({
      dpopSigningAlgValuesSupported: [JwaSignatureAlgorithm.EdDSA],
      credentialConfigurationsSupported: {
        universityDegree: universityDegreeCredentialConfigurationSupported,
      },
    })
    const issuer1Record = await issuerTenant1.modules.openId4VcIssuer.getIssuerByIssuerId(openIdIssuerTenant1.issuerId)
    expect(issuer1Record.dpopSigningAlgValuesSupported).toEqual(['EdDSA'])
    expect(issuer1Record.credentialConfigurationsSupported).toEqual({
      universityDegree: {
        format: 'vc+sd-jwt',
        cryptographic_binding_methods_supported: ['did:key', 'jwk'],
        proof_types_supported: {
          jwt: {
            proof_signing_alg_values_supported: ['EdDSA', 'ES256'],
          },
        },
        vct: universityDegreeCredentialConfigurationSupported.vct,
        scope: universityDegreeCredentialConfigurationSupported.scope,
      },
    })
    const openIdIssuerTenant2 = await issuerTenant2.modules.openId4VcIssuer.createIssuer({
      dpopSigningAlgValuesSupported: [JwaSignatureAlgorithm.EdDSA],
      credentialConfigurationsSupported: {
        [universityDegreeCredentialSdJwt2.id]: universityDegreeCredentialSdJwt2,
      },
    })

    const { issuanceSession: issuanceSession1, credentialOffer: credentialOffer1 } =
      await issuerTenant1.modules.openId4VcIssuer.createCredentialOffer({
        issuerId: openIdIssuerTenant1.issuerId,
        offeredCredentials: ['universityDegree'],
        preAuthorizedCodeFlowConfig: {
          txCode: {
            input_mode: 'numeric',
            length: 4,
          },
        },
        version: 'v1.draft13',
      })

    const { issuanceSession: issuanceSession2, credentialOffer: credentialOffer2 } =
      await issuerTenant2.modules.openId4VcIssuer.createCredentialOffer({
        issuerId: openIdIssuerTenant2.issuerId,
        offeredCredentials: [universityDegreeCredentialSdJwt2.id],
        preAuthorizedCodeFlowConfig: {
          txCode: {},
        },
        version: 'v1.draft11-13',
      })

    await issuerTenant2.endSession()

    await waitForCredentialIssuanceSessionRecordSubject(issuer.replaySubject, {
      state: OpenId4VcIssuanceSessionState.OfferCreated,
      issuanceSessionId: issuanceSession1.id,
      contextCorrelationId: issuer1.tenantId,
    })
    await waitForCredentialIssuanceSessionRecordSubject(issuer.replaySubject, {
      state: OpenId4VcIssuanceSessionState.OfferCreated,
      issuanceSessionId: issuanceSession2.id,
      contextCorrelationId: issuer2.tenantId,
    })

    const holderTenant1 = await holder.agent.modules.tenants.getTenantAgent({ tenantId: holder1.tenantId })

    const resolvedCredentialOffer1 = await holderTenant1.modules.openId4VcHolder.resolveCredentialOffer(
      credentialOffer1
    )

    expect(resolvedCredentialOffer1.metadata.credentialIssuer?.dpop_signing_alg_values_supported).toEqual(['EdDSA'])
    expect(resolvedCredentialOffer1.offeredCredentialConfigurations).toEqual({
      universityDegree: {
        format: 'vc+sd-jwt',
        cryptographic_binding_methods_supported: ['did:key', 'jwk'],
        proof_types_supported: {
          jwt: {
            proof_signing_alg_values_supported: ['EdDSA', 'ES256'],
          },
        },
        vct: universityDegreeCredentialConfigurationSupported.vct,
        scope: universityDegreeCredentialConfigurationSupported.scope,
      },
    })

    expect(resolvedCredentialOffer1.credentialOfferPayload.credential_issuer).toEqual(
      `${issuanceBaseUrl}/${openIdIssuerTenant1.issuerId}`
    )
    expect(resolvedCredentialOffer1.metadata.credentialIssuer?.token_endpoint).toEqual(
      `${issuanceBaseUrl}/${openIdIssuerTenant1.issuerId}/token`
    )
    expect(resolvedCredentialOffer1.metadata.credentialIssuer?.credential_endpoint).toEqual(
      `${issuanceBaseUrl}/${openIdIssuerTenant1.issuerId}/credential`
    )

    // Bind to JWK
    const tokenResponseTenant1 = await holderTenant1.modules.openId4VcHolder.requestToken({
      resolvedCredentialOffer: resolvedCredentialOffer1,
      txCode: issuanceSession1.userPin,
    })

    const expectedSubject = (await issuerTenant1.modules.openId4VcIssuer.getIssuanceSessionById(issuanceSession1.id))
      .authorization?.subject
    await issuerTenant1.endSession()

    expect(tokenResponseTenant1.accessToken).toBeDefined()
    expect(tokenResponseTenant1.dpop?.jwk).toBeInstanceOf(Jwk)
    const { payload } = Jwt.fromSerializedJwt(tokenResponseTenant1.accessToken)
    expect(payload.toJson()).toEqual({
      cnf: {
        jkt: await calculateJwkThumbprint({
          hashAlgorithm: HashAlgorithm.Sha256,
          hashCallback: getOid4vciCallbacks(holderTenant1.context).hash,
          jwk: tokenResponseTenant1.dpop?.jwk.toJson() as JwkJson,
        }),
      },
      'pre-authorized_code': expect.any(String),
      aud: `http://localhost:1234/oid4vci/${openIdIssuerTenant1.issuerId}`,
      exp: expect.any(Number),
      iat: expect.any(Number),
      iss: `http://localhost:1234/oid4vci/${openIdIssuerTenant1.issuerId}`,
      jti: expect.any(String),
      nbf: undefined,
      sub: expectedSubject,
    })

    const credentialsTenant1 = await holderTenant1.modules.openId4VcHolder.requestCredentials({
      resolvedCredentialOffer: resolvedCredentialOffer1,
      ...tokenResponseTenant1,
      credentialBindingResolver,
    })

    // Wait for all events
    await waitForCredentialIssuanceSessionRecordSubject(issuer.replaySubject, {
      state: OpenId4VcIssuanceSessionState.AccessTokenRequested,
      issuanceSessionId: issuanceSession1.id,
      contextCorrelationId: issuer1.tenantId,
    })
    await waitForCredentialIssuanceSessionRecordSubject(issuer.replaySubject, {
      state: OpenId4VcIssuanceSessionState.AccessTokenCreated,
      issuanceSessionId: issuanceSession1.id,
      contextCorrelationId: issuer1.tenantId,
    })
    await waitForCredentialIssuanceSessionRecordSubject(issuer.replaySubject, {
      state: OpenId4VcIssuanceSessionState.CredentialRequestReceived,
      issuanceSessionId: issuanceSession1.id,
      contextCorrelationId: issuer1.tenantId,
    })
    await waitForCredentialIssuanceSessionRecordSubject(issuer.replaySubject, {
      state: OpenId4VcIssuanceSessionState.Completed,
      issuanceSessionId: issuanceSession1.id,
      contextCorrelationId: issuer1.tenantId,
    })

    expect(credentialsTenant1.credentials).toHaveLength(1)
    const compactSdJwtVcTenant1 = (credentialsTenant1.credentials[0].credentials[0] as SdJwtVc).compact
    const sdJwtVcTenant1 = holderTenant1.sdJwtVc.fromCompact(compactSdJwtVcTenant1)
    expect(sdJwtVcTenant1.payload.vct).toEqual('UniversityDegreeCredential')

    const resolvedCredentialOffer2 = await holderTenant1.modules.openId4VcHolder.resolveCredentialOffer(
      credentialOffer2
    )

    await waitForCredentialIssuanceSessionRecordSubject(issuer.replaySubject, {
      state: OpenId4VcIssuanceSessionState.OfferUriRetrieved,
      issuanceSessionId: issuanceSession2.id,
      contextCorrelationId: issuer2.tenantId,
    })

    expect(resolvedCredentialOffer2.credentialOfferPayload.credential_issuer).toEqual(
      `${issuanceBaseUrl}/${openIdIssuerTenant2.issuerId}`
    )
    expect(resolvedCredentialOffer2.metadata.credentialIssuer?.token_endpoint).toEqual(
      `${issuanceBaseUrl}/${openIdIssuerTenant2.issuerId}/token`
    )
    expect(resolvedCredentialOffer2.metadata.credentialIssuer?.credential_endpoint).toEqual(
      `${issuanceBaseUrl}/${openIdIssuerTenant2.issuerId}/credential`
    )

    // Bind to did
    const tokenResponseTenant2 = await holderTenant1.modules.openId4VcHolder.requestToken({
      resolvedCredentialOffer: resolvedCredentialOffer2,
      txCode: issuanceSession2.userPin,
    })

    const credentialsTenant2 = await holderTenant1.modules.openId4VcHolder.requestCredentials({
      resolvedCredentialOffer: resolvedCredentialOffer2,
      ...tokenResponseTenant2,
      credentialBindingResolver,
    })

    // Wait for all events
    await waitForCredentialIssuanceSessionRecordSubject(issuer.replaySubject, {
      state: OpenId4VcIssuanceSessionState.AccessTokenRequested,
      issuanceSessionId: issuanceSession2.id,
      contextCorrelationId: issuer2.tenantId,
    })
    await waitForCredentialIssuanceSessionRecordSubject(issuer.replaySubject, {
      state: OpenId4VcIssuanceSessionState.AccessTokenCreated,
      issuanceSessionId: issuanceSession2.id,
      contextCorrelationId: issuer2.tenantId,
    })
    await waitForCredentialIssuanceSessionRecordSubject(issuer.replaySubject, {
      state: OpenId4VcIssuanceSessionState.CredentialRequestReceived,
      issuanceSessionId: issuanceSession2.id,
      contextCorrelationId: issuer2.tenantId,
    })
    await waitForCredentialIssuanceSessionRecordSubject(issuer.replaySubject, {
      state: OpenId4VcIssuanceSessionState.Completed,
      issuanceSessionId: issuanceSession2.id,
      contextCorrelationId: issuer2.tenantId,
    })

    expect(credentialsTenant2.credentials).toHaveLength(1)
    const compactSdJwtVcTenant2 = (credentialsTenant2.credentials[0].credentials[0] as SdJwtVc).compact
    const sdJwtVcTenant2 = holderTenant1.sdJwtVc.fromCompact(compactSdJwtVcTenant2)
    expect(sdJwtVcTenant2.payload.vct).toEqual('UniversityDegreeCredential2')

    await holderTenant1.endSession()
  })

  it('e2e flow with tenants, issuer endpoints requesting a sd-jwt-vc using authorization code flow', async () => {
    const issuerTenant = await issuer.agent.modules.tenants.getTenantAgent({ tenantId: issuer1.tenantId })
    const holderTenant = await holder.agent.modules.tenants.getTenantAgent({ tenantId: holder1.tenantId })

    const authorizationServerKey = await issuer.agent.wallet.createKey({
      keyType: KeyType.P256,
    })
    const authorizationServerJwk = getJwkFromKey(authorizationServerKey).toJson()
    const authorizationServer = new Oauth2AuthorizationServer({
      callbacks: {
        clientAuthentication: clientAuthenticationNone(),
        generateRandom: issuer.agent.context.wallet.getRandomValues,
        hash: Hasher.hash,
        fetch: issuer.agent.config.agentDependencies.fetch,
        verifyJwt: () => {
          throw new Error('not implemented')
        },
        signJwt: async (signer, { header, payload }) => {
          const jwsService = issuer.agent.dependencyManager.resolve(JwsService)
          return jwsService.createJwsCompact(issuer.agent.context, {
            key: authorizationServerKey,
            payload: JwtPayload.fromJson(payload),
            protectedHeaderOptions: {
              ...header,
              jwk: undefined,
              alg: 'ES256',
              kid: 'first',
            },
          })
        },
      },
    })
    const app = express()
    app.get('/.well-known/oauth-authorization-server', (req, res) =>
      res.json({
        jwks_uri: 'http://localhost:4747/jwks.json',
        issuer: 'http://localhost:4747',
        token_endpoint: 'http://localhost:4747/token',
        authorization_endpoint: 'http://localhost:4747/authorize',
      } satisfies AuthorizationServerMetadata)
    )
    app.get('/jwks.json', (req, res) =>
      res.setHeader('Content-Type', 'application/jwk-set+json').send(
        JSON.stringify({
          keys: [{ ...authorizationServerJwk, kid: 'first' }],
        })
      )
    )
    app.post('/token', async (req, res) =>
      res.json(
        await authorizationServer.createAccessTokenResponse({
          authorizationServer: 'http://localhost:4747',
          audience: 'http://localhost:1234/oid4vci/8bc91672-6a32-466c-96ec-6efca8760068',
          expiresInSeconds: 5000,
          subject: 'something',
          scope: 'UniversityDegreeCredential',
          additionalAccessTokenPayload: {
            issuer_state: 'dbf99eea-0131-48b0-9022-17f7ebe25ea7',
          },
          signer: {
            method: 'jwk',
            publicJwk: authorizationServerJwk,
            alg: 'ES256',
          },
        })
      )
    )
    const server = app.listen(4747)

    const openIdIssuerTenant = await issuerTenant.modules.openId4VcIssuer.createIssuer({
      issuerId: '8bc91672-6a32-466c-96ec-6efca8760068',
      credentialConfigurationsSupported: {
        universityDegree: universityDegreeCredentialConfigurationSupported,
      },
      authorizationServerConfigs: [
        {
          issuer: 'http://localhost:4747',
        },
      ],
    })

    const { issuanceSession, credentialOffer } = await issuerTenant.modules.openId4VcIssuer.createCredentialOffer({
      issuerId: openIdIssuerTenant.issuerId,
      offeredCredentials: ['universityDegree'],
      authorizationCodeFlowConfig: {
        authorizationServerUrl: 'http://localhost:4747',
        issuerState: 'dbf99eea-0131-48b0-9022-17f7ebe25ea7',
      },
      version: 'v1.draft13',
    })

    await issuerTenant.endSession()

    const resolvedCredentialOffer = await holderTenant.modules.openId4VcHolder.resolveCredentialOffer(credentialOffer)
    const resolvedAuthorization = await holderTenant.modules.openId4VcHolder.resolveIssuanceAuthorizationRequest(
      resolvedCredentialOffer,
      {
        clientId: 'foo',
        redirectUri: 'http://localhost:1234/redirect',
        scope: ['UniversityDegreeCredential'],
      }
    )
    if (resolvedAuthorization.authorizationFlow === AuthorizationFlow.PresentationDuringIssuance) {
      throw new Error('Not supported')
    }

    // Bind to JWK
    const tokenResponseTenant = await holderTenant.modules.openId4VcHolder.requestToken({
      resolvedCredentialOffer,
      // Mock the authorization code flow part,
      code: 'some-authorization-code',
      clientId: 'foo',
      redirectUri: 'http://localhost:1234/redirect',
      codeVerifier: resolvedAuthorization.codeVerifier,
    })
    const credentialResponse = await holderTenant.modules.openId4VcHolder.requestCredentials({
      resolvedCredentialOffer,
      ...tokenResponseTenant,
      credentialBindingResolver,
    })

    await waitForCredentialIssuanceSessionRecordSubject(issuer.replaySubject, {
      state: OpenId4VcIssuanceSessionState.Completed,
      issuanceSessionId: issuanceSession.id,
      contextCorrelationId: issuer1.tenantId,
    })

    expect(credentialResponse.credentials).toHaveLength(1)
    const compactSdJwtVcTenant1 = (credentialResponse.credentials[0].credentials[0] as SdJwtVc).compact
    const sdJwtVcTenant1 = holderTenant.sdJwtVc.fromCompact(compactSdJwtVcTenant1)
    expect(sdJwtVcTenant1.payload.vct).toEqual('UniversityDegreeCredential')

    await holderTenant.endSession()
    server.close()
  })

  it('e2e flow with tenants only requesting an id-token', async () => {
    const holderTenant = await holder.agent.modules.tenants.getTenantAgent({ tenantId: holder1.tenantId })
    const verifierTenant1 = await verifier.agent.modules.tenants.getTenantAgent({ tenantId: verifier1.tenantId })

    const openIdVerifierTenant1 = await verifierTenant1.modules.openId4VcVerifier.createVerifier()

    const { authorizationRequest: authorizationRequestUri1, verificationSession: verificationSession } =
      await verifierTenant1.modules.openId4VcVerifier.createAuthorizationRequest({
        verifierId: openIdVerifierTenant1.verifierId,
        requestSigner: {
          method: 'did',
          didUrl: verifier1.verificationMethod.id,
        },
      })

    expect(authorizationRequestUri1).toEqual(
      `openid://?client_id=${encodeURIComponent(verifier1.did)}&request_uri=${encodeURIComponent(
        verificationSession.authorizationRequestUri
      )}`
    )

    await verifierTenant1.endSession()

    const resolvedAuthorizationRequest = await holderTenant.modules.openId4VcHolder.resolveSiopAuthorizationRequest(
      authorizationRequestUri1
    )

    expect(resolvedAuthorizationRequest.presentationExchange).toBeUndefined()

    const { submittedResponse: submittedResponse1, serverResponse: serverResponse1 } =
      await holderTenant.modules.openId4VcHolder.acceptSiopAuthorizationRequest({
        authorizationRequest: resolvedAuthorizationRequest.authorizationRequest,
        openIdTokenIssuer: {
          method: 'did',
          didUrl: holder1.verificationMethod.id,
        },
      })

    expect(submittedResponse1).toEqual({
      id_token: expect.any(String),
      state: expect.any(String),
    })
    expect(serverResponse1).toMatchObject({
      status: 200,
    })

    // The RP MUST validate that the aud (audience) Claim contains the value of the client_id
    // that the RP sent in the Authorization Request as an audience.
    // When the request has been signed, the value might be an HTTPS URL, or a Decentralized Identifier.
    const verifierTenant1_2 = await verifier.agent.modules.tenants.getTenantAgent({ tenantId: verifier1.tenantId })
    await waitForVerificationSessionRecordSubject(verifier.replaySubject, {
      contextCorrelationId: verifierTenant1_2.context.contextCorrelationId,
      state: OpenId4VcVerificationSessionState.ResponseVerified,
      verificationSessionId: verificationSession.id,
    })

    const { idToken, presentationExchange } =
      await verifierTenant1_2.modules.openId4VcVerifier.getVerifiedAuthorizationResponse(verificationSession.id)

    const requestObjectPayload = JsonEncoder.fromBase64(
      verificationSession.authorizationRequestJwt?.split('.')[1] as string
    )
    expect(idToken?.payload).toMatchObject({
      state: requestObjectPayload.state,
      nonce: requestObjectPayload.nonce,
    })

    expect(presentationExchange).toBeUndefined()
  })

  it('e2e flow with tenants, verifier endpoints verifying a jwt-vc', async () => {
    const holderTenant = await holder.agent.modules.tenants.getTenantAgent({ tenantId: holder1.tenantId })
    const verifierTenant1 = await verifier.agent.modules.tenants.getTenantAgent({ tenantId: verifier1.tenantId })
    const verifierTenant2 = await verifier.agent.modules.tenants.getTenantAgent({ tenantId: verifier2.tenantId })

    const openIdVerifierTenant1 = await verifierTenant1.modules.openId4VcVerifier.createVerifier()
    const openIdVerifierTenant2 = await verifierTenant2.modules.openId4VcVerifier.createVerifier()

    const signedCredential1 = await issuer.agent.w3cCredentials.signCredential({
      format: ClaimFormat.JwtVc,
      credential: new W3cCredential({
        type: ['VerifiableCredential', 'OpenBadgeCredential'],
        issuer: new W3cIssuer({ id: issuer.did }),
        credentialSubject: new W3cCredentialSubject({ id: holder1.did }),
        issuanceDate: w3cDate(Date.now()),
      }),
      alg: JwaSignatureAlgorithm.EdDSA,
      verificationMethod: issuer.verificationMethod.id,
    })

    const signedCredential2 = await issuer.agent.w3cCredentials.signCredential({
      format: ClaimFormat.JwtVc,
      credential: new W3cCredential({
        type: ['VerifiableCredential', 'UniversityDegreeCredential'],
        issuer: new W3cIssuer({ id: issuer.did }),
        credentialSubject: new W3cCredentialSubject({ id: holder1.did }),
        issuanceDate: w3cDate(Date.now()),
      }),
      alg: JwaSignatureAlgorithm.EdDSA,
      verificationMethod: issuer.verificationMethod.id,
    })

    await holderTenant.w3cCredentials.storeCredential({ credential: signedCredential1 })
    await holderTenant.w3cCredentials.storeCredential({ credential: signedCredential2 })

    const { authorizationRequest: authorizationRequestUri1, verificationSession: verificationSession1 } =
      await verifierTenant1.modules.openId4VcVerifier.createAuthorizationRequest({
        verifierId: openIdVerifierTenant1.verifierId,
        requestSigner: {
          method: 'did',
          didUrl: verifier1.verificationMethod.id,
        },
        presentationExchange: {
          definition: openBadgePresentationDefinition,
        },
      })

    expect(authorizationRequestUri1).toEqual(
      `openid4vp://?client_id=${encodeURIComponent(verifier1.did)}&request_uri=${encodeURIComponent(
        verificationSession1.authorizationRequestUri
      )}`
    )

    const { authorizationRequest: authorizationRequestUri2, verificationSession: verificationSession2 } =
      await verifierTenant2.modules.openId4VcVerifier.createAuthorizationRequest({
        requestSigner: {
          method: 'did',
          didUrl: verifier2.verificationMethod.id,
        },
        presentationExchange: {
          definition: universityDegreePresentationDefinition,
        },
        verifierId: openIdVerifierTenant2.verifierId,
      })

    expect(authorizationRequestUri2).toEqual(
      `openid4vp://?client_id=${encodeURIComponent(verifier2.did)}&request_uri=${encodeURIComponent(
        verificationSession2.authorizationRequestUri
      )}`
    )

    await verifierTenant1.endSession()
    await verifierTenant2.endSession()

    const resolvedProofRequest1 = await holderTenant.modules.openId4VcHolder.resolveSiopAuthorizationRequest(
      authorizationRequestUri1
    )

    expect(resolvedProofRequest1.presentationExchange?.credentialsForRequest).toMatchObject({
      areRequirementsSatisfied: true,
      requirements: [
        {
          submissionEntry: [
            {
              verifiableCredentials: [
                {
                  type: ClaimFormat.JwtVc,
                  credentialRecord: {
                    credential: {
                      type: ['VerifiableCredential', 'OpenBadgeCredential'],
                    },
                  },
                },
              ],
            },
          ],
        },
      ],
    })

    const resolvedProofRequest2 = await holderTenant.modules.openId4VcHolder.resolveSiopAuthorizationRequest(
      authorizationRequestUri2
    )

    expect(resolvedProofRequest2.presentationExchange?.credentialsForRequest).toMatchObject({
      areRequirementsSatisfied: true,
      requirements: [
        {
          submissionEntry: [
            {
              verifiableCredentials: [
                {
                  type: ClaimFormat.JwtVc,
                  credentialRecord: {
                    credential: {
                      type: ['VerifiableCredential', 'UniversityDegreeCredential'],
                    },
                  },
                },
              ],
            },
          ],
        },
      ],
    })

    if (!resolvedProofRequest1.presentationExchange || !resolvedProofRequest2.presentationExchange) {
      throw new Error('Presentation exchange not defined')
    }

    const presentationExchangeService = holderTenant.dependencyManager.resolve(DifPresentationExchangeService)
    const selectedCredentials = presentationExchangeService.selectCredentialsForRequest(
      resolvedProofRequest1.presentationExchange.credentialsForRequest
    )

    const { submittedResponse: submittedResponse1, serverResponse: serverResponse1 } =
      await holderTenant.modules.openId4VcHolder.acceptSiopAuthorizationRequest({
        authorizationRequest: resolvedProofRequest1.authorizationRequest,
        presentationExchange: {
          credentials: selectedCredentials,
        },
      })

    expect(submittedResponse1).toEqual({
      presentation_submission: {
        definition_id: 'OpenBadgeCredential',
        descriptor_map: [
          {
            format: 'jwt_vp',
            id: 'OpenBadgeCredentialDescriptor',
            path: '$',
            path_nested: {
              format: 'jwt_vc',
              id: 'OpenBadgeCredentialDescriptor',
              path: '$.vp.verifiableCredential[0]',
            },
          },
        ],
        id: expect.any(String),
      },
      state: expect.any(String),
      vp_token: expect.any(String),
    })
    expect(serverResponse1).toMatchObject({
      status: 200,
    })

    // The RP MUST validate that the aud (audience) Claim contains the value of the client_id
    // that the RP sent in the Authorization Request as an audience.
    // When the request has been signed, the value might be an HTTPS URL, or a Decentralized Identifier.
    const verifierTenant1_2 = await verifier.agent.modules.tenants.getTenantAgent({ tenantId: verifier1.tenantId })
    await waitForVerificationSessionRecordSubject(verifier.replaySubject, {
      contextCorrelationId: verifierTenant1_2.context.contextCorrelationId,
      state: OpenId4VcVerificationSessionState.ResponseVerified,
      verificationSessionId: verificationSession1.id,
    })

    const { idToken: idToken1, presentationExchange: presentationExchange1 } =
      await verifierTenant1_2.modules.openId4VcVerifier.getVerifiedAuthorizationResponse(verificationSession1.id)

    expect(idToken1).toBeUndefined()
    expect(presentationExchange1).toMatchObject({
      definition: openBadgePresentationDefinition,
      submission: {
        definition_id: 'OpenBadgeCredential',
      },
      presentations: [
        {
          verifiableCredential: [
            {
              type: ['VerifiableCredential', 'OpenBadgeCredential'],
            },
          ],
        },
      ],
    })

    const selectedCredentials2 = presentationExchangeService.selectCredentialsForRequest(
      resolvedProofRequest2.presentationExchange.credentialsForRequest
    )

    const { serverResponse: serverResponse2 } =
      await holderTenant.modules.openId4VcHolder.acceptSiopAuthorizationRequest({
        authorizationRequest: resolvedProofRequest2.authorizationRequest,
        presentationExchange: {
          credentials: selectedCredentials2,
        },
      })
    expect(serverResponse2).toMatchObject({
      status: 200,
    })

    // The RP MUST validate that the aud (audience) Claim contains the value of the client_id
    // that the RP sent in the Authorization Request as an audience.
    // When the request has been signed, the value might be an HTTPS URL, or a Decentralized Identifier.
    const verifierTenant2_2 = await verifier.agent.modules.tenants.getTenantAgent({ tenantId: verifier2.tenantId })
    await waitForVerificationSessionRecordSubject(verifier.replaySubject, {
      contextCorrelationId: verifierTenant2_2.context.contextCorrelationId,
      state: OpenId4VcVerificationSessionState.ResponseVerified,
      verificationSessionId: verificationSession2.id,
    })
    const { idToken: idToken2, presentationExchange: presentationExchange2 } =
      await verifierTenant2_2.modules.openId4VcVerifier.getVerifiedAuthorizationResponse(verificationSession2.id)
    expect(idToken2).toBeUndefined()

    expect(presentationExchange2).toMatchObject({
      definition: universityDegreePresentationDefinition,
      submission: {
        definition_id: 'UniversityDegreeCredential',
      },
      presentations: [
        {
          verifiableCredential: [
            {
              type: ['VerifiableCredential', 'UniversityDegreeCredential'],
            },
          ],
        },
      ],
    })
  })

  it('e2e flow (jarm) with verifier endpoints verifying a sd-jwt-vc with selective disclosure', async () => {
    const openIdVerifier = await verifier.agent.modules.openId4VcVerifier.createVerifier()

    const signedSdJwtVc = await issuer.agent.sdJwtVc.sign({
      holder: { method: 'did', didUrl: holder.kid },
      issuer: {
        method: 'did',
        didUrl: issuer.kid,
      },
      payload: {
        vct: 'OpenBadgeCredential',
        university: 'innsbruck',
        degree: 'bachelor',
        name: 'John Doe',
      },
      disclosureFrame: {
        _sd: ['university', 'name'],
      },
    })

    const certificate = await verifier.agent.x509.createSelfSignedCertificate({
      key: await verifier.agent.wallet.createKey({ keyType: KeyType.Ed25519 }),
      extensions: [[{ type: 'dns', value: `localhost:${serverPort}` }]],
    })

    const rawCertificate = certificate.toString('base64')
    await holder.agent.sdJwtVc.store(signedSdJwtVc.compact)

    await holder.agent.x509.addTrustedCertificate(rawCertificate)
    await verifier.agent.x509.addTrustedCertificate(rawCertificate)

    const presentationDefinition = {
      id: 'OpenBadgeCredential',
      input_descriptors: [
        {
          id: 'OpenBadgeCredentialDescriptor',
          format: {
            'vc+sd-jwt': {
              'sd-jwt_alg_values': ['EdDSA'],
            },
          },
          constraints: {
            limit_disclosure: 'required',
            fields: [
              {
                path: ['$.vct'],
                filter: {
                  type: 'string',
                  const: 'OpenBadgeCredential',
                },
              },
              {
                path: ['$.university'],
              },
            ],
          },
        },
      ],
    } satisfies DifPresentationExchangeDefinitionV2

    const { authorizationRequest, verificationSession } =
      await verifier.agent.modules.openId4VcVerifier.createAuthorizationRequest({
        verifierId: openIdVerifier.verifierId,
        responseMode: 'direct_post.jwt',
        requestSigner: {
          method: 'x5c',
          x5c: [rawCertificate],
          issuer: 'https://example.com/hakuna/matadata',
        },
        presentationExchange: {
          definition: presentationDefinition,
        },
      })

    expect(authorizationRequest).toEqual(
      `openid4vp://?client_id=localhost%3A1234&request_uri=${encodeURIComponent(
        verificationSession.authorizationRequestUri
      )}`
    )

    const resolvedAuthorizationRequest = await holder.agent.modules.openId4VcHolder.resolveSiopAuthorizationRequest(
      authorizationRequest
    )
    expect(resolvedAuthorizationRequest.authorizationRequest.payload?.response_mode).toEqual('direct_post.jwt')

    expect(resolvedAuthorizationRequest.presentationExchange?.credentialsForRequest).toEqual({
      areRequirementsSatisfied: true,
      name: undefined,
      purpose: undefined,
      requirements: [
        {
          isRequirementSatisfied: true,
          needsCount: 1,
          rule: 'pick',
          submissionEntry: [
            {
              name: undefined,
              purpose: undefined,
              inputDescriptorId: 'OpenBadgeCredentialDescriptor',
              verifiableCredentials: [
                {
                  type: ClaimFormat.SdJwtVc,
                  credentialRecord: expect.objectContaining({
                    compactSdJwtVc: signedSdJwtVc.compact,
                  }),
                  // Name is NOT in here
                  disclosedPayload: {
                    cnf: {
                      kid: 'did:key:z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc#z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc',
                    },
                    degree: 'bachelor',
                    iat: expect.any(Number),
                    iss: 'did:key:z6MkrzQPBr4pyqC776KKtrz13SchM5ePPbssuPuQZb5t4uKQ',
                    university: 'innsbruck',
                    vct: 'OpenBadgeCredential',
                  },
                },
              ],
            },
          ],
        },
      ],
    })

    if (!resolvedAuthorizationRequest.presentationExchange) {
      throw new Error('Presentation exchange not defined')
    }

    const selectedCredentials = holder.agent.modules.openId4VcHolder.selectCredentialsForRequest(
      resolvedAuthorizationRequest.presentationExchange.credentialsForRequest
    )

    const { serverResponse, submittedResponse } =
      await holder.agent.modules.openId4VcHolder.acceptSiopAuthorizationRequest({
        authorizationRequest: resolvedAuthorizationRequest.authorizationRequest,
        presentationExchange: {
          credentials: selectedCredentials,
        },
      })

    // path_nested should not be used for sd-jwt
    expect(submittedResponse.presentation_submission?.descriptor_map[0].path_nested).toBeUndefined()
    expect(submittedResponse).toEqual({
      presentation_submission: {
        definition_id: 'OpenBadgeCredential',
        descriptor_map: [
          {
            format: 'vc+sd-jwt',
            id: 'OpenBadgeCredentialDescriptor',
            path: '$',
          },
        ],
        id: expect.any(String),
      },
      state: expect.any(String),
      vp_token: expect.any(String),
    })
    expect(serverResponse).toMatchObject({
      status: 200,
    })

    // The RP MUST validate that the aud (audience) Claim contains the value of the client_id
    // that the RP sent in the Authorization Request as an audience.
    // When the request has been signed, the value might be an HTTPS URL, or a Decentralized Identifier.
    await waitForVerificationSessionRecordSubject(verifier.replaySubject, {
      contextCorrelationId: verifier.agent.context.contextCorrelationId,
      state: OpenId4VcVerificationSessionState.ResponseVerified,
      verificationSessionId: verificationSession.id,
    })
    const { idToken, presentationExchange } =
      await verifier.agent.modules.openId4VcVerifier.getVerifiedAuthorizationResponse(verificationSession.id)

    expect(idToken).toBeUndefined()

    const presentation = presentationExchange?.presentations[0] as SdJwtVc

    // name SHOULD NOT be disclosed
    expect(presentation.prettyClaims).not.toHaveProperty('name')

    // university and name SHOULD NOT be in the signed payload
    expect(presentation.payload).not.toHaveProperty('university')
    expect(presentation.payload).not.toHaveProperty('name')

    expect(presentationExchange).toEqual({
      definition: presentationDefinition,
      submission: {
        definition_id: 'OpenBadgeCredential',
        descriptor_map: [
          {
            format: 'vc+sd-jwt',
            id: 'OpenBadgeCredentialDescriptor',
            path: '$',
          },
        ],
        id: expect.any(String),
      },
      presentations: [
        {
          compact: expect.any(String),
          header: {
            alg: 'EdDSA',
            kid: '#z6MkrzQPBr4pyqC776KKtrz13SchM5ePPbssuPuQZb5t4uKQ',
            typ: 'vc+sd-jwt',
          },
          payload: {
            _sd: [expect.any(String), expect.any(String)],
            _sd_alg: 'sha-256',
            cnf: {
              kid: 'did:key:z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc#z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc',
            },
            iat: expect.any(Number),
            iss: 'did:key:z6MkrzQPBr4pyqC776KKtrz13SchM5ePPbssuPuQZb5t4uKQ',
            vct: 'OpenBadgeCredential',
            degree: 'bachelor',
          },
          // university SHOULD be disclosed
          prettyClaims: {
            cnf: {
              kid: 'did:key:z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc#z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc',
            },
            iat: expect.any(Number),
            iss: 'did:key:z6MkrzQPBr4pyqC776KKtrz13SchM5ePPbssuPuQZb5t4uKQ',
            vct: 'OpenBadgeCredential',
            degree: 'bachelor',
            university: 'innsbruck',
          },
        },
      ],
      descriptors: expect.any(Array),
    })
  })

  it('e2e flow with verifier endpoints verifying a sd-jwt-vc with selective disclosure', async () => {
    const openIdVerifier = await verifier.agent.modules.openId4VcVerifier.createVerifier()

    const signedSdJwtVc = await issuer.agent.sdJwtVc.sign({
      holder: { method: 'did', didUrl: holder.kid },
      issuer: {
        method: 'did',
        didUrl: issuer.kid,
      },
      payload: {
        vct: 'OpenBadgeCredential',
        university: 'innsbruck',
        degree: 'bachelor',
        name: 'John Doe',
      },
      disclosureFrame: {
        _sd: ['university', 'name'],
      },
    })

    const certificate = await verifier.agent.x509.createSelfSignedCertificate({
      key: await verifier.agent.wallet.createKey({ keyType: KeyType.Ed25519 }),
      extensions: [[{ type: 'dns', value: `localhost:${serverPort}` }]],
    })

    const rawCertificate = certificate.toString('base64')
    await holder.agent.sdJwtVc.store(signedSdJwtVc.compact)

    await holder.agent.x509.addTrustedCertificate(rawCertificate)
    await verifier.agent.x509.addTrustedCertificate(rawCertificate)

    const presentationDefinition = {
      id: 'OpenBadgeCredential',
      input_descriptors: [
        {
          id: 'OpenBadgeCredentialDescriptor',
          format: {
            'vc+sd-jwt': {
              'sd-jwt_alg_values': ['EdDSA'],
            },
          },
          constraints: {
            limit_disclosure: 'required',
            fields: [
              {
                path: ['$.vct'],
                filter: {
                  type: 'string',
                  const: 'OpenBadgeCredential',
                },
              },
              {
                path: ['$.university'],
              },
            ],
          },
        },
      ],
    } satisfies DifPresentationExchangeDefinitionV2

    const { authorizationRequest, verificationSession } =
      await verifier.agent.modules.openId4VcVerifier.createAuthorizationRequest({
        verifierId: openIdVerifier.verifierId,
        requestSigner: {
          method: 'x5c',
          x5c: [rawCertificate],
          issuer: 'https://example.com/hakuna/matadata',
        },
        presentationExchange: {
          definition: presentationDefinition,
        },
      })

    expect(authorizationRequest).toEqual(
      `openid4vp://?client_id=localhost%3A1234&request_uri=${encodeURIComponent(
        verificationSession.authorizationRequestUri
      )}`
    )

    const resolvedAuthorizationRequest = await holder.agent.modules.openId4VcHolder.resolveSiopAuthorizationRequest(
      authorizationRequest
    )

    expect(resolvedAuthorizationRequest.presentationExchange?.credentialsForRequest).toEqual({
      areRequirementsSatisfied: true,
      name: undefined,
      purpose: undefined,
      requirements: [
        {
          isRequirementSatisfied: true,
          needsCount: 1,
          rule: 'pick',
          submissionEntry: [
            {
              name: undefined,
              purpose: undefined,
              inputDescriptorId: 'OpenBadgeCredentialDescriptor',
              verifiableCredentials: [
                {
                  type: ClaimFormat.SdJwtVc,
                  credentialRecord: expect.objectContaining({
                    compactSdJwtVc: signedSdJwtVc.compact,
                  }),
                  // Name is NOT in here
                  disclosedPayload: {
                    cnf: {
                      kid: 'did:key:z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc#z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc',
                    },
                    degree: 'bachelor',
                    iat: expect.any(Number),
                    iss: 'did:key:z6MkrzQPBr4pyqC776KKtrz13SchM5ePPbssuPuQZb5t4uKQ',
                    university: 'innsbruck',
                    vct: 'OpenBadgeCredential',
                  },
                },
              ],
            },
          ],
        },
      ],
    })

    if (!resolvedAuthorizationRequest.presentationExchange) {
      throw new Error('Presentation exchange not defined')
    }

    const selectedCredentials = holder.agent.modules.openId4VcHolder.selectCredentialsForRequest(
      resolvedAuthorizationRequest.presentationExchange.credentialsForRequest
    )

    const { serverResponse, submittedResponse } =
      await holder.agent.modules.openId4VcHolder.acceptSiopAuthorizationRequest({
        authorizationRequest: resolvedAuthorizationRequest.authorizationRequest,
        presentationExchange: {
          credentials: selectedCredentials,
        },
      })

    // path_nested should not be used for sd-jwt
    expect(submittedResponse.presentation_submission?.descriptor_map[0].path_nested).toBeUndefined()
    expect(submittedResponse).toEqual({
      presentation_submission: {
        definition_id: 'OpenBadgeCredential',
        descriptor_map: [
          {
            format: 'vc+sd-jwt',
            id: 'OpenBadgeCredentialDescriptor',
            path: '$',
          },
        ],
        id: expect.any(String),
      },
      state: expect.any(String),
      vp_token: expect.any(String),
    })
    expect(serverResponse).toMatchObject({
      status: 200,
    })

    // The RP MUST validate that the aud (audience) Claim contains the value of the client_id
    // that the RP sent in the Authorization Request as an audience.
    // When the request has been signed, the value might be an HTTPS URL, or a Decentralized Identifier.
    await waitForVerificationSessionRecordSubject(verifier.replaySubject, {
      contextCorrelationId: verifier.agent.context.contextCorrelationId,
      state: OpenId4VcVerificationSessionState.ResponseVerified,
      verificationSessionId: verificationSession.id,
    })
    const { idToken, presentationExchange } =
      await verifier.agent.modules.openId4VcVerifier.getVerifiedAuthorizationResponse(verificationSession.id)

    expect(idToken).toBeUndefined()

    const presentation = presentationExchange?.presentations[0] as SdJwtVc

    // name SHOULD NOT be disclosed
    expect(presentation.prettyClaims).not.toHaveProperty('name')

    // university and name SHOULD NOT be in the signed payload
    expect(presentation.payload).not.toHaveProperty('university')
    expect(presentation.payload).not.toHaveProperty('name')

    expect(presentationExchange).toEqual({
      definition: presentationDefinition,
      submission: {
        definition_id: 'OpenBadgeCredential',
        descriptor_map: [
          {
            format: 'vc+sd-jwt',
            id: 'OpenBadgeCredentialDescriptor',
            path: '$',
          },
        ],
        id: expect.any(String),
      },
      presentations: [
        {
          compact: expect.any(String),
          header: {
            alg: 'EdDSA',
            kid: '#z6MkrzQPBr4pyqC776KKtrz13SchM5ePPbssuPuQZb5t4uKQ',
            typ: 'vc+sd-jwt',
          },
          payload: {
            _sd: [expect.any(String), expect.any(String)],
            _sd_alg: 'sha-256',
            cnf: {
              kid: 'did:key:z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc#z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc',
            },
            iat: expect.any(Number),
            iss: 'did:key:z6MkrzQPBr4pyqC776KKtrz13SchM5ePPbssuPuQZb5t4uKQ',
            vct: 'OpenBadgeCredential',
            degree: 'bachelor',
          },
          // university SHOULD be disclosed
          prettyClaims: {
            cnf: {
              kid: 'did:key:z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc#z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc',
            },
            iat: expect.any(Number),
            iss: 'did:key:z6MkrzQPBr4pyqC776KKtrz13SchM5ePPbssuPuQZb5t4uKQ',
            vct: 'OpenBadgeCredential',
            degree: 'bachelor',
            university: 'innsbruck',
          },
        },
      ],
      descriptors: expect.any(Array),
    })
  })

  it('e2e flow with verifier endpoints verifying two sd-jwt-vcs with selective disclosure', async () => {
    const openIdVerifier = await verifier.agent.modules.openId4VcVerifier.createVerifier()

    const signedSdJwtVc = await issuer.agent.sdJwtVc.sign({
      holder: { method: 'did', didUrl: holder.kid },
      issuer: {
        method: 'did',
        didUrl: issuer.kid,
      },
      payload: {
        vct: 'OpenBadgeCredential',
        university: 'innsbruck',
        degree: 'bachelor',
        name: 'John Doe',
      },
      disclosureFrame: {
        _sd: ['university', 'name'],
      },
    })

    const signedSdJwtVc2 = await issuer.agent.sdJwtVc.sign({
      holder: { method: 'did', didUrl: holder.kid },
      issuer: {
        method: 'did',
        didUrl: issuer.kid,
      },
      payload: {
        vct: 'OpenBadgeCredential2',
        university: 'innsbruck2',
        degree: 'bachelor2',
        name: 'John Doe2',
      },
      disclosureFrame: {
        _sd: ['university', 'name'],
      },
    })

    const certificate = await verifier.agent.x509.createSelfSignedCertificate({
      key: await verifier.agent.wallet.createKey({ keyType: KeyType.Ed25519 }),
      extensions: [[{ type: 'dns', value: `localhost:${serverPort}` }]],
    })

    const rawCertificate = certificate.toString('base64')
    await holder.agent.sdJwtVc.store(signedSdJwtVc.compact)
    await holder.agent.sdJwtVc.store(signedSdJwtVc2.compact)

    await holder.agent.x509.addTrustedCertificate(rawCertificate)
    await verifier.agent.x509.addTrustedCertificate(rawCertificate)

    const presentationDefinition = {
      id: 'OpenBadgeCredentials',
      input_descriptors: [
        {
          id: 'OpenBadgeCredentialDescriptor',
          format: {
            'vc+sd-jwt': {
              'sd-jwt_alg_values': ['EdDSA'],
            },
          },
          constraints: {
            limit_disclosure: 'required',
            fields: [
              {
                path: ['$.vct'],
                filter: {
                  type: 'string',
                  const: 'OpenBadgeCredential',
                },
              },
              {
                path: ['$.university'],
              },
            ],
          },
        },
        {
          id: 'OpenBadgeCredentialDescriptor2',
          format: {
            'vc+sd-jwt': {
              'sd-jwt_alg_values': ['EdDSA'],
            },
          },
          constraints: {
            limit_disclosure: 'required',
            fields: [
              {
                path: ['$.vct'],
                filter: {
                  type: 'string',
                  const: 'OpenBadgeCredential2',
                },
              },
              {
                path: ['$.name'],
              },
            ],
          },
        },
      ],
    } satisfies DifPresentationExchangeDefinitionV2

    const { authorizationRequest, verificationSession } =
      await verifier.agent.modules.openId4VcVerifier.createAuthorizationRequest({
        verifierId: openIdVerifier.verifierId,

        requestSigner: {
          method: 'x5c',
          x5c: [rawCertificate],
        },
        presentationExchange: {
          definition: presentationDefinition,
        },
      })

    expect(authorizationRequest).toEqual(
      `openid4vp://?client_id=localhost%3A1234&request_uri=${encodeURIComponent(
        verificationSession.authorizationRequestUri
      )}`
    )

    const resolvedAuthorizationRequest = await holder.agent.modules.openId4VcHolder.resolveSiopAuthorizationRequest(
      authorizationRequest
    )

    expect(resolvedAuthorizationRequest.presentationExchange?.credentialsForRequest).toEqual({
      areRequirementsSatisfied: true,
      name: undefined,
      purpose: undefined,
      requirements: expect.arrayContaining([
        {
          isRequirementSatisfied: true,
          needsCount: 1,
          rule: 'pick',
          submissionEntry: [
            {
              name: undefined,
              purpose: undefined,
              inputDescriptorId: 'OpenBadgeCredentialDescriptor',
              verifiableCredentials: [
                {
                  type: ClaimFormat.SdJwtVc,
                  credentialRecord: expect.objectContaining({
                    compactSdJwtVc: signedSdJwtVc.compact,
                  }),
                  // Name is NOT in here
                  disclosedPayload: {
                    cnf: {
                      kid: 'did:key:z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc#z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc',
                    },
                    degree: 'bachelor',
                    iat: expect.any(Number),
                    iss: 'did:key:z6MkrzQPBr4pyqC776KKtrz13SchM5ePPbssuPuQZb5t4uKQ',
                    university: 'innsbruck',
                    vct: 'OpenBadgeCredential',
                  },
                },
              ],
            },
          ],
        },
        {
          isRequirementSatisfied: true,
          needsCount: 1,
          rule: 'pick',
          submissionEntry: [
            {
              name: undefined,
              purpose: undefined,
              inputDescriptorId: 'OpenBadgeCredentialDescriptor2',
              verifiableCredentials: [
                {
                  type: ClaimFormat.SdJwtVc,
                  credentialRecord: expect.objectContaining({
                    compactSdJwtVc: signedSdJwtVc2.compact,
                  }),
                  disclosedPayload: {
                    cnf: {
                      kid: 'did:key:z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc#z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc',
                    },
                    iat: expect.any(Number),
                    iss: 'did:key:z6MkrzQPBr4pyqC776KKtrz13SchM5ePPbssuPuQZb5t4uKQ',
                    vct: 'OpenBadgeCredential2',
                    degree: 'bachelor2',
                    name: 'John Doe2',
                  },
                },
              ],
            },
          ],
        },
      ]),
    })

    if (!resolvedAuthorizationRequest.presentationExchange) {
      throw new Error('Presentation exchange not defined')
    }

    const selectedCredentials = holder.agent.modules.openId4VcHolder.selectCredentialsForRequest(
      resolvedAuthorizationRequest.presentationExchange.credentialsForRequest
    )

    const { serverResponse, submittedResponse } =
      await holder.agent.modules.openId4VcHolder.acceptSiopAuthorizationRequest({
        authorizationRequest: resolvedAuthorizationRequest.authorizationRequest,
        presentationExchange: {
          credentials: selectedCredentials,
        },
      })

    // path_nested should not be used for sd-jwt
    expect(submittedResponse.presentation_submission?.descriptor_map[0].path_nested).toBeUndefined()
    expect(submittedResponse).toEqual({
      presentation_submission: {
        definition_id: 'OpenBadgeCredentials',
        descriptor_map: [
          {
            format: 'vc+sd-jwt',
            id: 'OpenBadgeCredentialDescriptor',
            path: '$[0]',
          },
          {
            format: 'vc+sd-jwt',
            id: 'OpenBadgeCredentialDescriptor2',
            path: '$[1]',
          },
        ],
        id: expect.any(String),
      },
      state: expect.any(String),
      vp_token: [expect.any(String), expect.any(String)],
    })
    expect(serverResponse).toMatchObject({
      status: 200,
    })

    // The RP MUST validate that the aud (audience) Claim contains the value of the client_id
    // that the RP sent in the Authorization Request as an audience.
    // When the request has been signed, the value might be an HTTPS URL, or a Decentralized Identifier.
    await waitForVerificationSessionRecordSubject(verifier.replaySubject, {
      contextCorrelationId: verifier.agent.context.contextCorrelationId,
      state: OpenId4VcVerificationSessionState.ResponseVerified,
      verificationSessionId: verificationSession.id,
    })
    const { idToken, presentationExchange } =
      await verifier.agent.modules.openId4VcVerifier.getVerifiedAuthorizationResponse(verificationSession.id)

    expect(idToken).toBeUndefined()

    const presentation = presentationExchange?.presentations[0] as SdJwtVc

    // name SHOULD NOT be disclosed
    expect(presentation.prettyClaims).not.toHaveProperty('name')

    // university and name SHOULD NOT be in the signed payload
    expect(presentation.payload).not.toHaveProperty('university')
    expect(presentation.payload).not.toHaveProperty('name')

    expect(presentationExchange).toEqual({
      definition: presentationDefinition,
      submission: {
        definition_id: 'OpenBadgeCredentials',
        descriptor_map: [
          {
            format: 'vc+sd-jwt',
            id: 'OpenBadgeCredentialDescriptor',
            path: '$[0]',
          },
          {
            format: 'vc+sd-jwt',
            id: 'OpenBadgeCredentialDescriptor2',
            path: '$[1]',
          },
        ],
        id: expect.any(String),
      },
      presentations: [
        {
          compact: expect.any(String),
          header: {
            alg: 'EdDSA',
            kid: '#z6MkrzQPBr4pyqC776KKtrz13SchM5ePPbssuPuQZb5t4uKQ',
            typ: 'vc+sd-jwt',
          },
          payload: {
            _sd: [expect.any(String), expect.any(String)],
            _sd_alg: 'sha-256',
            cnf: {
              kid: 'did:key:z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc#z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc',
            },
            iat: expect.any(Number),
            iss: 'did:key:z6MkrzQPBr4pyqC776KKtrz13SchM5ePPbssuPuQZb5t4uKQ',
            vct: 'OpenBadgeCredential',
            degree: 'bachelor',
          },
          // university SHOULD be disclosed
          prettyClaims: {
            cnf: {
              kid: 'did:key:z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc#z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc',
            },
            iat: expect.any(Number),
            iss: 'did:key:z6MkrzQPBr4pyqC776KKtrz13SchM5ePPbssuPuQZb5t4uKQ',
            vct: 'OpenBadgeCredential',
            degree: 'bachelor',
            university: 'innsbruck',
          },
        },
        {
          compact: expect.any(String),
          header: {
            alg: 'EdDSA',
            kid: '#z6MkrzQPBr4pyqC776KKtrz13SchM5ePPbssuPuQZb5t4uKQ',
            typ: 'vc+sd-jwt',
          },
          payload: {
            _sd: [expect.any(String), expect.any(String)],
            _sd_alg: 'sha-256',
            cnf: {
              kid: 'did:key:z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc#z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc',
            },
            iat: expect.any(Number),
            iss: 'did:key:z6MkrzQPBr4pyqC776KKtrz13SchM5ePPbssuPuQZb5t4uKQ',
            vct: 'OpenBadgeCredential2',
            degree: 'bachelor2',
          },
          prettyClaims: {
            cnf: {
              kid: 'did:key:z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc#z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc',
            },
            iat: expect.any(Number),
            iss: 'did:key:z6MkrzQPBr4pyqC776KKtrz13SchM5ePPbssuPuQZb5t4uKQ',
            vct: 'OpenBadgeCredential2',
            name: 'John Doe2',
            degree: 'bachelor2',
          },
        },
      ],
      descriptors: expect.any(Array),
    })
  })

  it('e2e flow with tenants, issuer endpoints requesting a mdoc', async () => {
    const issuerTenant1 = await issuer.agent.modules.tenants.getTenantAgent({ tenantId: issuer1.tenantId })

    const selfSignedIssuerCertificate = await issuerTenant1.x509.createSelfSignedCertificate({
      key: await issuerTenant1.wallet.createKey({ keyType: KeyType.P256 }),
      extensions: [],
      name: 'C=DE',
    })
    const selfSignedIssuerCertPem = selfSignedIssuerCertificate.toString('pem')
    await issuerTenant1.x509.setTrustedCertificates([selfSignedIssuerCertPem])

    const openIdIssuerTenant1 = await issuerTenant1.modules.openId4VcIssuer.createIssuer({
      dpopSigningAlgValuesSupported: [JwaSignatureAlgorithm.ES256],
      credentialConfigurationsSupported: {
        universityDegree: universityDegreeCredentialConfigurationSupportedMdoc,
      },
    })
    const issuer1Record = await issuerTenant1.modules.openId4VcIssuer.getIssuerByIssuerId(openIdIssuerTenant1.issuerId)
    expect(issuer1Record.dpopSigningAlgValuesSupported).toEqual(['ES256'])

    expect(issuer1Record.credentialConfigurationsSupported).toEqual({
      universityDegree: {
        format: 'mso_mdoc',
        cryptographic_binding_methods_supported: ['did:key', 'jwk'],
        proof_types_supported: {
          jwt: {
            proof_signing_alg_values_supported: ['ES256', 'EdDSA'],
          },
        },
        doctype: universityDegreeCredentialConfigurationSupportedMdoc.doctype,
        scope: universityDegreeCredentialConfigurationSupportedMdoc.scope,
      },
    })

    const { issuanceSession: issuanceSession1, credentialOffer: credentialOffer1 } =
      await issuerTenant1.modules.openId4VcIssuer.createCredentialOffer({
        issuerId: openIdIssuerTenant1.issuerId,
        offeredCredentials: ['universityDegree'],
        preAuthorizedCodeFlowConfig: {},
        version: 'v1.draft13',
      })

    await issuerTenant1.endSession()

    await waitForCredentialIssuanceSessionRecordSubject(issuer.replaySubject, {
      state: OpenId4VcIssuanceSessionState.OfferCreated,
      issuanceSessionId: issuanceSession1.id,
      contextCorrelationId: issuer1.tenantId,
    })

    const holderTenant1 = await holder.agent.modules.tenants.getTenantAgent({ tenantId: holder1.tenantId })
    await holderTenant1.x509.setTrustedCertificates([selfSignedIssuerCertPem])

    const resolvedCredentialOffer1 = await holderTenant1.modules.openId4VcHolder.resolveCredentialOffer(
      credentialOffer1
    )

    expect(resolvedCredentialOffer1.metadata.credentialIssuer?.dpop_signing_alg_values_supported).toEqual(['ES256'])
    expect(resolvedCredentialOffer1.offeredCredentialConfigurations).toEqual({
      universityDegree: {
        doctype: 'UniversityDegreeCredential',
        cryptographic_binding_methods_supported: ['did:key', 'jwk'],
        format: 'mso_mdoc',
        scope: universityDegreeCredentialConfigurationSupportedMdoc.scope,
        proof_types_supported: {
          jwt: {
            proof_signing_alg_values_supported: ['ES256', 'EdDSA'],
          },
        },
      },
    })

    expect(resolvedCredentialOffer1.credentialOfferPayload.credential_issuer).toEqual(
      `${issuanceBaseUrl}/${openIdIssuerTenant1.issuerId}`
    )
    expect(resolvedCredentialOffer1.metadata.credentialIssuer?.token_endpoint).toEqual(
      `${issuanceBaseUrl}/${openIdIssuerTenant1.issuerId}/token`
    )
    expect(resolvedCredentialOffer1.metadata.credentialIssuer?.credential_endpoint).toEqual(
      `${issuanceBaseUrl}/${openIdIssuerTenant1.issuerId}/credential`
    )

    // Bind to JWK
    const tokenResponseTenant1 = await holderTenant1.modules.openId4VcHolder.requestToken({
      resolvedCredentialOffer: resolvedCredentialOffer1,
    })

    expect(tokenResponseTenant1.accessToken).toBeDefined()
    expect(tokenResponseTenant1.dpop?.jwk).toBeInstanceOf(Jwk)
    const { payload } = Jwt.fromSerializedJwt(tokenResponseTenant1.accessToken)

    expect(payload.toJson()).toEqual({
      cnf: {
        jkt: await calculateJwkThumbprint({
          hashAlgorithm: HashAlgorithm.Sha256,
          hashCallback: getOid4vciCallbacks(holderTenant1.context).hash,
          jwk: tokenResponseTenant1.dpop?.jwk.toJson() as JwkJson,
        }),
      },
      'pre-authorized_code':
        resolvedCredentialOffer1.credentialOfferPayload.grants?.[preAuthorizedCodeGrantIdentifier]?.[
          'pre-authorized_code'
        ],

      aud: `http://localhost:1234/oid4vci/${openIdIssuerTenant1.issuerId}`,
      exp: expect.any(Number),
      iat: expect.any(Number),
      iss: `http://localhost:1234/oid4vci/${openIdIssuerTenant1.issuerId}`,
      jti: expect.any(String),
      nbf: undefined,
      sub: expect.stringContaining('credo:'),
    })

    const credentialsTenant1 = await holderTenant1.modules.openId4VcHolder.requestCredentials({
      resolvedCredentialOffer: resolvedCredentialOffer1,
      ...tokenResponseTenant1,
      credentialBindingResolver,
    })

    // Wait for all events
    await waitForCredentialIssuanceSessionRecordSubject(issuer.replaySubject, {
      state: OpenId4VcIssuanceSessionState.AccessTokenRequested,
      issuanceSessionId: issuanceSession1.id,
      contextCorrelationId: issuer1.tenantId,
    })
    await waitForCredentialIssuanceSessionRecordSubject(issuer.replaySubject, {
      state: OpenId4VcIssuanceSessionState.AccessTokenCreated,
      issuanceSessionId: issuanceSession1.id,
      contextCorrelationId: issuer1.tenantId,
    })
    await waitForCredentialIssuanceSessionRecordSubject(issuer.replaySubject, {
      state: OpenId4VcIssuanceSessionState.CredentialRequestReceived,
      issuanceSessionId: issuanceSession1.id,
      contextCorrelationId: issuer1.tenantId,
    })
    await waitForCredentialIssuanceSessionRecordSubject(issuer.replaySubject, {
      state: OpenId4VcIssuanceSessionState.Completed,
      issuanceSessionId: issuanceSession1.id,
      contextCorrelationId: issuer1.tenantId,
    })

    expect(credentialsTenant1.credentials).toHaveLength(1)
    const mdocBase64Url = (credentialsTenant1.credentials[0].credentials[0] as Mdoc).base64Url
    const mdoc = holderTenant1.mdoc.fromBase64Url(mdocBase64Url)
    expect(mdoc.docType).toEqual('UniversityDegreeCredential')

    await holderTenant1.endSession()
  })

  it('e2e flow with verifier endpoints verifying a mdoc and sd-jwt (jarm)', async () => {
    const openIdVerifier = await verifier.agent.modules.openId4VcVerifier.createVerifier()

    const signedSdJwtVc = await issuer.agent.sdJwtVc.sign({
      holder: { method: 'did', didUrl: holder.kid },
      issuer: {
        method: 'did',
        didUrl: issuer.kid,
      },
      payload: {
        vct: 'OpenBadgeCredential',
        university: 'innsbruck',
        degree: 'bachelor',
        name: 'John Doe',
      },
      disclosureFrame: {
        _sd: ['university', 'name'],
      },
    })
    await holder.agent.sdJwtVc.store(signedSdJwtVc.compact)

    const selfSignedCertificate = await X509Service.createSelfSignedCertificate(issuer.agent.context, {
      key: await issuer.agent.context.wallet.createKey({ keyType: KeyType.P256 }),
      extensions: [],
      name: 'C=DE',
    })

    await verifier.agent.x509.setTrustedCertificates([selfSignedCertificate.toString('pem')])

    const parsedDid = parseDid(issuer.kid)
    if (!parsedDid.fragment) {
      throw new Error(`didUrl '${parsedDid.didUrl}' does not contain a '#'. Unable to derive key from did document.`)
    }

    const holderKey = await holder.agent.context.wallet.createKey({ keyType: KeyType.P256 })

    const signedMdoc = await issuer.agent.mdoc.sign({
      docType: 'org.eu.university',
      holderKey,
      issuerCertificate: selfSignedCertificate.toString('pem'),
      namespaces: {
        'eu.europa.ec.eudi.pid.1': {
          university: 'innsbruck',
          degree: 'bachelor',
          name: 'John Doe',
          not: 'disclosed',
        },
      },
    })

    const certificate = await verifier.agent.x509.createSelfSignedCertificate({
      key: await verifier.agent.wallet.createKey({ keyType: KeyType.Ed25519 }),
      extensions: [[{ type: 'dns', value: 'localhost:1234' }]],
    })

    const rawCertificate = certificate.toString('base64')
    await holder.agent.mdoc.store(signedMdoc)

    await holder.agent.x509.addTrustedCertificate(rawCertificate)
    await verifier.agent.x509.addTrustedCertificate(rawCertificate)

    const presentationDefinition = {
      id: 'mDL-sample-req',
      input_descriptors: [
        {
          id: 'org.eu.university',
          format: {
            mso_mdoc: {
              alg: ['ES256', 'ES384', 'ES512', 'EdDSA', 'ESB256', 'ESB320', 'ESB384', 'ESB512'],
            },
          },
          constraints: {
            fields: [
              {
                path: ["$['eu.europa.ec.eudi.pid.1']['name']"],
                intent_to_retain: false,
              },
              {
                path: ["$['eu.europa.ec.eudi.pid.1']['degree']"],
                intent_to_retain: false,
              },
            ],
            limit_disclosure: 'required',
          },
        },
        {
          id: 'OpenBadgeCredentialDescriptor',
          format: {
            'vc+sd-jwt': {
              'sd-jwt_alg_values': ['EdDSA'],
            },
          },
          constraints: {
            limit_disclosure: 'required',
            fields: [
              {
                path: ['$.vct'],
                filter: {
                  type: 'string',
                  const: 'OpenBadgeCredential',
                },
              },
              {
                path: ['$.university'],
              },
            ],
          },
        },
      ],
    } satisfies DifPresentationExchangeDefinitionV2

    const { authorizationRequest, verificationSession } =
      await verifier.agent.modules.openId4VcVerifier.createAuthorizationRequest({
        responseMode: 'direct_post.jwt',
        verifierId: openIdVerifier.verifierId,
        requestSigner: {
          method: 'x5c',
          x5c: [rawCertificate],
          issuer: 'https://example.com/hakuna/matadata',
        },
        presentationExchange: {
          definition: presentationDefinition,
        },
      })

    expect(authorizationRequest).toEqual(
      `openid4vp://?client_id=localhost%3A1234&request_uri=${encodeURIComponent(
        verificationSession.authorizationRequestUri
      )}`
    )

    const resolvedAuthorizationRequest = await holder.agent.modules.openId4VcHolder.resolveSiopAuthorizationRequest(
      authorizationRequest
    )

    expect(resolvedAuthorizationRequest.presentationExchange?.credentialsForRequest).toEqual({
      areRequirementsSatisfied: true,
      name: undefined,
      purpose: undefined,
      requirements: expect.arrayContaining([
        {
          isRequirementSatisfied: true,
          needsCount: 1,
          rule: 'pick',
          submissionEntry: [
            {
              name: undefined,
              purpose: undefined,
              inputDescriptorId: 'org.eu.university',
              verifiableCredentials: [
                {
                  type: ClaimFormat.MsoMdoc,
                  credentialRecord: expect.objectContaining({
                    base64Url: expect.any(String),
                  }),
                  // Name is NOT in here
                  disclosedPayload: {
                    'eu.europa.ec.eudi.pid.1': {
                      degree: 'bachelor',
                      name: 'John Doe',
                    },
                  },
                },
              ],
            },
          ],
        },

        {
          isRequirementSatisfied: true,
          needsCount: 1,
          rule: 'pick',
          submissionEntry: [
            {
              name: undefined,
              purpose: undefined,
              inputDescriptorId: 'OpenBadgeCredentialDescriptor',
              verifiableCredentials: [
                {
                  type: ClaimFormat.SdJwtVc,
                  credentialRecord: expect.objectContaining({
                    compactSdJwtVc: signedSdJwtVc.compact,
                  }),
                  // Name is NOT in here
                  disclosedPayload: {
                    cnf: {
                      kid: 'did:key:z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc#z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc',
                    },
                    degree: 'bachelor',
                    iat: expect.any(Number),
                    iss: 'did:key:z6MkrzQPBr4pyqC776KKtrz13SchM5ePPbssuPuQZb5t4uKQ',
                    university: 'innsbruck',
                    vct: 'OpenBadgeCredential',
                  },
                },
              ],
            },
          ],
        },
      ]),
    })

    if (!resolvedAuthorizationRequest.presentationExchange) {
      throw new Error('Presentation exchange not defined')
    }

    const selectedCredentials = holder.agent.modules.openId4VcHolder.selectCredentialsForRequest(
      resolvedAuthorizationRequest.presentationExchange.credentialsForRequest
    )

    const { serverResponse, submittedResponse } =
      await holder.agent.modules.openId4VcHolder.acceptSiopAuthorizationRequest({
        authorizationRequest: resolvedAuthorizationRequest.authorizationRequest,
        presentationExchange: {
          credentials: selectedCredentials,
        },
      })

    // path_nested should not be used for sd-jwt
    expect(submittedResponse.presentation_submission?.descriptor_map[0].path_nested).toBeUndefined()
    expect(submittedResponse).toEqual({
      presentation_submission: {
        id: expect.any(String),
        definition_id: 'mDL-sample-req',
        descriptor_map: [
          {
            id: 'org.eu.university',
            format: 'mso_mdoc',
            path: '$[0]',
          },
          {
            format: 'vc+sd-jwt',
            id: 'OpenBadgeCredentialDescriptor',
            path: '$[1]',
          },
        ],
      },
      state: expect.any(String),
      vp_token: expect.any(Array<string>),
    })
    expect(serverResponse).toMatchObject({
      status: 200,
    })

    // The RP MUST validate that the aud (audience) Claim contains the value of the client_id
    // that the RP sent in the Authorization Request as an audience.
    // When the request has been signed, the value might be an HTTPS URL, or a Decentralized Identifier.
    await waitForVerificationSessionRecordSubject(verifier.replaySubject, {
      contextCorrelationId: verifier.agent.context.contextCorrelationId,
      state: OpenId4VcVerificationSessionState.ResponseVerified,
      verificationSessionId: verificationSession.id,
    })
    const { idToken, presentationExchange } =
      await verifier.agent.modules.openId4VcVerifier.getVerifiedAuthorizationResponse(verificationSession.id)

    expect(idToken).toBeUndefined()

    const presentation = presentationExchange?.presentations[0] as MdocDeviceResponse
    expect(presentation.documents).toHaveLength(1)

    const mdocResponse = presentation.documents[0]

    // name SHOULD NOT be disclosed
    expect(mdocResponse.issuerSignedNamespaces).toStrictEqual({
      'eu.europa.ec.eudi.pid.1': {
        degree: 'bachelor',
        name: 'John Doe',
      },
    })

    expect(presentationExchange).toEqual({
      definition: presentationDefinition,
      submission: {
        id: expect.any(String),
        definition_id: 'mDL-sample-req',
        descriptor_map: [
          {
            id: 'org.eu.university',
            format: 'mso_mdoc',
            path: '$[0]',
          },
          {
            id: 'OpenBadgeCredentialDescriptor',
            format: 'vc+sd-jwt',
            path: '$[1]',
          },
        ],
      },
      presentations: [
        {
          base64Url: expect.any(String),
          documents: [
            {
              issuerSignedDocument: {
                docType: 'org.eu.university',
                issuerSigned: {
                  nameSpaces: new Map([['eu.europa.ec.eudi.pid.1', [{}, {}]]]),
                  issuerAuth: expect.any(Object),
                },
                deviceSigned: expect.any(Object),
              },
              base64Url: expect.any(String),
            },
          ],
        },
        {
          compact: expect.any(String),
          header: {
            alg: 'EdDSA',
            kid: '#z6MkrzQPBr4pyqC776KKtrz13SchM5ePPbssuPuQZb5t4uKQ',
            typ: 'vc+sd-jwt',
          },
          payload: {
            _sd: [expect.any(String), expect.any(String)],
            _sd_alg: 'sha-256',
            cnf: {
              kid: 'did:key:z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc#z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc',
            },
            iat: expect.any(Number),
            iss: 'did:key:z6MkrzQPBr4pyqC776KKtrz13SchM5ePPbssuPuQZb5t4uKQ',
            vct: 'OpenBadgeCredential',
            degree: 'bachelor',
          },
          // university SHOULD be disclosed
          prettyClaims: {
            cnf: {
              kid: 'did:key:z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc#z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc',
            },
            iat: expect.any(Number),
            iss: 'did:key:z6MkrzQPBr4pyqC776KKtrz13SchM5ePPbssuPuQZb5t4uKQ',
            vct: 'OpenBadgeCredential',
            degree: 'bachelor',
            university: 'innsbruck',
          },
        },
      ],
      descriptors: expect.any(Array),
    })
  })

  it('e2e flow with verifier endpoints verifying two sd-jwt-vcs with selective disclosure', async () => {
    const openIdVerifier = await verifier.agent.modules.openId4VcVerifier.createVerifier()

    const signedSdJwtVc = await issuer.agent.sdJwtVc.sign({
      holder: { method: 'did', didUrl: holder.kid },
      issuer: {
        method: 'did',
        didUrl: issuer.kid,
      },
      payload: {
        vct: 'OpenBadgeCredential',
        university: 'innsbruck',
        degree: 'bachelor',
        name: 'John Doe',
      },
      disclosureFrame: {
        _sd: ['university', 'name'],
      },
    })

    const signedSdJwtVc2 = await issuer.agent.sdJwtVc.sign({
      holder: { method: 'did', didUrl: holder.kid },
      issuer: {
        method: 'did',
        didUrl: issuer.kid,
      },
      payload: {
        vct: 'OpenBadgeCredential2',
        university: 'innsbruck2',
        degree: 'bachelor2',
        name: 'John Doe2',
      },
      disclosureFrame: {
        _sd: ['university', 'name'],
      },
    })

    const certificate = await verifier.agent.x509.createSelfSignedCertificate({
      key: await verifier.agent.wallet.createKey({ keyType: KeyType.Ed25519 }),
      extensions: [[{ type: 'dns', value: 'localhost:1234' }]],
    })

    const rawCertificate = certificate.toString('base64')
    await holder.agent.sdJwtVc.store(signedSdJwtVc.compact)
    await holder.agent.sdJwtVc.store(signedSdJwtVc2.compact)

    await holder.agent.x509.addTrustedCertificate(rawCertificate)
    await verifier.agent.x509.addTrustedCertificate(rawCertificate)

    const presentationDefinition = {
      id: 'OpenBadgeCredentials',
      input_descriptors: [
        {
          id: 'OpenBadgeCredentialDescriptor',
          format: {
            'vc+sd-jwt': {
              'sd-jwt_alg_values': ['EdDSA'],
            },
          },
          constraints: {
            limit_disclosure: 'required',
            fields: [
              {
                path: ['$.vct'],
                filter: {
                  type: 'string',
                  const: 'OpenBadgeCredential',
                },
              },
              {
                path: ['$.university'],
              },
            ],
          },
        },
        {
          id: 'OpenBadgeCredentialDescriptor2',
          format: {
            'vc+sd-jwt': {
              'sd-jwt_alg_values': ['EdDSA'],
            },
          },
          constraints: {
            limit_disclosure: 'required',
            fields: [
              {
                path: ['$.vct'],
                filter: {
                  type: 'string',
                  const: 'OpenBadgeCredential2',
                },
              },
              {
                path: ['$.name'],
              },
            ],
          },
        },
      ],
    } satisfies DifPresentationExchangeDefinitionV2

    const { authorizationRequest, verificationSession } =
      await verifier.agent.modules.openId4VcVerifier.createAuthorizationRequest({
        verifierId: openIdVerifier.verifierId,

        requestSigner: {
          method: 'x5c',
          x5c: [rawCertificate],
        },
        presentationExchange: {
          definition: presentationDefinition,
        },
      })

    expect(authorizationRequest).toEqual(
      `openid4vp://?client_id=localhost%3A1234&request_uri=${encodeURIComponent(
        verificationSession.authorizationRequestUri
      )}`
    )

    const resolvedAuthorizationRequest = await holder.agent.modules.openId4VcHolder.resolveSiopAuthorizationRequest(
      authorizationRequest
    )

    expect(resolvedAuthorizationRequest.presentationExchange?.credentialsForRequest).toEqual({
      areRequirementsSatisfied: true,
      name: undefined,
      purpose: undefined,
      requirements: expect.arrayContaining([
        {
          isRequirementSatisfied: true,
          needsCount: 1,
          rule: 'pick',
          submissionEntry: [
            {
              name: undefined,
              purpose: undefined,
              inputDescriptorId: 'OpenBadgeCredentialDescriptor',
              verifiableCredentials: [
                {
                  type: ClaimFormat.SdJwtVc,
                  credentialRecord: expect.objectContaining({
                    compactSdJwtVc: signedSdJwtVc.compact,
                  }),
                  // Name is NOT in here
                  disclosedPayload: {
                    cnf: {
                      kid: 'did:key:z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc#z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc',
                    },
                    degree: 'bachelor',
                    iat: expect.any(Number),
                    iss: 'did:key:z6MkrzQPBr4pyqC776KKtrz13SchM5ePPbssuPuQZb5t4uKQ',
                    university: 'innsbruck',
                    vct: 'OpenBadgeCredential',
                  },
                },
              ],
            },
          ],
        },
        {
          isRequirementSatisfied: true,
          needsCount: 1,
          rule: 'pick',
          submissionEntry: [
            {
              name: undefined,
              purpose: undefined,
              inputDescriptorId: 'OpenBadgeCredentialDescriptor2',
              verifiableCredentials: [
                {
                  type: ClaimFormat.SdJwtVc,
                  credentialRecord: expect.objectContaining({
                    compactSdJwtVc: signedSdJwtVc2.compact,
                  }),
                  disclosedPayload: {
                    cnf: {
                      kid: 'did:key:z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc#z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc',
                    },
                    iat: expect.any(Number),
                    iss: 'did:key:z6MkrzQPBr4pyqC776KKtrz13SchM5ePPbssuPuQZb5t4uKQ',
                    vct: 'OpenBadgeCredential2',
                    degree: 'bachelor2',
                    name: 'John Doe2',
                  },
                },
              ],
            },
          ],
        },
      ]),
    })

    if (!resolvedAuthorizationRequest.presentationExchange) {
      throw new Error('Presentation exchange not defined')
    }

    const selectedCredentials = holder.agent.modules.openId4VcHolder.selectCredentialsForRequest(
      resolvedAuthorizationRequest.presentationExchange.credentialsForRequest
    )

    const { serverResponse, submittedResponse } =
      await holder.agent.modules.openId4VcHolder.acceptSiopAuthorizationRequest({
        authorizationRequest: resolvedAuthorizationRequest.authorizationRequest,
        presentationExchange: {
          credentials: selectedCredentials,
        },
      })

    // path_nested should not be used for sd-jwt
    expect(submittedResponse.presentation_submission?.descriptor_map[0].path_nested).toBeUndefined()
    expect(submittedResponse).toEqual({
      presentation_submission: {
        definition_id: 'OpenBadgeCredentials',
        descriptor_map: [
          {
            format: 'vc+sd-jwt',
            id: 'OpenBadgeCredentialDescriptor',
            path: '$[0]',
          },
          {
            format: 'vc+sd-jwt',
            id: 'OpenBadgeCredentialDescriptor2',
            path: '$[1]',
          },
        ],
        id: expect.any(String),
      },
      state: expect.any(String),
      vp_token: [expect.any(String), expect.any(String)],
    })
    expect(serverResponse).toMatchObject({
      status: 200,
    })

    // The RP MUST validate that the aud (audience) Claim contains the value of the client_id
    // that the RP sent in the Authorization Request as an audience.
    // When the request has been signed, the value might be an HTTPS URL, or a Decentralized Identifier.
    await waitForVerificationSessionRecordSubject(verifier.replaySubject, {
      contextCorrelationId: verifier.agent.context.contextCorrelationId,
      state: OpenId4VcVerificationSessionState.ResponseVerified,
      verificationSessionId: verificationSession.id,
    })
    const { idToken, presentationExchange } =
      await verifier.agent.modules.openId4VcVerifier.getVerifiedAuthorizationResponse(verificationSession.id)

    expect(idToken).toBeUndefined()

    const presentation = presentationExchange?.presentations[0] as SdJwtVc

    // name SHOULD NOT be disclosed
    expect(presentation.prettyClaims).not.toHaveProperty('name')

    // university and name SHOULD NOT be in the signed payload
    expect(presentation.payload).not.toHaveProperty('university')
    expect(presentation.payload).not.toHaveProperty('name')

    expect(presentationExchange).toEqual({
      definition: presentationDefinition,
      submission: {
        definition_id: 'OpenBadgeCredentials',
        descriptor_map: [
          {
            format: 'vc+sd-jwt',
            id: 'OpenBadgeCredentialDescriptor',
            path: '$[0]',
          },
          {
            format: 'vc+sd-jwt',
            id: 'OpenBadgeCredentialDescriptor2',
            path: '$[1]',
          },
        ],
        id: expect.any(String),
      },
      presentations: [
        {
          compact: expect.any(String),
          header: {
            alg: 'EdDSA',
            kid: '#z6MkrzQPBr4pyqC776KKtrz13SchM5ePPbssuPuQZb5t4uKQ',
            typ: 'vc+sd-jwt',
          },
          payload: {
            _sd: [expect.any(String), expect.any(String)],
            _sd_alg: 'sha-256',
            cnf: {
              kid: 'did:key:z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc#z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc',
            },
            iat: expect.any(Number),
            iss: 'did:key:z6MkrzQPBr4pyqC776KKtrz13SchM5ePPbssuPuQZb5t4uKQ',
            vct: 'OpenBadgeCredential',
            degree: 'bachelor',
          },
          // university SHOULD be disclosed
          prettyClaims: {
            cnf: {
              kid: 'did:key:z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc#z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc',
            },
            iat: expect.any(Number),
            iss: 'did:key:z6MkrzQPBr4pyqC776KKtrz13SchM5ePPbssuPuQZb5t4uKQ',
            vct: 'OpenBadgeCredential',
            degree: 'bachelor',
            university: 'innsbruck',
          },
        },
        {
          compact: expect.any(String),
          header: {
            alg: 'EdDSA',
            kid: '#z6MkrzQPBr4pyqC776KKtrz13SchM5ePPbssuPuQZb5t4uKQ',
            typ: 'vc+sd-jwt',
          },
          payload: {
            _sd: [expect.any(String), expect.any(String)],
            _sd_alg: 'sha-256',
            cnf: {
              kid: 'did:key:z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc#z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc',
            },
            iat: expect.any(Number),
            iss: 'did:key:z6MkrzQPBr4pyqC776KKtrz13SchM5ePPbssuPuQZb5t4uKQ',
            vct: 'OpenBadgeCredential2',
            degree: 'bachelor2',
          },
          prettyClaims: {
            cnf: {
              kid: 'did:key:z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc#z6MkpGR4gs4Rc3Zph4vj8wRnjnAxgAPSxcR8MAVKutWspQzc',
            },
            iat: expect.any(Number),
            iss: 'did:key:z6MkrzQPBr4pyqC776KKtrz13SchM5ePPbssuPuQZb5t4uKQ',
            vct: 'OpenBadgeCredential2',
            name: 'John Doe2',
            degree: 'bachelor2',
          },
        },
      ],
      descriptors: expect.any(Array),
    })
  })

  it('e2e flow with tenants and federation, verifier endpoints verifying a jwt-vc', async () => {
    const holderTenant = await holder.agent.modules.tenants.getTenantAgent({ tenantId: holder1.tenantId })
    const verifierTenant1 = await verifier.agent.modules.tenants.getTenantAgent({ tenantId: verifier1.tenantId })
    const verifierTenant2 = await verifier.agent.modules.tenants.getTenantAgent({ tenantId: verifier2.tenantId })

    const openIdVerifierTenant1 = await verifierTenant1.modules.openId4VcVerifier.createVerifier()
    const openIdVerifierTenant2 = await verifierTenant2.modules.openId4VcVerifier.createVerifier()

    const signedCredential1 = await issuer.agent.w3cCredentials.signCredential({
      format: ClaimFormat.JwtVc,
      credential: new W3cCredential({
        type: ['VerifiableCredential', 'OpenBadgeCredential'],
        issuer: new W3cIssuer({ id: issuer.did }),
        credentialSubject: new W3cCredentialSubject({ id: holder1.did }),
        issuanceDate: w3cDate(Date.now()),
      }),
      alg: JwaSignatureAlgorithm.EdDSA,
      verificationMethod: issuer.verificationMethod.id,
    })

    const signedCredential2 = await issuer.agent.w3cCredentials.signCredential({
      format: ClaimFormat.JwtVc,
      credential: new W3cCredential({
        type: ['VerifiableCredential', 'UniversityDegreeCredential'],
        issuer: new W3cIssuer({ id: issuer.did }),
        credentialSubject: new W3cCredentialSubject({ id: holder1.did }),
        issuanceDate: w3cDate(Date.now()),
      }),
      alg: JwaSignatureAlgorithm.EdDSA,
      verificationMethod: issuer.verificationMethod.id,
    })

    await holderTenant.w3cCredentials.storeCredential({ credential: signedCredential1 })
    await holderTenant.w3cCredentials.storeCredential({ credential: signedCredential2 })

    const { authorizationRequest: authorizationRequestUri1, verificationSession: verificationSession1 } =
      await verifierTenant1.modules.openId4VcVerifier.createAuthorizationRequest({
        verifierId: openIdVerifierTenant1.verifierId,
        requestSigner: {
          method: 'openid-federation',
        },
        presentationExchange: {
          definition: openBadgePresentationDefinition,
        },
      })

    expect(authorizationRequestUri1).toEqual(
      `openid4vp://?client_id=${encodeURIComponent(
        `http://localhost:1234/oid4vp/${openIdVerifierTenant1.verifierId}`
      )}&request_uri=${encodeURIComponent(verificationSession1.authorizationRequestUri)}`
    )

    const { authorizationRequest: authorizationRequestUri2, verificationSession: verificationSession2 } =
      await verifierTenant2.modules.openId4VcVerifier.createAuthorizationRequest({
        requestSigner: {
          method: 'openid-federation',
        },
        presentationExchange: {
          definition: universityDegreePresentationDefinition,
        },
        verifierId: openIdVerifierTenant2.verifierId,
      })

    expect(authorizationRequestUri2).toEqual(
      `openid4vp://?client_id=${encodeURIComponent(
        `http://localhost:1234/oid4vp/${openIdVerifierTenant2.verifierId}`
      )}&request_uri=${encodeURIComponent(verificationSession2.authorizationRequestUri)}`
    )

    await verifierTenant1.endSession()
    await verifierTenant2.endSession()

    const resolvedProofRequest1 = await holderTenant.modules.openId4VcHolder.resolveSiopAuthorizationRequest(
      authorizationRequestUri1,
      {
        federation: {
          trustedEntityIds: [`http://localhost:1234/oid4vp/${openIdVerifierTenant1.verifierId}`],
        },
      }
    )

    expect(resolvedProofRequest1.presentationExchange?.credentialsForRequest).toMatchObject({
      areRequirementsSatisfied: true,
      requirements: [
        {
          submissionEntry: [
            {
              verifiableCredentials: [
                {
                  type: ClaimFormat.JwtVc,
                  credentialRecord: {
                    credential: {
                      type: ['VerifiableCredential', 'OpenBadgeCredential'],
                    },
                  },
                },
              ],
            },
          ],
        },
      ],
    })

    const resolvedProofRequest2 = await holderTenant.modules.openId4VcHolder.resolveSiopAuthorizationRequest(
      authorizationRequestUri2,
      {
        federation: {
          trustedEntityIds: [`http://localhost:1234/oid4vp/${openIdVerifierTenant2.verifierId}`],
        },
      }
    )

    expect(resolvedProofRequest2.presentationExchange?.credentialsForRequest).toMatchObject({
      areRequirementsSatisfied: true,
      requirements: [
        {
          submissionEntry: [
            {
              verifiableCredentials: [
                {
                  type: ClaimFormat.JwtVc,
                  credentialRecord: {
                    credential: {
                      type: ['VerifiableCredential', 'UniversityDegreeCredential'],
                    },
                  },
                },
              ],
            },
          ],
        },
      ],
    })

    if (!resolvedProofRequest1.presentationExchange || !resolvedProofRequest2.presentationExchange) {
      throw new Error('Presentation exchange not defined')
    }

    const presentationExchangeService = holderTenant.dependencyManager.resolve(DifPresentationExchangeService)
    const selectedCredentials = presentationExchangeService.selectCredentialsForRequest(
      resolvedProofRequest1.presentationExchange.credentialsForRequest
    )

    const { submittedResponse: submittedResponse1, serverResponse: serverResponse1 } =
      await holderTenant.modules.openId4VcHolder.acceptSiopAuthorizationRequest({
        authorizationRequest: resolvedProofRequest1.authorizationRequest,
        presentationExchange: {
          credentials: selectedCredentials,
        },
      })

    expect(submittedResponse1).toEqual({
      presentation_submission: {
        definition_id: 'OpenBadgeCredential',
        descriptor_map: [
          {
            format: 'jwt_vp',
            id: 'OpenBadgeCredentialDescriptor',
            path: '$',
            path_nested: {
              format: 'jwt_vc',
              id: 'OpenBadgeCredentialDescriptor',
              path: '$.vp.verifiableCredential[0]',
            },
          },
        ],
        id: expect.any(String),
      },
      state: expect.any(String),
      vp_token: expect.any(String),
    })
    expect(serverResponse1).toMatchObject({
      status: 200,
    })

    // The RP MUST validate that the aud (audience) Claim contains the value of the client_id
    // that the RP sent in the Authorization Request as an audience.
    // When the request has been signed, the value might be an HTTPS URL, or a Decentralized Identifier.
    const verifierTenant1_2 = await verifier.agent.modules.tenants.getTenantAgent({ tenantId: verifier1.tenantId })
    await waitForVerificationSessionRecordSubject(verifier.replaySubject, {
      contextCorrelationId: verifierTenant1_2.context.contextCorrelationId,
      state: OpenId4VcVerificationSessionState.ResponseVerified,
      verificationSessionId: verificationSession1.id,
    })

    const { idToken: idToken1, presentationExchange: presentationExchange1 } =
      await verifierTenant1_2.modules.openId4VcVerifier.getVerifiedAuthorizationResponse(verificationSession1.id)

    expect(idToken1).toBeUndefined()
    expect(presentationExchange1).toMatchObject({
      definition: openBadgePresentationDefinition,
      submission: {
        definition_id: 'OpenBadgeCredential',
      },
      presentations: [
        {
          verifiableCredential: [
            {
              type: ['VerifiableCredential', 'OpenBadgeCredential'],
            },
          ],
        },
      ],
    })

    const selectedCredentials2 = presentationExchangeService.selectCredentialsForRequest(
      resolvedProofRequest2.presentationExchange.credentialsForRequest
    )

    const { serverResponse: serverResponse2 } =
      await holderTenant.modules.openId4VcHolder.acceptSiopAuthorizationRequest({
        authorizationRequest: resolvedProofRequest2.authorizationRequest,
        presentationExchange: {
          credentials: selectedCredentials2,
        },
      })
    expect(serverResponse2).toMatchObject({
      status: 200,
    })

    // The RP MUST validate that the aud (audience) Claim contains the value of the client_id
    // that the RP sent in the Authorization Request as an audience.
    // When the request has been signed, the value might be an HTTPS URL, or a Decentralized Identifier.
    const verifierTenant2_2 = await verifier.agent.modules.tenants.getTenantAgent({ tenantId: verifier2.tenantId })
    await waitForVerificationSessionRecordSubject(verifier.replaySubject, {
      contextCorrelationId: verifierTenant2_2.context.contextCorrelationId,
      state: OpenId4VcVerificationSessionState.ResponseVerified,
      verificationSessionId: verificationSession2.id,
    })
    const { idToken: idToken2, presentationExchange: presentationExchange2 } =
      await verifierTenant2_2.modules.openId4VcVerifier.getVerifiedAuthorizationResponse(verificationSession2.id)
    expect(idToken2).toBeUndefined()

    expect(presentationExchange2).toMatchObject({
      definition: universityDegreePresentationDefinition,
      submission: {
        definition_id: 'UniversityDegreeCredential',
      },
      presentations: [
        {
          verifiableCredential: [
            {
              type: ['VerifiableCredential', 'UniversityDegreeCredential'],
            },
          ],
        },
      ],
    })
  })
})
