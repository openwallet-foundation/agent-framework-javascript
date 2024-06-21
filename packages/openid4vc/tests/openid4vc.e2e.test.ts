import type { AgentType, TenantType } from './utils'
import type { OpenId4VciCredentialBindingResolver } from '../src/openid4vc-holder'
import type { DifPresentationExchangeDefinitionV2, SdJwtVc } from '@credo-ts/core'
import type { Server } from 'http'

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

import {
  waitForVerificationSessionRecordSubject,
  waitForCredentialIssuanceSessionRecordSubject,
  createAgentFromModules,
  createTenantForAgent,
} from './utils'
import { universityDegreeCredentialSdJwt, universityDegreeCredentialSdJwt2 } from './utilsVci'
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
        openId4VcIssuer: new OpenId4VcIssuerModule({
          baseUrl: issuanceBaseUrl,
          endpoints: {
            credential: {
              credentialRequestToCredentialMapper: async ({ agentContext, credentialRequest, holderBinding }) => {
                // We sign the request with the first did:key did we have
                const didsApi = agentContext.dependencyManager.resolve(DidsApi)
                const [firstDidKeyDid] = await didsApi.getCreatedDids({ method: 'key' })
                const didDocument = await didsApi.resolveDidDocument(firstDidKeyDid.did)
                const verificationMethod = didDocument.verificationMethod?.[0]
                if (!verificationMethod) {
                  throw new Error('No verification method found')
                }

                if (credentialRequest.format === 'vc+sd-jwt') {
                  return {
                    credentialSupportedId:
                      credentialRequest.vct === 'UniversityDegreeCredential'
                        ? universityDegreeCredentialSdJwt.id
                        : universityDegreeCredentialSdJwt2.id,
                    format: credentialRequest.format,
                    payload: { vct: credentialRequest.vct, university: 'innsbruck', degree: 'bachelor' },
                    holder: holderBinding,
                    issuer: {
                      method: 'did',
                      didUrl: verificationMethod.id,
                    },
                    disclosureFrame: { _sd: ['university', 'degree'] },
                  }
                }

                throw new Error('Invalid request')
              },
            },
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
      },
      '96213c3d7fc8d4d6754c7a0fd969598e'
    )) as unknown as typeof holder
    holder1 = await createTenantForAgent(holder.agent, 'hTenant1')

    verifier = (await createAgentFromModules(
      'verifier',
      {
        openId4VcVerifier: new OpenId4VcVerifierModule({
          baseUrl: verificationBaseUrl,
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
      credentialsSupported: [universityDegreeCredentialSdJwt],
    })

    const openIdIssuerTenant2 = await issuerTenant2.modules.openId4VcIssuer.createIssuer({
      credentialsSupported: [universityDegreeCredentialSdJwt2],
    })

    const { issuanceSession: issuanceSession1, credentialOffer: credentialOffer1 } =
      await issuerTenant1.modules.openId4VcIssuer.createCredentialOffer({
        issuerId: openIdIssuerTenant1.issuerId,
        offeredCredentials: [universityDegreeCredentialSdJwt.id],
        preAuthorizedCodeFlowConfig: { userPinRequired: false },
      })

    const { issuanceSession: issuanceSession2, credentialOffer: credentialOffer2 } =
      await issuerTenant2.modules.openId4VcIssuer.createCredentialOffer({
        issuerId: openIdIssuerTenant2.issuerId,
        offeredCredentials: [universityDegreeCredentialSdJwt2.id],
        preAuthorizedCodeFlowConfig: { userPinRequired: false },
      })

    await issuerTenant1.endSession()
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

    await waitForCredentialIssuanceSessionRecordSubject(issuer.replaySubject, {
      state: OpenId4VcIssuanceSessionState.OfferUriRetrieved,
      issuanceSessionId: issuanceSession1.id,
      contextCorrelationId: issuer1.tenantId,
    })

    expect(resolvedCredentialOffer1.credentialOfferPayload.credential_issuer).toEqual(
      `${issuanceBaseUrl}/${openIdIssuerTenant1.issuerId}`
    )
    expect(resolvedCredentialOffer1.metadata.credentialIssuerMetadata?.token_endpoint).toEqual(
      `${issuanceBaseUrl}/${openIdIssuerTenant1.issuerId}/token`
    )
    expect(resolvedCredentialOffer1.metadata.credentialIssuerMetadata?.credential_endpoint).toEqual(
      `${issuanceBaseUrl}/${openIdIssuerTenant1.issuerId}/credential`
    )

    // Bind to JWK
    const credentialsTenant1 = await holderTenant1.modules.openId4VcHolder.acceptCredentialOfferUsingPreAuthorizedCode(
      resolvedCredentialOffer1,
      {
        credentialBindingResolver,
      }
    )

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

    expect(credentialsTenant1).toHaveLength(1)
    const compactSdJwtVcTenant1 = (credentialsTenant1[0] as SdJwtVc).compact
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
    expect(resolvedCredentialOffer2.metadata.credentialIssuerMetadata?.token_endpoint).toEqual(
      `${issuanceBaseUrl}/${openIdIssuerTenant2.issuerId}/token`
    )
    expect(resolvedCredentialOffer2.metadata.credentialIssuerMetadata?.credential_endpoint).toEqual(
      `${issuanceBaseUrl}/${openIdIssuerTenant2.issuerId}/credential`
    )

    // Bind to did
    const credentialsTenant2 = await holderTenant1.modules.openId4VcHolder.acceptCredentialOfferUsingPreAuthorizedCode(
      resolvedCredentialOffer2,
      {
        credentialBindingResolver,
      }
    )

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

    expect(credentialsTenant2).toHaveLength(1)
    const compactSdJwtVcTenant2 = (credentialsTenant2[0] as SdJwtVc).compact
    const sdJwtVcTenant2 = holderTenant1.sdJwtVc.fromCompact(compactSdJwtVcTenant2)
    expect(sdJwtVcTenant2.payload.vct).toEqual('UniversityDegreeCredential2')

    await holderTenant1.endSession()
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
      `openid://?request_uri=${encodeURIComponent(verificationSession.authorizationRequestUri)}`
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
      expires_in: 6000,
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
      `openid4vp://?request_uri=${encodeURIComponent(verificationSession1.authorizationRequestUri)}`
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
      `openid4vp://?request_uri=${encodeURIComponent(verificationSession2.authorizationRequestUri)}`
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
      expires_in: 6000,
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

  it('e2e flow with verifier endpoints verifying a sd-jwt-vc with selective disclosure', async () => {
    const openIdVerifier = await verifier.agent.modules.openId4VcVerifier.createVerifier()

    const signedSdJwtVc = await issuer.agent.sdJwtVc.sign({
      holder: {
        method: 'did',
        didUrl: holder.kid,
      },
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
          method: 'did',
          didUrl: verifier.kid,
        },
        presentationExchange: {
          definition: presentationDefinition,
        },
      })

    expect(authorizationRequest).toEqual(
      `openid4vp://?request_uri=${encodeURIComponent(verificationSession.authorizationRequestUri)}`
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

    // TODO: better way to auto-select
    const presentationExchangeService = holder.agent.dependencyManager.resolve(DifPresentationExchangeService)
    const selectedCredentials = presentationExchangeService.selectCredentialsForRequest(
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
      expires_in: 6000,
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
    })
  })
})
