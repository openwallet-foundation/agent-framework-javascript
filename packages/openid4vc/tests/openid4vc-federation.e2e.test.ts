import type { AgentType, TenantType } from './utils'
import type { OpenId4VcVerifierModuleConfig } from '../src'
import type { Server } from 'http'

import {
  ClaimFormat,
  DidsApi,
  JwaSignatureAlgorithm,
  W3cCredential,
  W3cCredentialSubject,
  w3cDate,
  W3cIssuer,
  DifPresentationExchangeService,
} from '@credo-ts/core'
import express, { type Express } from 'express'

import { AskarModule } from '../../askar/src'
import { askarModuleConfig } from '../../askar/tests/helpers'
import { TenantsModule } from '../../tenants/src'
import {
  OpenId4VcHolderModule,
  OpenId4VcIssuerModule,
  OpenId4VcVerificationSessionState,
  OpenId4VcVerifierModule,
} from '../src'

import { createAgentFromModules, createTenantForAgent, waitForVerificationSessionRecordSubject } from './utils'
import { openBadgePresentationDefinition, universityDegreePresentationDefinition } from './utilsVp'

const serverPort = 1234
const baseUrl = `http://localhost:${serverPort}`
const issuanceBaseUrl = `${baseUrl}/oid4vci`
const verificationBaseUrl = `${baseUrl}/oid4vp`

describe('OpenId4Vc-federation', () => {
  let expressApp: Express
  let expressServer: Server

  let issuer: AgentType<{
    openId4VcIssuer: OpenId4VcIssuerModule
    tenants: TenantsModule<{ openId4VcIssuer: OpenId4VcIssuerModule }>
  }>
  // let issuer1: TenantType
  // let issuer2: TenantType

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

  let federationConfig: OpenId4VcVerifierModuleConfig['federation'] | undefined

  beforeEach(async () => {
    expressApp = express()

    issuer = (await createAgentFromModules(
      'issuer',
      {
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
    // issuer1 = await createTenantForAgent(issuer.agent, 'iTenant1')
    // issuer2 = await createTenantForAgent(issuer.agent, 'iTenant2')

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
          federation: {
            async isSubordinateEntity(agentContext, options) {
              if (federationConfig && federationConfig.isSubordinateEntity) {
                return federationConfig.isSubordinateEntity(agentContext, options)
              }
              return false
            },
            async getAuthorityHints(agentContext, options) {
              if (federationConfig && federationConfig.getAuthorityHints) {
                return federationConfig.getAuthorityHints(agentContext, options)
              }
              return undefined
            },
          },
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

    federationConfig = undefined
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

  it('e2e flow with tenants and federation with multiple layers, verifier endpoints verifying a jwt-vc', async () => {
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

    federationConfig = {
      isSubordinateEntity: async (agentContext, options) => {
        // When the verifier 2 gets asked if verifier 1 is a subordinate entity, it should return true
        return options.verifierId === openIdVerifierTenant2.verifierId
      },
      getAuthorityHints: async (agentContext, options) => {
        // The verifier 1 says that the verifier 2 is above him
        return options.verifierId === openIdVerifierTenant1.verifierId
          ? [`http://localhost:1234/oid4vp/${openIdVerifierTenant2.verifierId}`]
          : undefined
      },
    }

    // Gets a request from verifier 1 but we trust verifier 2 so if the verifier 1 is in the subordinate entity list of verifier 2 it should succeed
    const resolvedProofRequest1 = await holderTenant.modules.openId4VcHolder.resolveSiopAuthorizationRequest(
      authorizationRequestUri1,
      {
        federation: {
          trustedEntityIds: [`http://localhost:1234/oid4vp/${openIdVerifierTenant2.verifierId}`],
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

  it('e2e flow with tenants and federation, unhappy flow', async () => {
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

    const resolvedProofRequestWithFederationPromise =
      holderTenant.modules.openId4VcHolder.resolveSiopAuthorizationRequest(authorizationRequestUri1, {
        federation: {
          // This will look for a whole different trusted entity
          trustedEntityIds: [`http://localhost:1234/oid4vp/${openIdVerifierTenant2.verifierId}`],
        },
      })

    // TODO: Look into this error see if we can make it more specific
    await expect(resolvedProofRequestWithFederationPromise).rejects.toThrow(
      `Error verifying the DID Auth Token signature.`
    )

    const resolvedProofRequestWithoutFederationPromise =
      holderTenant.modules.openId4VcHolder.resolveSiopAuthorizationRequest(authorizationRequestUri2)
    await expect(resolvedProofRequestWithoutFederationPromise).rejects.toThrow(
      `Error verifying the DID Auth Token signature.`
    )
  })
})
