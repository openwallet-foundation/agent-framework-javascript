import type { AgentType } from './utils'
import type {
  OpenId4VciGetVerificationSessionForIssuanceSessionAuthorization,
  OpenId4VciSignSdJwtCredentials,
} from '../src'
import type { OpenId4VciCredentialBindingResolver } from '../src/openid4vc-holder'
import type { DcqlQuery, DifPresentationExchangeDefinitionV2, SdJwtVc, SdJwtVcIssuer } from '@credo-ts/core'

import { AuthorizationFlow } from '@animo-id/oid4vci'
import { ClaimFormat, getJwkFromKey } from '@credo-ts/core'
import express, { type Express } from 'express'

import { setupNockToExpress } from '../../../tests/nockToExpress'
import { AskarModule } from '../../askar/src'
import { askarModuleConfig } from '../../askar/tests/helpers'
import {
  OpenId4VcVerifierModule,
  OpenId4VcHolderModule,
  OpenId4VcIssuanceSessionState,
  OpenId4VcIssuerModule,
  getScopesFromCredentialConfigurationsSupported,
} from '../src'

import { waitForCredentialIssuanceSessionRecordSubject, createAgentFromModules } from './utils'
import { universityDegreeCredentialConfigurationSupported } from './utilsVci'

const dcqlQuery = {
  credentials: [
    {
      id: 'e498bd12-be8f-4884-8ffe-2704176b99be',
      format: 'vc+sd-jwt',
      claims: [
        {
          path: ['given_name'],
        },
        {
          path: ['family_name'],
        },
      ],
      meta: {
        vct_values: ['urn:eu.europa.ec.eudi:pid:1'],
      },
    },
  ],
} satisfies DcqlQuery

const presentationDefinition = {
  id: 'a34cff9d-a825-4283-9d9a-e84f97ebdd08',
  input_descriptors: [
    {
      id: 'e498bd12-be8f-4884-8ffe-2704176b99be',
      name: 'Identity Credential',
      purpose: 'To issue your university degree we need to verify your identity',
      constraints: {
        limit_disclosure: 'required',
        fields: [
          {
            path: ['$.vct'],
            filter: {
              type: 'string',
              const: 'urn:eu.europa.ec.eudi:pid:1',
            },
          },
          {
            path: ['$.given_name'],
            filter: {
              type: 'string',
            },
          },
          {
            path: ['$.family_name'],
            filter: {
              type: 'string',
            },
          },
        ],
      },
    },
  ],
} as const satisfies DifPresentationExchangeDefinitionV2

const baseUrl = 'http://localhost:4871'
const issuerBaseUrl = `${baseUrl}/oid4vci`
const verifierBaseUrl = `${baseUrl}/oid4vp`

let issuer: AgentType<{
  openId4VcIssuer: OpenId4VcIssuerModule
  openId4VcVerifier: OpenId4VcVerifierModule
  askar: AskarModule
}>

const getVerificationSessionForIssuanceSessionAuthorization =
  (queryMethod: 'dcql' | 'presentationDefinition'): OpenId4VciGetVerificationSessionForIssuanceSessionAuthorization =>
  async ({ issuanceSession, scopes }) => {
    if (scopes.includes(universityDegreeCredentialConfigurationSupported.scope)) {
      const createRequestReturn = await issuer.agent.modules.openId4VcVerifier.createAuthorizationRequest({
        verifierId: issuanceSession.issuerId,
        requestSigner: {
          method: 'x5c',
          x5c: [issuer.certificate.toString('base64')],
        },
        responseMode: 'direct_post.jwt',
        presentationExchange:
          queryMethod === 'presentationDefinition'
            ? {
                definition: presentationDefinition,
              }
            : undefined,
        dcql:
          queryMethod === 'dcql'
            ? {
                query: dcqlQuery,
              }
            : undefined,
      })

      return {
        ...createRequestReturn,
        scopes: [universityDegreeCredentialConfigurationSupported.scope],
      }
    }

    throw new Error('Unsupported scope values')
  }

describe('OpenId4Vc Presentation During Issuance', () => {
  let expressApp: Express
  let clearNock: () => void

  let holder: AgentType<{
    openId4VcHolder: OpenId4VcHolderModule
    askar: AskarModule
  }>

  beforeEach(async () => {
    expressApp = express()

    issuer = await createAgentFromModules('issuer', {
      openId4VcIssuer: new OpenId4VcIssuerModule({
        baseUrl: issuerBaseUrl,
        getVerificationSessionForIssuanceSessionAuthorization:
          getVerificationSessionForIssuanceSessionAuthorization('presentationDefinition'),
        credentialRequestToCredentialMapper: async ({
          credentialRequest,
          holderBindings,
          credentialConfigurationIds,
          verification,
        }) => {
          if (!verification) {
            throw new Error('Expected verification in credential request mapper')
          }

          const credentialConfigurationId = credentialConfigurationIds[0]
          let credential: SdJwtVc

          if (verification.presentationExchange) {
            const descriptor = verification.presentationExchange.descriptors.find(
              (descriptor) => descriptor.descriptor.id === presentationDefinition.input_descriptors[0].id
            )

            if (!descriptor || descriptor.format !== ClaimFormat.SdJwtVc) {
              throw new Error('Expected descriptor with sd-jwt vc format')
            }

            credential = descriptor.credential
          } else {
            const presentation = verification.dcql.presentation[verification.dcql.presentationResult.credentials[0].id]

            if (presentation.claimFormat !== ClaimFormat.SdJwtVc) {
              throw new Error('Expected preentation with sd-jwt vc format')
            }

            credential = presentation
          }

          const fullName = `${credential.prettyClaims.given_name} ${credential.prettyClaims.family_name}`

          if (credentialRequest.format === 'vc+sd-jwt') {
            return {
              credentialConfigurationId,
              format: credentialRequest.format,
              credentials: holderBindings.map((holderBinding) => ({
                payload: { vct: credentialRequest.vct, full_name: fullName, degree: 'Software Engineer' },
                holder: holderBinding,
                issuer: {
                  method: 'x5c',
                  x5c: [issuer.certificate.toString('base64')],
                  issuer: baseUrl,
                },
                disclosureFrame: {
                  _sd: ['full_name'],
                },
              })),
            } satisfies OpenId4VciSignSdJwtCredentials
          } else {
            throw new Error('Invalid request')
          }
        },
      }),
      openId4VcVerifier: new OpenId4VcVerifierModule({
        baseUrl: verifierBaseUrl,
      }),
      askar: new AskarModule(askarModuleConfig),
    })

    holder = await createAgentFromModules('holder', {
      openId4VcHolder: new OpenId4VcHolderModule(),
      askar: new AskarModule(askarModuleConfig),
    })

    await holder.agent.x509.addTrustedCertificate(issuer.certificate.toString('base64'))
    await issuer.agent.x509.addTrustedCertificate(issuer.certificate.toString('base64'))

    // We let AFJ create the router, so we have a fresh one each time
    expressApp.use('/oid4vci', issuer.agent.modules.openId4VcIssuer.config.router)
    expressApp.use('/oid4vp', issuer.agent.modules.openId4VcVerifier.config.router)

    clearNock = setupNockToExpress(baseUrl, expressApp)
  })

  afterEach(async () => {
    clearNock()

    await issuer.agent.shutdown()
    await issuer.agent.wallet.delete()

    await holder.agent.shutdown()
    await holder.agent.wallet.delete()
  })

  const credentialBindingResolver: OpenId4VciCredentialBindingResolver = () => ({
    method: 'jwk',
    jwk: getJwkFromKey(holder.key),
  })

  it('e2e flow with requesting presentation of credentials before issuance succeeds with presentation definition', async () => {
    const issuerRecord = await issuer.agent.modules.openId4VcIssuer.createIssuer({
      issuerId: '2f9c0385-7191-4c50-aa22-40cf5839d52b',
      credentialConfigurationsSupported: {
        universityDegree: universityDegreeCredentialConfigurationSupported,
      },
    })

    const x5cIssuer = {
      method: 'x5c',
      x5c: [issuer.certificate.toString('base64')],
      issuer: baseUrl,
    } satisfies SdJwtVcIssuer

    await issuer.agent.modules.openId4VcVerifier.createVerifier({
      verifierId: '2f9c0385-7191-4c50-aa22-40cf5839d52b',
    })

    // Pre-store identity credential
    const holderIdentityCredential = await issuer.agent.sdJwtVc.sign({
      issuer: x5cIssuer,
      payload: {
        vct: 'urn:eu.europa.ec.eudi:pid:1',
        given_name: 'Erika',
        family_name: 'Powerstar',
      },
      disclosureFrame: {
        _sd: ['given_name', 'family_name'],
      },
      holder: {
        method: 'jwk',
        jwk: holder.jwk,
      },
    })
    await holder.agent.sdJwtVc.store(holderIdentityCredential.compact)

    // Create offer for university degree
    const { issuanceSession, credentialOffer } = await issuer.agent.modules.openId4VcIssuer.createCredentialOffer({
      issuerId: issuerRecord.issuerId,
      offeredCredentials: ['universityDegree'],
      authorizationCodeFlowConfig: {
        requirePresentationDuringIssuance: true,
      },
    })

    // Resolve offer
    const resolvedCredentialOffer = await holder.agent.modules.openId4VcHolder.resolveCredentialOffer(credentialOffer)
    const resolvedAuthorization = await holder.agent.modules.openId4VcHolder.resolveIssuanceAuthorizationRequest(
      resolvedCredentialOffer,
      {
        clientId: 'foo',
        redirectUri: 'http://localhost:1234/redirect',
        scope: getScopesFromCredentialConfigurationsSupported(resolvedCredentialOffer.offeredCredentialConfigurations),
      }
    )

    // Ensure presentation request
    if (resolvedAuthorization.authorizationFlow !== AuthorizationFlow.PresentationDuringIssuance) {
      throw new Error('Not supported')
    }
    const resolvedPresentationRequest = await holder.agent.modules.openId4VcHolder.resolveSiopAuthorizationRequest(
      resolvedAuthorization.oid4vpRequestUrl
    )
    if (!resolvedPresentationRequest.presentationExchange) {
      throw new Error('Missing presentation exchange')
    }

    // Submit presentation
    const selectedCredentials = holder.agent.modules.openId4VcHolder.selectCredentialsForPresentationExchangeRequest(
      resolvedPresentationRequest.presentationExchange.credentialsForRequest
    )
    const siopResult = await holder.agent.modules.openId4VcHolder.acceptSiopAuthorizationRequest({
      authorizationRequest: resolvedPresentationRequest.authorizationRequest,
      presentationExchange: {
        credentials: selectedCredentials,
      },
    })
    expect(siopResult.serverResponse.status).toEqual(200)
    expect(siopResult.ok).toEqual(true)
    if (!siopResult.ok) {
      throw new Error('not ok')
    }

    // Request authorization code
    const { authorizationCode } = await holder.agent.modules.openId4VcHolder.retrieveAuthorizationCodeUsingPresentation(
      {
        authSession: resolvedAuthorization.authSession,
        resolvedCredentialOffer,
        presentationDuringIssuanceSession: siopResult.presentationDuringIssuanceSession,
      }
    )

    // Request access token
    const tokenResponse = await holder.agent.modules.openId4VcHolder.requestToken({
      resolvedCredentialOffer,
      code: authorizationCode,
      clientId: 'foo',
      redirectUri: 'http://localhost:1234/redirect',
    })

    // Request credential
    const credentialResponse = await holder.agent.modules.openId4VcHolder.requestCredentials({
      resolvedCredentialOffer,
      ...tokenResponse,
      clientId: 'foo',
      credentialBindingResolver,
    })

    await waitForCredentialIssuanceSessionRecordSubject(issuer.replaySubject, {
      state: OpenId4VcIssuanceSessionState.Completed,
      issuanceSessionId: issuanceSession.id,
    })

    expect(credentialResponse.credentials).toHaveLength(1)
    const compactSdJwtVc = (credentialResponse.credentials[0].credentials[0] as SdJwtVc).compact
    const sdJwtVc = holder.agent.sdJwtVc.fromCompact(compactSdJwtVc)
    expect(sdJwtVc.payload.vct).toEqual(universityDegreeCredentialConfigurationSupported.vct)
    expect(sdJwtVc.prettyClaims.full_name).toEqual('Erika Powerstar')
  })

  it('e2e flow with requesting presentation of credentials before issuance succeeds with dcql query', async () => {
    issuer.agent.modules.openId4VcIssuer.config.getVerificationSessionForIssuanceSessionAuthorization =
      getVerificationSessionForIssuanceSessionAuthorization('dcql')

    const issuerRecord = await issuer.agent.modules.openId4VcIssuer.createIssuer({
      issuerId: '2f9c0385-7191-4c50-aa22-40cf5839d52b',
      credentialConfigurationsSupported: {
        universityDegree: universityDegreeCredentialConfigurationSupported,
      },
    })

    const x5cIssuer = {
      method: 'x5c',
      x5c: [issuer.certificate.toString('base64')],
      issuer: baseUrl,
    } satisfies SdJwtVcIssuer

    await issuer.agent.modules.openId4VcVerifier.createVerifier({
      verifierId: '2f9c0385-7191-4c50-aa22-40cf5839d52b',
    })

    // Pre-store identity credential
    const holderIdentityCredential = await issuer.agent.sdJwtVc.sign({
      issuer: x5cIssuer,
      payload: {
        vct: 'urn:eu.europa.ec.eudi:pid:1',
        given_name: 'Erika',
        family_name: 'Powerstar',
      },
      disclosureFrame: {
        _sd: ['given_name', 'family_name'],
      },
      holder: {
        method: 'jwk',
        jwk: holder.jwk,
      },
    })
    await holder.agent.sdJwtVc.store(holderIdentityCredential.compact)

    // Create offer for university degree
    const { issuanceSession, credentialOffer } = await issuer.agent.modules.openId4VcIssuer.createCredentialOffer({
      issuerId: issuerRecord.issuerId,
      offeredCredentials: ['universityDegree'],
      authorizationCodeFlowConfig: {
        requirePresentationDuringIssuance: true,
      },
    })

    // Resolve offer
    const resolvedCredentialOffer = await holder.agent.modules.openId4VcHolder.resolveCredentialOffer(credentialOffer)
    const resolvedAuthorization = await holder.agent.modules.openId4VcHolder.resolveIssuanceAuthorizationRequest(
      resolvedCredentialOffer,
      {
        clientId: 'foo',
        redirectUri: 'http://localhost:1234/redirect',
        scope: getScopesFromCredentialConfigurationsSupported(resolvedCredentialOffer.offeredCredentialConfigurations),
      }
    )

    // Ensure presentation request
    if (resolvedAuthorization.authorizationFlow !== AuthorizationFlow.PresentationDuringIssuance) {
      throw new Error('Not supported')
    }
    const resolvedPresentationRequest = await holder.agent.modules.openId4VcHolder.resolveSiopAuthorizationRequest(
      resolvedAuthorization.oid4vpRequestUrl
    )
    if (!resolvedPresentationRequest.dcql) {
      throw new Error('Missing dcql')
    }

    // Submit presentation
    const selectedCredentials = holder.agent.modules.openId4VcHolder.selectCredentialsForDcqlRequest(
      resolvedPresentationRequest.dcql.queryResult
    )
    const siopResult = await holder.agent.modules.openId4VcHolder.acceptSiopAuthorizationRequest({
      authorizationRequest: resolvedPresentationRequest.authorizationRequest,
      dcql: {
        credentials: selectedCredentials,
      },
    })
    expect(siopResult.serverResponse.status).toEqual(200)
    expect(siopResult.ok).toEqual(true)
    if (!siopResult.ok) {
      throw new Error('not ok')
    }

    // Request authorization code
    const { authorizationCode } = await holder.agent.modules.openId4VcHolder.retrieveAuthorizationCodeUsingPresentation(
      {
        authSession: resolvedAuthorization.authSession,
        resolvedCredentialOffer,
        presentationDuringIssuanceSession: siopResult.presentationDuringIssuanceSession,
      }
    )

    // Request access token
    const tokenResponse = await holder.agent.modules.openId4VcHolder.requestToken({
      resolvedCredentialOffer,
      code: authorizationCode,
      clientId: 'foo',
      redirectUri: 'http://localhost:1234/redirect',
    })

    // Request credential
    const credentialResponse = await holder.agent.modules.openId4VcHolder.requestCredentials({
      resolvedCredentialOffer,
      ...tokenResponse,
      clientId: 'foo',
      credentialBindingResolver,
    })

    await waitForCredentialIssuanceSessionRecordSubject(issuer.replaySubject, {
      state: OpenId4VcIssuanceSessionState.Completed,
      issuanceSessionId: issuanceSession.id,
    })

    expect(credentialResponse.credentials).toHaveLength(1)
    const compactSdJwtVc = (credentialResponse.credentials[0].credentials[0] as SdJwtVc).compact
    const sdJwtVc = holder.agent.sdJwtVc.fromCompact(compactSdJwtVc)
    expect(sdJwtVc.payload.vct).toEqual(universityDegreeCredentialConfigurationSupported.vct)
    expect(sdJwtVc.prettyClaims.full_name).toEqual('Erika Powerstar')
  })

  it('e2e flow with requesting presentation of credentials before issuance but fails because presentation not verified', async () => {
    const issuerRecord = await issuer.agent.modules.openId4VcIssuer.createIssuer({
      issuerId: '2f9c0385-7191-4c50-aa22-40cf5839d52b',
      credentialConfigurationsSupported: {
        universityDegree: universityDegreeCredentialConfigurationSupported,
      },
    })

    const x5cIssuer = {
      method: 'x5c',
      x5c: [issuer.certificate.toString('base64')],
      issuer: baseUrl,
    } satisfies SdJwtVcIssuer

    await issuer.agent.modules.openId4VcVerifier.createVerifier({
      verifierId: '2f9c0385-7191-4c50-aa22-40cf5839d52b',
    })

    // Pre-store identity credential
    const holderIdentityCredential = await issuer.agent.sdJwtVc.sign({
      issuer: x5cIssuer,
      payload: {
        vct: 'urn:eu.europa.ec.eudi:pid:1',
        given_name: 'Erika',
        family_name: 'Powerstar',
      },
      disclosureFrame: {
        _sd: ['given_name', 'family_name'],
      },
      holder: {
        method: 'jwk',
        jwk: holder.jwk,
      },
    })
    await holder.agent.sdJwtVc.store(holderIdentityCredential.compact)

    // Create offer for university degree
    const { credentialOffer } = await issuer.agent.modules.openId4VcIssuer.createCredentialOffer({
      issuerId: issuerRecord.issuerId,
      offeredCredentials: ['universityDegree'],
      authorizationCodeFlowConfig: {
        requirePresentationDuringIssuance: true,
      },
    })

    // Resolve offer
    const resolvedCredentialOffer = await holder.agent.modules.openId4VcHolder.resolveCredentialOffer(credentialOffer)
    const resolvedAuthorization = await holder.agent.modules.openId4VcHolder.resolveIssuanceAuthorizationRequest(
      resolvedCredentialOffer,
      {
        clientId: 'foo',
        redirectUri: 'http://localhost:1234/redirect',
        scope: getScopesFromCredentialConfigurationsSupported(resolvedCredentialOffer.offeredCredentialConfigurations),
      }
    )

    // Ensure presentation request
    if (resolvedAuthorization.authorizationFlow !== AuthorizationFlow.PresentationDuringIssuance) {
      throw new Error('Not supported')
    }
    const resolvedPresentationRequest = await holder.agent.modules.openId4VcHolder.resolveSiopAuthorizationRequest(
      resolvedAuthorization.oid4vpRequestUrl
    )
    if (!resolvedPresentationRequest.presentationExchange) {
      throw new Error('Missing presentation exchange')
    }

    // Requesting authorization code should fail
    await expect(
      holder.agent.modules.openId4VcHolder.retrieveAuthorizationCodeUsingPresentation({
        authSession: resolvedAuthorization.authSession,
        resolvedCredentialOffer,
      })
    ).rejects.toThrow(`Invalid presentation for 'auth_session'`)
  })

  it('e2e flow with requesting presentation of credentials before issuance but fails because invalid auth session', async () => {
    const issuerRecord = await issuer.agent.modules.openId4VcIssuer.createIssuer({
      issuerId: '2f9c0385-7191-4c50-aa22-40cf5839d52b',
      credentialConfigurationsSupported: {
        universityDegree: universityDegreeCredentialConfigurationSupported,
      },
    })

    // Create offer for university degree
    const { credentialOffer } = await issuer.agent.modules.openId4VcIssuer.createCredentialOffer({
      issuerId: issuerRecord.issuerId,
      offeredCredentials: ['universityDegree'],
      authorizationCodeFlowConfig: {
        requirePresentationDuringIssuance: true,
      },
    })

    // Resolve offer
    const resolvedCredentialOffer = await holder.agent.modules.openId4VcHolder.resolveCredentialOffer(credentialOffer)

    await expect(
      holder.agent.modules.openId4VcHolder.retrieveAuthorizationCodeUsingPresentation({
        authSession: 'some auth session',
        resolvedCredentialOffer,
      })
    ).rejects.toThrow("Invalid 'auth_session'")
  })
})
