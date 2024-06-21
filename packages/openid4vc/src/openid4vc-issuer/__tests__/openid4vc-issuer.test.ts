import type { OpenId4VciCredentialRequest, OpenId4VciCredentialSupportedWithId } from '../../shared'
import type {
  OpenId4VcIssuerMetadata,
  OpenId4VciCredentialRequestToCredentialMapper,
} from '../OpenId4VcIssuerServiceOptions'
import type { OpenId4VcIssuerRecord } from '../repository'
import type {
  AgentContext,
  KeyDidCreateOptions,
  VerificationMethod,
  W3cVerifiableCredential,
  W3cVerifyCredentialResult,
} from '@credo-ts/core'
import type { OriginalVerifiableCredential as SphereonW3cVerifiableCredential } from '@sphereon/ssi-types'

import {
  SdJwtVcApi,
  JwtPayload,
  Agent,
  CredoError,
  DidKey,
  DidsApi,
  JsonTransformer,
  JwsService,
  KeyType,
  TypedArrayEncoder,
  W3cCredential,
  W3cCredentialService,
  W3cCredentialSubject,
  W3cIssuer,
  W3cJsonLdVerifiableCredential,
  W3cJwtVerifiableCredential,
  equalsIgnoreOrder,
  getJwkFromKey,
  getKeyFromVerificationMethod,
  w3cDate,
} from '@credo-ts/core'

import { AskarModule } from '../../../../askar/src'
import { askarModuleConfig } from '../../../../askar/tests/helpers'
import { agentDependencies } from '../../../../node/src'
import { OpenId4VciCredentialFormatProfile } from '../../shared'
import { OpenId4VcIssuanceSessionState } from '../OpenId4VcIssuanceSessionState'
import { OpenId4VcIssuerModule } from '../OpenId4VcIssuerModule'
import { OpenId4VcIssuanceSessionRepository } from '../repository'

const openBadgeCredential = {
  id: 'https://openid4vc-issuer.com/credentials/OpenBadgeCredential',
  format: OpenId4VciCredentialFormatProfile.JwtVcJson,
  types: ['VerifiableCredential', 'OpenBadgeCredential'],
} satisfies OpenId4VciCredentialSupportedWithId

const universityDegreeCredential = {
  id: 'https://openid4vc-issuer.com/credentials/UniversityDegreeCredential',
  format: OpenId4VciCredentialFormatProfile.JwtVcJson,
  types: ['VerifiableCredential', 'UniversityDegreeCredential'],
} satisfies OpenId4VciCredentialSupportedWithId

const universityDegreeCredentialLd = {
  id: 'https://openid4vc-issuer.com/credentials/UniversityDegreeCredentialLd',
  format: OpenId4VciCredentialFormatProfile.JwtVcJsonLd,
  '@context': [],
  types: ['VerifiableCredential', 'UniversityDegreeCredential'],
} satisfies OpenId4VciCredentialSupportedWithId

const universityDegreeCredentialSdJwt = {
  id: 'https://openid4vc-issuer.com/credentials/UniversityDegreeCredentialSdJwt',
  format: OpenId4VciCredentialFormatProfile.SdJwtVc,
  vct: 'UniversityDegreeCredential',
} satisfies OpenId4VciCredentialSupportedWithId

const modules = {
  openId4VcIssuer: new OpenId4VcIssuerModule({
    baseUrl: 'https://openid4vc-issuer.com',
    endpoints: {
      credential: {
        credentialRequestToCredentialMapper: () => {
          throw new Error('Not implemented')
        },
      },
    },
  }),
  askar: new AskarModule(askarModuleConfig),
}

const jwsService = new JwsService()

const createCredentialRequest = async (
  agentContext: AgentContext,
  options: {
    issuerMetadata: OpenId4VcIssuerMetadata
    credentialSupported: OpenId4VciCredentialSupportedWithId
    nonce: string
    kid: string
    clientId?: string // use with the authorization code flow,
  }
): Promise<OpenId4VciCredentialRequest> => {
  const { credentialSupported, kid, nonce, issuerMetadata, clientId } = options

  const didsApi = agentContext.dependencyManager.resolve(DidsApi)
  const didDocument = await didsApi.resolveDidDocument(kid)
  if (!didDocument.verificationMethod) {
    throw new CredoError(`No verification method found for kid ${kid}`)
  }

  const verificationMethod = didDocument.dereferenceKey(kid, ['authentication', 'assertionMethod'])
  const key = getKeyFromVerificationMethod(verificationMethod)
  const jwk = getJwkFromKey(key)

  const jws = await jwsService.createJwsCompact(agentContext, {
    protectedHeaderOptions: { alg: jwk.supportedSignatureAlgorithms[0], kid, typ: 'openid4vci-proof+jwt' },
    payload: new JwtPayload({
      iat: Math.floor(Date.now() / 1000), // unix time
      iss: clientId,
      aud: issuerMetadata.issuerUrl,
      additionalClaims: {
        nonce,
      },
    }),
    key,
  })

  if (credentialSupported.format === OpenId4VciCredentialFormatProfile.JwtVcJson) {
    return { ...credentialSupported, proof: { jwt: jws, proof_type: 'jwt' } }
  } else if (
    credentialSupported.format === OpenId4VciCredentialFormatProfile.JwtVcJsonLd ||
    credentialSupported.format === OpenId4VciCredentialFormatProfile.LdpVc
  ) {
    return {
      format: credentialSupported.format,
      credential_definition: {
        '@context': credentialSupported['@context'],
        types: credentialSupported.types,
      },

      proof: { jwt: jws, proof_type: 'jwt' },
    }
  } else if (credentialSupported.format === OpenId4VciCredentialFormatProfile.SdJwtVc) {
    return { ...credentialSupported, proof: { jwt: jws, proof_type: 'jwt' } }
  }

  throw new Error('Unsupported format')
}

const issuer = new Agent({
  config: {
    label: 'OpenId4VcIssuer Test323',
    walletConfig: {
      id: 'openid4vc-Issuer-test323',
      key: 'openid4vc-Issuer-test323',
    },
  },
  dependencies: agentDependencies,
  modules,
})

const holder = new Agent({
  config: {
    label: 'OpenId4VciIssuer(Holder) Test323',
    walletConfig: {
      id: 'openid4vc-Issuer(Holder)-test323',
      key: 'openid4vc-Issuer(Holder)-test323',
    },
  },
  dependencies: agentDependencies,
  modules,
})

describe('OpenId4VcIssuer', () => {
  let issuerVerificationMethod: VerificationMethod
  let issuerDid: string
  let openId4VcIssuer: OpenId4VcIssuerRecord

  let holderKid: string
  let holderVerificationMethod: VerificationMethod
  let holderDid: string

  beforeEach(async () => {
    await issuer.initialize()
    await holder.initialize()

    const holderDidCreateResult = await holder.dids.create<KeyDidCreateOptions>({
      method: 'key',
      options: { keyType: KeyType.Ed25519 },
      secret: { privateKey: TypedArrayEncoder.fromString('96213c3d7fc8d4d6754c7a0fd969598e') },
    })

    holderDid = holderDidCreateResult.didState.did as string
    const holderDidKey = DidKey.fromDid(holderDid)
    holderKid = `${holderDid}#${holderDidKey.key.fingerprint}`
    const _holderVerificationMethod = holderDidCreateResult.didState.didDocument?.dereferenceKey(holderKid, [
      'authentication',
    ])
    if (!_holderVerificationMethod) throw new Error('No verification method found')
    holderVerificationMethod = _holderVerificationMethod

    const issuerDidCreateResult = await issuer.dids.create<KeyDidCreateOptions>({
      method: 'key',
      options: { keyType: KeyType.Ed25519 },
      secret: { privateKey: TypedArrayEncoder.fromString('96213c3d7fc8d4d6754c7a0fd969598f') },
    })

    issuerDid = issuerDidCreateResult.didState.did as string

    const issuerDidKey = DidKey.fromDid(issuerDid)
    const issuerKid = `${issuerDid}#${issuerDidKey.key.fingerprint}`
    const _issuerVerificationMethod = issuerDidCreateResult.didState.didDocument?.dereferenceKey(issuerKid, [
      'authentication',
    ])
    if (!_issuerVerificationMethod) throw new Error('No verification method found')
    issuerVerificationMethod = _issuerVerificationMethod

    openId4VcIssuer = await issuer.modules.openId4VcIssuer.createIssuer({
      credentialsSupported: [
        openBadgeCredential,
        universityDegreeCredential,
        universityDegreeCredentialLd,
        universityDegreeCredentialSdJwt,
      ],
    })
  })

  afterEach(async () => {
    await issuer.shutdown()
    await issuer.wallet.delete()

    await holder.shutdown()
    await holder.wallet.delete()
  })

  // This method is available on the holder service,
  // would be nice to reuse
  async function handleCredentialResponse(
    agentContext: AgentContext,
    sphereonVerifiableCredential: SphereonW3cVerifiableCredential,
    credentialSupported: OpenId4VciCredentialSupportedWithId
  ) {
    if (credentialSupported.format === 'vc+sd-jwt' && typeof sphereonVerifiableCredential === 'string') {
      const api = agentContext.dependencyManager.resolve(SdJwtVcApi)
      await api.verify({ compactSdJwtVc: sphereonVerifiableCredential })
      return
    }

    const w3cCredentialService = holder.context.dependencyManager.resolve(W3cCredentialService)

    let result: W3cVerifyCredentialResult
    let w3cVerifiableCredential: W3cVerifiableCredential

    if (typeof sphereonVerifiableCredential === 'string') {
      if (credentialSupported.format !== 'jwt_vc_json' && credentialSupported.format !== 'jwt_vc_json-ld') {
        throw new Error(`Invalid format. ${credentialSupported.format}`)
      }
      w3cVerifiableCredential = W3cJwtVerifiableCredential.fromSerializedJwt(sphereonVerifiableCredential)
      result = await w3cCredentialService.verifyCredential(holder.context, { credential: w3cVerifiableCredential })
    } else if (credentialSupported.format === 'ldp_vc') {
      if (credentialSupported.format !== 'ldp_vc') throw new Error('Invalid format')
      // validate jwt credentials

      w3cVerifiableCredential = JsonTransformer.fromJSON(sphereonVerifiableCredential, W3cJsonLdVerifiableCredential)
      result = await w3cCredentialService.verifyCredential(holder.context, { credential: w3cVerifiableCredential })
    } else {
      throw new CredoError(`Unsupported credential format`)
    }

    if (!result.isValid) {
      holder.context.config.logger.error('Failed to validate credential', { result })
      throw new CredoError(`Failed to validate credential, error = ${result.error?.message ?? 'Unknown'}`)
    }

    if (equalsIgnoreOrder(w3cVerifiableCredential.type, credentialSupported.types) === false) {
      throw new Error('Invalid credential type')
    }
    return w3cVerifiableCredential
  }

  it('pre authorized code flow (sd-jwt-vc)', async () => {
    const preAuthorizedCode = '1234567890'

    const result = await issuer.modules.openId4VcIssuer.createCredentialOffer({
      issuerId: openId4VcIssuer.issuerId,
      offeredCredentials: [universityDegreeCredentialSdJwt.id],
      preAuthorizedCodeFlowConfig: {
        preAuthorizedCode,
        userPinRequired: false,
      },
    })

    const issuanceSessionRepository = issuer.context.dependencyManager.resolve(OpenId4VcIssuanceSessionRepository)
    result.issuanceSession.cNonce = '1234'
    result.issuanceSession.cNonceExpiresAt = new Date(Date.now() + 30000) // 30 seconds
    await issuanceSessionRepository.update(issuer.context, result.issuanceSession)

    expect(result).toMatchObject({
      credentialOffer: expect.stringMatching(
        new RegExp(
          `^openid-credential-offer://\\?credential_offer_uri=https%3A%2F%2Fopenid4vc-issuer.com%2F${openId4VcIssuer.issuerId}%2Foffers%2F.*$`
        )
      ),
      issuanceSession: {
        credentialOfferPayload: {
          credential_issuer: `https://openid4vc-issuer.com/${openId4VcIssuer.issuerId}`,
          credentials: ['https://openid4vc-issuer.com/credentials/UniversityDegreeCredentialSdJwt'],
          grants: {
            'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
              'pre-authorized_code': '1234567890',
              user_pin_required: false,
            },
          },
        },
      },
    })

    const issuerMetadata = await issuer.modules.openId4VcIssuer.getIssuerMetadata(openId4VcIssuer.issuerId)
    const credentialRequest = await createCredentialRequest(holder.context, {
      credentialSupported: universityDegreeCredentialSdJwt,
      issuerMetadata,
      kid: holderKid,
      nonce: result.issuanceSession.cNonce as string,
    })

    const issuanceSession = await issuer.modules.openId4VcIssuer.findIssuanceSessionForCredentialRequest({
      credentialRequest,
      issuerId: openId4VcIssuer.issuerId,
    })

    if (!issuanceSession) {
      throw new Error('No issuance session found')
    }

    // We need to update the state, as it is checked and we're skipping the access token step
    result.issuanceSession.state = OpenId4VcIssuanceSessionState.AccessTokenCreated
    await issuanceSessionRepository.update(issuer.context, result.issuanceSession)

    const { credentialResponse } = await issuer.modules.openId4VcIssuer.createCredentialResponse({
      issuanceSessionId: issuanceSession.id,
      credentialRequest,

      credentialRequestToCredentialMapper: () => ({
        format: 'vc+sd-jwt',
        payload: { vct: 'UniversityDegreeCredential', university: 'innsbruck', degree: 'bachelor' },
        issuer: { method: 'did', didUrl: issuerVerificationMethod.id },
        holder: { method: 'did', didUrl: holderVerificationMethod.id },
        disclosureFrame: { _sd: ['university', 'degree'] },
        credentialSupportedId: universityDegreeCredentialSdJwt.id,
      }),
    })

    expect(credentialResponse).toEqual({
      c_nonce: expect.any(String),
      c_nonce_expires_in: 300,
      credential: expect.any(String),
      format: 'vc+sd-jwt',
    })

    await handleCredentialResponse(
      holder.context,
      credentialResponse.credential as SphereonW3cVerifiableCredential,
      universityDegreeCredentialSdJwt
    )
  })

  it('pre authorized code flow (jwt-vc-json)', async () => {
    const preAuthorizedCode = '1234567890'

    const result = await issuer.modules.openId4VcIssuer.createCredentialOffer({
      issuerId: openId4VcIssuer.issuerId,
      offeredCredentials: [openBadgeCredential.id],
      preAuthorizedCodeFlowConfig: {
        preAuthorizedCode,
        userPinRequired: false,
      },
      issuanceMetadata: {
        myIssuance: 'metadata',
      },
    })

    const issuanceSessionRepository = issuer.context.dependencyManager.resolve(OpenId4VcIssuanceSessionRepository)
    // We need to update the state, as it is checked and we're skipping the access token step
    result.issuanceSession.cNonce = '1234'
    result.issuanceSession.cNonceExpiresAt = new Date(Date.now() + 30000) // 30 seconds
    result.issuanceSession.state = OpenId4VcIssuanceSessionState.AccessTokenCreated
    await issuanceSessionRepository.update(issuer.context, result.issuanceSession)

    expect(result.credentialOffer).toBeDefined()

    const issuerMetadata = await issuer.modules.openId4VcIssuer.getIssuerMetadata(openId4VcIssuer.issuerId)
    const { credentialResponse } = await issuer.modules.openId4VcIssuer.createCredentialResponse({
      issuanceSessionId: result.issuanceSession.id,
      credentialRequestToCredentialMapper: ({ issuanceSession }) => {
        expect(issuanceSession.id).toEqual(result.issuanceSession.id)
        expect(issuanceSession.issuanceMetadata).toEqual({
          myIssuance: 'metadata',
        })

        return {
          format: 'jwt_vc',
          credentialSupportedId: openBadgeCredential.id,
          credential: new W3cCredential({
            type: openBadgeCredential.types,
            issuer: new W3cIssuer({ id: issuerDid }),
            credentialSubject: new W3cCredentialSubject({ id: holderDid }),
            issuanceDate: w3cDate(Date.now()),
          }),
          verificationMethod: issuerVerificationMethod.id,
        }
      },
      credentialRequest: await createCredentialRequest(holder.context, {
        credentialSupported: openBadgeCredential,
        issuerMetadata,
        kid: holderKid,
        nonce: result.issuanceSession.cNonce as string,
      }),
    })

    expect(credentialResponse).toEqual({
      c_nonce: expect.any(String),
      c_nonce_expires_in: 300,
      credential: expect.any(String),
      format: 'jwt_vc_json',
    })

    await handleCredentialResponse(
      holder.context,
      credentialResponse.credential as SphereonW3cVerifiableCredential,
      openBadgeCredential
    )
  })

  it('credential id not in credential supported errors', async () => {
    const preAuthorizedCode = '1234567890'

    await expect(
      issuer.modules.openId4VcIssuer.createCredentialOffer({
        issuerId: openId4VcIssuer.issuerId,
        offeredCredentials: ['invalid id'],
        preAuthorizedCodeFlowConfig: {
          preAuthorizedCode,
          userPinRequired: false,
        },
      })
    ).rejects.toThrow("Offered credential 'invalid id' is not part of credentials_supported of the issuer metadata.")
  })

  it('issuing non offered credential errors', async () => {
    const preAuthorizedCode = '1234567890'

    const result = await issuer.modules.openId4VcIssuer.createCredentialOffer({
      issuerId: openId4VcIssuer.issuerId,
      offeredCredentials: [openBadgeCredential.id],
      preAuthorizedCodeFlowConfig: {
        preAuthorizedCode,
        userPinRequired: false,
      },
    })

    const issuanceSessionRepository = issuer.context.dependencyManager.resolve(OpenId4VcIssuanceSessionRepository)
    // We need to update the state, as it is checked and we're skipping the access token step
    result.issuanceSession.state = OpenId4VcIssuanceSessionState.AccessTokenCreated
    result.issuanceSession.cNonce = '1234'
    result.issuanceSession.cNonceExpiresAt = new Date(Date.now() + 30000) // 30 seconds
    await issuanceSessionRepository.update(issuer.context, result.issuanceSession)

    const issuerMetadata = await issuer.modules.openId4VcIssuer.getIssuerMetadata(openId4VcIssuer.issuerId)
    await expect(
      issuer.modules.openId4VcIssuer.createCredentialResponse({
        issuanceSessionId: result.issuanceSession.id,
        credentialRequest: await createCredentialRequest(holder.context, {
          credentialSupported: universityDegreeCredential,
          issuerMetadata,
          kid: holderKid,
          nonce: result.issuanceSession.cNonce as string,
        }),
        credentialRequestToCredentialMapper: () => {
          throw new Error('Not implemented')
        },
      })
    ).rejects.toThrow('No offered credentials match the credential request.')
  })

  it('pre authorized code flow using multiple credentials_supported', async () => {
    const preAuthorizedCode = '1234567890'

    const result = await issuer.modules.openId4VcIssuer.createCredentialOffer({
      offeredCredentials: [openBadgeCredential.id, universityDegreeCredentialLd.id],
      issuerId: openId4VcIssuer.issuerId,
      preAuthorizedCodeFlowConfig: {
        preAuthorizedCode,
        userPinRequired: false,
      },
    })

    const issuanceSessionRepository = issuer.context.dependencyManager.resolve(OpenId4VcIssuanceSessionRepository)
    // We need to update the state, as it is checked and we're skipping the access token step
    result.issuanceSession.cNonce = '1234'
    result.issuanceSession.cNonceExpiresAt = new Date(Date.now() + 30000) // 30 seconds
    result.issuanceSession.state = OpenId4VcIssuanceSessionState.AccessTokenCreated
    await issuanceSessionRepository.update(issuer.context, result.issuanceSession)

    const issuerMetadata = await issuer.modules.openId4VcIssuer.getIssuerMetadata(openId4VcIssuer.issuerId)
    const { credentialResponse } = await issuer.modules.openId4VcIssuer.createCredentialResponse({
      issuanceSessionId: result.issuanceSession.id,
      credentialRequest: await createCredentialRequest(holder.context, {
        credentialSupported: universityDegreeCredentialLd,
        issuerMetadata,
        kid: holderKid,
        nonce: result.issuanceSession.cNonce as string,
      }),
      credentialRequestToCredentialMapper: () => ({
        format: 'jwt_vc',
        credential: new W3cCredential({
          type: universityDegreeCredentialLd.types,
          issuer: new W3cIssuer({ id: issuerDid }),
          credentialSubject: new W3cCredentialSubject({ id: holderDid }),
          issuanceDate: w3cDate(Date.now()),
        }),
        credentialSupportedId: universityDegreeCredentialLd.id,
        verificationMethod: issuerVerificationMethod.id,
      }),
    })

    expect(credentialResponse).toEqual({
      c_nonce: expect.any(String),
      c_nonce_expires_in: 300,
      credential: expect.any(String),
      format: 'jwt_vc_json-ld',
    })

    await handleCredentialResponse(
      holder.context,
      credentialResponse.credential as SphereonW3cVerifiableCredential,
      universityDegreeCredentialLd
    )
  })

  it('requesting non offered credential errors', async () => {
    const preAuthorizedCode = '1234567890'

    const result = await issuer.modules.openId4VcIssuer.createCredentialOffer({
      offeredCredentials: [openBadgeCredential.id],
      issuerId: openId4VcIssuer.issuerId,
      preAuthorizedCodeFlowConfig: {
        preAuthorizedCode,
        userPinRequired: false,
      },
    })

    const issuanceSessionRepository = issuer.context.dependencyManager.resolve(OpenId4VcIssuanceSessionRepository)
    // We need to update the state, as it is checked and we're skipping the access token step
    result.issuanceSession.state = OpenId4VcIssuanceSessionState.AccessTokenCreated
    result.issuanceSession.cNonce = '1234'
    result.issuanceSession.cNonceExpiresAt = new Date(Date.now() + 30000) // 30 seconds
    await issuanceSessionRepository.update(issuer.context, result.issuanceSession)

    const issuerMetadata = await issuer.modules.openId4VcIssuer.getIssuerMetadata(openId4VcIssuer.issuerId)
    await expect(
      issuer.modules.openId4VcIssuer.createCredentialResponse({
        issuanceSessionId: result.issuanceSession.id,
        credentialRequest: await createCredentialRequest(holder.context, {
          credentialSupported: {
            id: 'someid',
            format: openBadgeCredential.format,
            types: universityDegreeCredential.types,
          },
          issuerMetadata,
          kid: holderKid,
          nonce: result.issuanceSession.cNonce as string,
        }),
        credentialRequestToCredentialMapper: () => {
          throw new Error('Not implemented')
        },
      })
    ).rejects.toThrow('No offered credentials match the credential request.')
  })

  it('create credential offer and retrieve it from the uri (pre authorized flow)', async () => {
    const preAuthorizedCode = '1234567890'

    const { credentialOffer } = await issuer.modules.openId4VcIssuer.createCredentialOffer({
      issuerId: openId4VcIssuer.issuerId,
      offeredCredentials: [openBadgeCredential.id],
      preAuthorizedCodeFlowConfig: {
        preAuthorizedCode,
        userPinRequired: false,
      },
    })

    expect(credentialOffer).toMatch(
      new RegExp(
        `^openid-credential-offer://\\?credential_offer_uri=https%3A%2F%2Fopenid4vc-issuer.com%2F${openId4VcIssuer.issuerId}%2Foffers%2F.*$`
      )
    )
  })

  it('offer and request multiple credentials', async () => {
    const preAuthorizedCode = '1234567890'

    const result = await issuer.modules.openId4VcIssuer.createCredentialOffer({
      offeredCredentials: [openBadgeCredential.id, universityDegreeCredential.id],
      issuerId: openId4VcIssuer.issuerId,
      preAuthorizedCodeFlowConfig: {
        preAuthorizedCode,
        userPinRequired: false,
      },
    })

    const issuanceSessionRepository = issuer.context.dependencyManager.resolve(OpenId4VcIssuanceSessionRepository)
    result.issuanceSession.cNonce = '1234'
    result.issuanceSession.cNonceExpiresAt = new Date(Date.now() + 30000) // 30 seconds
    await issuanceSessionRepository.update(issuer.context, result.issuanceSession)

    expect(result.issuanceSession.credentialOfferPayload?.credentials).toEqual([
      openBadgeCredential.id,
      universityDegreeCredential.id,
    ])

    const credentialRequestToCredentialMapper: OpenId4VciCredentialRequestToCredentialMapper = ({
      credentialsSupported,
    }) => {
      const credential =
        credentialsSupported[0].id === openBadgeCredential.id ? openBadgeCredential : universityDegreeCredential
      return {
        format: 'jwt_vc',
        credential: new W3cCredential({
          type: credential.types,
          issuer: new W3cIssuer({ id: issuerDid }),
          credentialSubject: new W3cCredentialSubject({ id: holderDid }),
          issuanceDate: w3cDate(Date.now()),
        }),
        credentialSupportedId: credential.id,

        verificationMethod: issuerVerificationMethod.id,
      }
    }

    // We need to update the state, as it is checked and we're skipping the access token step
    result.issuanceSession.state = OpenId4VcIssuanceSessionState.AccessTokenCreated
    await issuanceSessionRepository.update(issuer.context, result.issuanceSession)

    const issuerMetadata = await issuer.modules.openId4VcIssuer.getIssuerMetadata(openId4VcIssuer.issuerId)
    const { credentialResponse } = await issuer.modules.openId4VcIssuer.createCredentialResponse({
      issuanceSessionId: result.issuanceSession.id,
      credentialRequest: await createCredentialRequest(holder.context, {
        credentialSupported: openBadgeCredential,
        issuerMetadata,
        kid: holderKid,
        nonce: result.issuanceSession.cNonce as string,
      }),
      credentialRequestToCredentialMapper,
    })

    expect(credentialResponse).toEqual({
      c_nonce: expect.any(String),
      c_nonce_expires_in: 300,
      credential: expect.any(String),
      format: 'jwt_vc_json',
    })

    await handleCredentialResponse(
      holder.context,
      credentialResponse.credential as SphereonW3cVerifiableCredential,
      openBadgeCredential
    )

    const { credentialResponse: credentialResponse2 } = await issuer.modules.openId4VcIssuer.createCredentialResponse({
      issuanceSessionId: result.issuanceSession.id,
      credentialRequest: await createCredentialRequest(holder.context, {
        credentialSupported: universityDegreeCredential,
        issuerMetadata,
        kid: holderKid,
        nonce: credentialResponse.c_nonce ?? (result.issuanceSession.cNonce as string),
      }),
      credentialRequestToCredentialMapper,
    })

    expect(credentialResponse2).toEqual({
      c_nonce: expect.any(String),
      c_nonce_expires_in: 300,
      credential: expect.any(String),
      format: 'jwt_vc_json',
    })

    await handleCredentialResponse(
      holder.context,
      credentialResponse2.credential as SphereonW3cVerifiableCredential,
      universityDegreeCredential
    )
  })
})
