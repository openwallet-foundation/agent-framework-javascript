import type {
  OpenId4VcSiopAcceptAuthorizationRequestOptions,
  OpenId4VcSiopResolvedAuthorizationRequest,
} from './OpenId4vcSiopHolderServiceOptions'
import type { OpenId4VcJwtIssuer } from '../shared'
import type { AgentContext, JwkJson, VerifiablePresentation } from '@credo-ts/core'
import type {
  AuthorizationResponsePayload,
  PresentationExchangeResponseOpts,
  DcqlQueryResponseOpts,
  RequestObjectPayload,
  VerifiedAuthorizationRequest,
} from '@sphereon/did-auth-siop'

import {
  Buffer,
  CredoError,
  DifPresentationExchangeService,
  DifPresentationExchangeSubmissionLocation,
  Hasher,
  KeyType,
  TypedArrayEncoder,
  W3cJsonLdVerifiablePresentation,
  W3cJwtVerifiablePresentation,
  asArray,
  getJwkFromJson,
  injectable,
  parseDid,
  MdocDeviceResponse,
  DcqlService,
} from '@credo-ts/core'
import { OP, ResponseIss, ResponseMode, ResponseType, SupportedVersion, VPTokenLocation } from '@sphereon/did-auth-siop'

import { getSphereonVerifiablePresentation } from '../shared/transform'
import { getCreateJwtCallback, getVerifyJwtCallback, openIdTokenIssuerToJwtIssuer } from '../shared/utils'

@injectable()
export class OpenId4VcSiopHolderService {
  public constructor(
    private presentationExchangeService: DifPresentationExchangeService,
    private dcqlService: DcqlService
  ) {}

  public async resolveAuthorizationRequest(
    agentContext: AgentContext,
    requestJwtOrUri: string
  ): Promise<OpenId4VcSiopResolvedAuthorizationRequest> {
    const openidProvider = await this.getOpenIdProvider(agentContext)

    // parsing happens automatically in verifyAuthorizationRequest
    const verifiedAuthorizationRequest = await openidProvider.verifyAuthorizationRequest(requestJwtOrUri)

    agentContext.config.logger.debug(
      `verified SIOP Authorization Request for issuer '${verifiedAuthorizationRequest.issuer}'`
    )
    agentContext.config.logger.debug(`requestJwtOrUri '${requestJwtOrUri}'`)

    if (
      verifiedAuthorizationRequest.presentationDefinitions &&
      verifiedAuthorizationRequest.presentationDefinitions.length > 1
    ) {
      throw new CredoError('Only a single presentation definition is supported.')
    }

    const presentationDefinition = verifiedAuthorizationRequest.presentationDefinitions?.[0]?.definition
    const dcqlQuery = verifiedAuthorizationRequest.dcqlQuery

    return {
      authorizationRequest: verifiedAuthorizationRequest,

      // Parameters related to DIF Presentation Exchange
      presentationExchange: presentationDefinition
        ? {
            definition: presentationDefinition,
            credentialsForRequest: await this.presentationExchangeService.getCredentialsForRequest(
              agentContext,
              presentationDefinition
            ),
          }
        : undefined,

      dcql: dcqlQuery
        ? {
            queryResult: await this.dcqlService.getCredentialsForRequest(agentContext, dcqlQuery),
          }
        : undefined,
    }
  }

  public async acceptAuthorizationRequest(
    agentContext: AgentContext,
    options: OpenId4VcSiopAcceptAuthorizationRequestOptions
  ) {
    const { authorizationRequest, presentationExchange, dcql } = options
    let openIdTokenIssuer = options.openIdTokenIssuer
    let presentationExchangeOptions: PresentationExchangeResponseOpts | undefined = undefined
    let dcqlOptions: DcqlQueryResponseOpts | undefined = undefined

    const wantsIdToken = await authorizationRequest.authorizationRequest.containsResponseType(ResponseType.ID_TOKEN)
    const authorizationResponseNonce = await agentContext.wallet.generateNonce()

    if (
      (authorizationRequest.presentationDefinitions && authorizationRequest.presentationDefinitions.length > 0) ||
      authorizationRequest.dcqlQuery
    ) {
      const nonce = await authorizationRequest.authorizationRequest.getMergedProperty<string>('nonce')
      if (!nonce) {
        throw new CredoError("Unable to extract 'nonce' from authorization request")
      }

      const clientId = await authorizationRequest.authorizationRequest.getMergedProperty<string>('client_id')
      if (!clientId) {
        throw new CredoError("Unable to extract 'client_id' from authorization request")
      }

      const responseUri =
        (await authorizationRequest.authorizationRequest.getMergedProperty<string>('response_uri')) ??
        (await authorizationRequest.authorizationRequest.getMergedProperty<string>('redirect_uri'))
      if (!responseUri) {
        throw new CredoError("Unable to extract 'response_uri' from authorization request")
      }

      if (authorizationRequest.dcqlQuery) {
        if (!dcql) {
          throw new CredoError(
            'Authorization request included dcql query. `dcql` MUST be supplied to accept authorization requests.'
          )
        }

        const dcqlPresentation = await this.dcqlService.createPresentation(agentContext, {
          credentialQueryToCredential: dcql.credentials,
          challenge: nonce,
          domain: clientId,
          openid4vp: {
            mdocGeneratedNonce: authorizationResponseNonce,
            responseUri,
          },
        })

        dcqlOptions = {
          dcqlPresentation: this.dcqlService.getEncodedPresentations(dcqlPresentation),
        }

        if (wantsIdToken && !openIdTokenIssuer) {
          const nonMdocPresentation = Object.values(dcqlPresentation).find(
            (presentation) => presentation instanceof MdocDeviceResponse === false
          )

          if (nonMdocPresentation) {
            openIdTokenIssuer = this.getOpenIdTokenIssuerFromVerifiablePresentation(nonMdocPresentation)
          }
        }
      } else if (
        authorizationRequest.presentationDefinitions &&
        authorizationRequest.presentationDefinitions.length > 0
      ) {
        if (!presentationExchange) {
          throw new CredoError(
            'Authorization request included presentation definition. `presentationExchange` MUST be supplied to accept authorization requests.'
          )
        }

        const { verifiablePresentations, presentationSubmission } =
          await this.presentationExchangeService.createPresentation(agentContext, {
            credentialsForInputDescriptor: presentationExchange.credentials,
            presentationDefinition: authorizationRequest.presentationDefinitions[0].definition,
            challenge: nonce,
            domain: clientId,
            presentationSubmissionLocation: DifPresentationExchangeSubmissionLocation.EXTERNAL,
            openid4vp: {
              mdocGeneratedNonce: authorizationResponseNonce,
              responseUri,
            },
          })

        if (wantsIdToken && !openIdTokenIssuer) {
          openIdTokenIssuer = this.getOpenIdTokenIssuerFromVerifiablePresentation(verifiablePresentations[0])
        }

        presentationExchangeOptions = {
          verifiablePresentations: verifiablePresentations.map((vp) => getSphereonVerifiablePresentation(vp)),
          presentationSubmission,
          vpTokenLocation: VPTokenLocation.AUTHORIZATION_RESPONSE,
        }
      }
    } else if (options.presentationExchange) {
      throw new CredoError(
        '`presentationExchange` was supplied, but no presentation definition was found in the presentation request.'
      )
    } else if (options.dcql) {
      throw new CredoError('`dcql` was supplied, but no dcql_query was found in the presentation request.')
    }

    if (wantsIdToken) {
      if (!openIdTokenIssuer) {
        throw new CredoError(
          'Unable to create authorization response. openIdTokenIssuer MUST be supplied when no presentation is active and the ResponseType includes id_token.'
        )
      }

      this.assertValidTokenIssuer(authorizationRequest, openIdTokenIssuer)
    }

    const jwtIssuer =
      wantsIdToken && openIdTokenIssuer
        ? await openIdTokenIssuerToJwtIssuer(agentContext, openIdTokenIssuer)
        : undefined

    const openidProvider = await this.getOpenIdProvider(agentContext)
    const authorizationResponseWithCorrelationId = await openidProvider.createAuthorizationResponse(
      authorizationRequest,
      {
        jwtIssuer,
        presentationExchange: presentationExchangeOptions,
        dcqlQuery: dcqlOptions,
        // https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#name-aud-of-a-request-object
        audience: authorizationRequest.authorizationRequestPayload.client_id,
      }
    )

    const getCreateJarmResponseCallback = (authorizationResponseNonce: string) => {
      return async (opts: {
        authorizationResponsePayload: AuthorizationResponsePayload
        requestObjectPayload: RequestObjectPayload
      }) => {
        const { authorizationResponsePayload, requestObjectPayload } = opts

        const jwk = await OP.extractEncJwksFromClientMetadata(requestObjectPayload.client_metadata)
        if (!jwk.kty) {
          throw new CredoError('Missing kty in jwk.')
        }

        const validatedMetadata = OP.validateJarmMetadata({
          client_metadata: requestObjectPayload.client_metadata,
          server_metadata: {
            authorization_encryption_alg_values_supported: ['ECDH-ES'],
            authorization_encryption_enc_values_supported: ['A256GCM'],
          },
        })

        if (validatedMetadata.type !== 'encrypted') {
          throw new CredoError('Only encrypted JARM responses are supported.')
        }

        // Extract nonce from the request, we use this as the `apv`
        const nonce = authorizationRequest.payload?.nonce
        if (!nonce || typeof nonce !== 'string') {
          throw new CredoError('Missing nonce in authorization request payload')
        }

        const jwe = await this.encryptJarmResponse(agentContext, {
          jwkJson: jwk as JwkJson,
          payload: authorizationResponsePayload,
          authorizationRequestNonce: nonce,
          alg: validatedMetadata.client_metadata.authorization_encrypted_response_alg,
          enc: validatedMetadata.client_metadata.authorization_encrypted_response_enc,
          authorizationResponseNonce,
        })

        return { response: jwe }
      }
    }
    const response = await openidProvider.submitAuthorizationResponse(
      authorizationResponseWithCorrelationId,
      getCreateJarmResponseCallback(authorizationResponseNonce)
    )
    const responseText = await response
      .clone()
      .text()
      .catch(() => null)
    const responseJson = (await response
      .clone()
      .json()
      .catch(() => null)) as null | Record<string, unknown>

    if (!response.ok) {
      return {
        ok: false,
        serverResponse: {
          status: response.status,
          body: responseJson ?? responseText,
        },
        submittedResponse: authorizationResponseWithCorrelationId.response.payload,
      } as const
    }

    return {
      ok: true,
      serverResponse: {
        status: response.status,
        body: responseJson ?? {},
      },
      submittedResponse: authorizationResponseWithCorrelationId.response.payload,

      redirectUri: responseJson?.redirect_uri as string | undefined,
      presentationDuringIssuanceSession: responseJson?.presentation_during_issuance_session as string | undefined,
    } as const
  }

  private async getOpenIdProvider(agentContext: AgentContext) {
    const builder = OP.builder()
      .withExpiresIn(6000)
      .withIssuer(ResponseIss.SELF_ISSUED_V2)
      .withResponseMode(ResponseMode.POST)
      .withSupportedVersions([
        SupportedVersion.SIOPv2_D11,
        SupportedVersion.SIOPv2_D12_OID4VP_D18,
        SupportedVersion.SIOPv2_D12_OID4VP_D20,
      ])
      .withCreateJwtCallback(getCreateJwtCallback(agentContext))
      .withVerifyJwtCallback(getVerifyJwtCallback(agentContext))
      .withHasher(Hasher.hash)

    const openidProvider = builder.build()

    return openidProvider
  }

  private getOpenIdTokenIssuerFromVerifiablePresentation(
    verifiablePresentation: VerifiablePresentation
  ): OpenId4VcJwtIssuer {
    let openIdTokenIssuer: OpenId4VcJwtIssuer

    if (verifiablePresentation instanceof W3cJsonLdVerifiablePresentation) {
      const [firstProof] = asArray(verifiablePresentation.proof)
      if (!firstProof) throw new CredoError('Verifiable presentation does not contain a proof')

      if (!firstProof.verificationMethod.startsWith('did:')) {
        throw new CredoError(
          'Verifiable presentation proof verificationMethod is not a did. Unable to extract openIdTokenIssuer from verifiable presentation'
        )
      }

      openIdTokenIssuer = {
        method: 'did',
        didUrl: firstProof.verificationMethod,
      }
    } else if (verifiablePresentation instanceof W3cJwtVerifiablePresentation) {
      const kid = verifiablePresentation.jwt.header.kid

      if (!kid) throw new CredoError('Verifiable Presentation does not contain a kid in the jwt header')
      if (kid.startsWith('#') && verifiablePresentation.presentation.holderId) {
        openIdTokenIssuer = {
          didUrl: `${verifiablePresentation.presentation.holderId}${kid}`,
          method: 'did',
        }
      } else if (kid.startsWith('did:')) {
        openIdTokenIssuer = {
          didUrl: kid,
          method: 'did',
        }
      } else {
        throw new CredoError(
          "JWT W3C Verifiable presentation does not include did in JWT header 'kid'. Unable to extract openIdTokenIssuer from verifiable presentation"
        )
      }
    } else if (verifiablePresentation instanceof MdocDeviceResponse) {
      throw new CredoError('Mdoc Verifiable Presentations are not yet supported')
    } else {
      const cnf = verifiablePresentation.payload.cnf
      // FIXME: SD-JWT VC should have better payload typing, so this doesn't become so ugly
      if (
        !cnf ||
        typeof cnf !== 'object' ||
        !('kid' in cnf) ||
        typeof cnf.kid !== 'string' ||
        !cnf.kid.startsWith('did:') ||
        !cnf.kid.includes('#')
      ) {
        throw new CredoError(
          "SD-JWT Verifiable presentation has no 'cnf' claim or does not include 'cnf' claim where 'kid' is a didUrl pointing to a key. Unable to extract openIdTokenIssuer from verifiable presentation"
        )
      }

      openIdTokenIssuer = {
        didUrl: cnf.kid,
        method: 'did',
      }
    }

    return openIdTokenIssuer
  }

  private assertValidTokenIssuer(
    authorizationRequest: VerifiedAuthorizationRequest,
    openIdTokenIssuer: OpenId4VcJwtIssuer
  ) {
    const subjectSyntaxTypesSupported = authorizationRequest.registrationMetadataPayload.subject_syntax_types_supported
    if (!subjectSyntaxTypesSupported) {
      throw new CredoError(
        'subject_syntax_types_supported is not supplied in the registration metadata. subject_syntax_types is REQUIRED.'
      )
    }

    let allowedSubjectSyntaxTypes: string[] = []
    if (openIdTokenIssuer.method === 'did') {
      const parsedDid = parseDid(openIdTokenIssuer.didUrl)

      // Either did:<method> or did (for all did methods) is allowed
      allowedSubjectSyntaxTypes = [`did:${parsedDid.method}`, 'did']
    } else if (openIdTokenIssuer.method === 'jwk') {
      allowedSubjectSyntaxTypes = ['urn:ietf:params:oauth:jwk-thumbprint']
    } else {
      throw new CredoError("Only 'did' and 'jwk' are supported as openIdTokenIssuer at the moment")
    }

    // At least one of the allowed subject syntax types must be supported by the RP
    if (!allowedSubjectSyntaxTypes.some((allowed) => subjectSyntaxTypesSupported.includes(allowed))) {
      throw new CredoError(
        [
          'The provided openIdTokenIssuer is not supported by the relying party.',
          `Supported subject syntax types: '${subjectSyntaxTypesSupported.join(', ')}'`,
        ].join('\n')
      )
    }
  }

  private async encryptJarmResponse(
    agentContext: AgentContext,
    options: {
      jwkJson: JwkJson
      payload: Record<string, unknown>
      alg: string
      enc: string
      authorizationRequestNonce: string
      authorizationResponseNonce: string
    }
  ) {
    const { payload, jwkJson } = options
    const jwk = getJwkFromJson(jwkJson)
    const key = jwk.key

    if (!agentContext.wallet.directEncryptCompactJweEcdhEs) {
      throw new CredoError(
        'Cannot decrypt Jarm Response, wallet does not support directEncryptCompactJweEcdhEs. You need to upgrade your wallet implementation.'
      )
    }

    if (options.alg !== 'ECDH-ES') {
      throw new CredoError("Only 'ECDH-ES' is supported as 'alg' value for JARM response encryption")
    }

    if (options.enc !== 'A256GCM') {
      throw new CredoError("Only 'A256GCM' is supported as 'enc' value for JARM response encryption")
    }

    if (key.keyType !== KeyType.P256) {
      throw new CredoError(`Only '${KeyType.P256}' key type is supported for JARM response encryption`)
    }

    const data = Buffer.from(JSON.stringify(payload))
    const jwe = await agentContext.wallet.directEncryptCompactJweEcdhEs({
      data,
      recipientKey: key,
      header: {
        kid: jwkJson.kid,
      },
      encryptionAlgorithm: options.enc,
      apu: TypedArrayEncoder.toBase64URL(TypedArrayEncoder.fromString(options.authorizationResponseNonce)),
      apv: TypedArrayEncoder.toBase64URL(TypedArrayEncoder.fromString(options.authorizationRequestNonce)),
    })

    return jwe
  }
}
