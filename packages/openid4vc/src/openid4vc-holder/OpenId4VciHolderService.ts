import type {
  OpenId4VciAcceptCredentialOfferOptions,
  OpenId4VciAuthCodeFlowOptions,
  OpenId4VciCredentialBindingResolver,
  OpenId4VciCredentialResponse,
  OpenId4VciDpopRequestOptions,
  OpenId4VciNotificationEvent,
  OpenId4VciProofOfPossessionRequirements,
  OpenId4VciResolvedAuthorizationRequest,
  OpenId4VciResolvedCredentialOffer,
  OpenId4VciRetrieveAuthorizationCodeUsingPresentationOptions,
  OpenId4VciSupportedCredentialFormats,
  OpenId4VciTokenRequestOptions,
} from './OpenId4VciHolderServiceOptions'
import type {
  OpenId4VciCredentialConfigurationSupported,
  OpenId4VciCredentialIssuerMetadata,
  OpenId4VciMetadata,
} from '../shared'
import type { AgentContext, JwaSignatureAlgorithm, KeyType } from '@credo-ts/core'

import {
  getAuthorizationServerMetadataFromList,
  JwtSigner,
  Oauth2Client,
  preAuthorizedCodeGrantIdentifier,
  RequestDpopOptions,
} from '@animo-id/oauth2'
import {
  AuthorizationFlow,
  CredentialResponse,
  IssuerMetadataResult,
  Oid4vciClient,
  Oid4vciRetrieveCredentialsError,
} from '@animo-id/oid4vci'
import {
  CredoError,
  InjectionSymbols,
  Jwk,
  JwsService,
  Logger,
  Mdoc,
  MdocApi,
  SdJwtVcApi,
  SignatureSuiteRegistry,
  W3cCredentialService,
  W3cJsonLdVerifiableCredential,
  W3cJwtVerifiableCredential,
  getJwkClassFromJwaSignatureAlgorithm,
  getJwkFromJson,
  getJwkFromKey,
  getSupportedVerificationMethodTypesFromKeyType,
  inject,
  injectable,
  parseDid,
} from '@credo-ts/core'

import { OpenId4VciCredentialFormatProfile } from '../shared'
import { getOid4vciCallbacks } from '../shared/callbacks'
import { getOfferedCredentials, getScopesFromCredentialConfigurationsSupported } from '../shared/issuerMetadataUtils'
import { getKeyFromDid, getSupportedJwaSignatureAlgorithms } from '../shared/utils'

import { openId4VciSupportedCredentialFormats } from './OpenId4VciHolderServiceOptions'

@injectable()
export class OpenId4VciHolderService {
  private logger: Logger
  private w3cCredentialService: W3cCredentialService
  private jwsService: JwsService

  public constructor(
    @inject(InjectionSymbols.Logger) logger: Logger,
    w3cCredentialService: W3cCredentialService,
    jwsService: JwsService
  ) {
    this.w3cCredentialService = w3cCredentialService
    this.jwsService = jwsService
    this.logger = logger
  }

  public async resolveIssuerMetadata(
    agentContext: AgentContext,
    credentialIssuer: string
  ): Promise<OpenId4VciMetadata> {
    const client = this.getClient(agentContext)

    const metadata = await client.resolveIssuerMetadata(credentialIssuer)
    this.logger.debug('fetched credential issuer metadata', { metadata })

    return metadata
  }

  public async resolveCredentialOffer(
    agentContext: AgentContext,
    credentialOffer: string
  ): Promise<OpenId4VciResolvedCredentialOffer> {
    const client = this.getClient(agentContext)

    const credentialOfferObject = await client.resolveCredentialOffer(credentialOffer)
    const metadata = await client.resolveIssuerMetadata(credentialOfferObject.credential_issuer)
    this.logger.debug('fetched credential offer and issuer metadata', { metadata, credentialOfferObject })

    const credentialConfigurationsSupported = getOfferedCredentials(
      credentialOfferObject.credential_configuration_ids,
      client.getKnownCredentialConfigurationsSupported(metadata.credentialIssuer)
    )

    return {
      metadata,
      offeredCredentialConfigurations: credentialConfigurationsSupported,
      credentialOfferPayload: credentialOfferObject,
    }
  }

  public async resolveAuthorizationRequest(
    agentContext: AgentContext,
    resolvedCredentialOffer: OpenId4VciResolvedCredentialOffer,
    authCodeFlowOptions: OpenId4VciAuthCodeFlowOptions
  ): Promise<OpenId4VciResolvedAuthorizationRequest> {
    const { clientId, redirectUri } = authCodeFlowOptions
    const { metadata, credentialOfferPayload, offeredCredentialConfigurations } = resolvedCredentialOffer

    const client = this.getClient(agentContext)

    // If scope is not provided, we request scope for all offered credentials
    const scope =
      authCodeFlowOptions.scope ?? getScopesFromCredentialConfigurationsSupported(offeredCredentialConfigurations)

    const authorizationResult = await client.initiateAuthorization({
      clientId,
      issuerMetadata: metadata,
      credentialOffer: credentialOfferPayload,
      scope: scope.join(' '),
      redirectUri,
    })

    if (authorizationResult.authorizationFlow === AuthorizationFlow.PresentationDuringIssuance) {
      return {
        authorizationFlow: AuthorizationFlow.PresentationDuringIssuance,
        oid4vpRequestUrl: authorizationResult.oid4vpRequestUrl,
        authSession: authorizationResult.authSession,
      }
    }

    // Normal Oauth2Redirect flow
    return {
      authorizationFlow: AuthorizationFlow.Oauth2Redirect,
      codeVerifier: authorizationResult.pkce?.codeVerifier,
      authorizationRequestUrl: authorizationResult.authorizationRequestUrl,
    }
  }

  public async sendNotification(
    agentContext: AgentContext,
    options: {
      metadata: IssuerMetadataResult
      notificationId: string
      notificationEvent: OpenId4VciNotificationEvent
      accessToken: string
      dpop?: { jwk: Jwk; alg: JwaSignatureAlgorithm; nonce?: string }
    }
  ) {
    const client = this.getClient(agentContext)
    await client.sendNotification({
      accessToken: options.accessToken,
      dpop: options.dpop
        ? await this.getDpopOptions(agentContext, {
            ...options.dpop,
            dpopSigningAlgValuesSupported: [options.dpop.alg],
          })
        : undefined,
      issuerMetadata: options.metadata,
      notification: {
        event: options.notificationEvent,
        notificationId: options.notificationId,
      },
    })
  }

  private async getDpopOptions(
    agentContext: AgentContext,
    {
      jwk,
      dpopSigningAlgValuesSupported,
      nonce,
    }: { dpopSigningAlgValuesSupported: string[]; jwk?: Jwk; nonce?: string }
  ): Promise<RequestDpopOptions> {
    if (jwk) {
      const alg = dpopSigningAlgValuesSupported.find((alg) =>
        jwk.supportedSignatureAlgorithms.includes(alg as JwaSignatureAlgorithm)
      )

      if (!alg) {
        throw new CredoError(
          `No supported dpop signature algorithms found in dpop_signing_alg_values_supported '${dpopSigningAlgValuesSupported.join(
            ', '
          )}' matching key type ${jwk.keyType}`
        )
      }

      return {
        signer: {
          method: 'jwk',
          alg,
          publicJwk: jwk.toJson(),
        },
        nonce,
      }
    }

    const alg = dpopSigningAlgValuesSupported.find((alg) => getJwkClassFromJwaSignatureAlgorithm(alg))
    const JwkClass = alg ? getJwkClassFromJwaSignatureAlgorithm(alg) : undefined

    if (!alg || !JwkClass) {
      throw new CredoError(
        `No supported dpop signature algorithms found in dpop_signing_alg_values_supported '${dpopSigningAlgValuesSupported.join(
          ', '
        )}'`
      )
    }

    const key = await agentContext.wallet.createKey({ keyType: JwkClass.keyType })
    return {
      signer: {
        method: 'jwk',
        alg,
        publicJwk: getJwkFromKey(key).toJson(),
      },
      nonce,
    }
  }

  public async retrieveAuthorizationCodeUsingPresentation(
    agentContext: AgentContext,
    options: OpenId4VciRetrieveAuthorizationCodeUsingPresentationOptions
  ) {
    const client = this.getClient(agentContext)
    // TODO: support dpop on this endpoint as well
    // const dpop = options.dpop
    //   ? await this.getDpopOptions(agentContext, {
    //       ...options.dpop,
    //       dpopSigningAlgValuesSupported: [options.dpop.alg],
    //     })
    //   : undefined

    // TODO: we should support DPoP in this request as well
    const { authorizationChallengeResponse } = await client.retrieveAuthorizationCodeUsingPresentation({
      authSession: options.authSession,
      presentationDuringIssuanceSession: options.presentationDuringIssuanceSession,
      credentialOffer: options.resolvedCredentialOffer.credentialOfferPayload,
      issuerMetadata: options.resolvedCredentialOffer.metadata,
      // dpop
    })

    return {
      authorizationCode: authorizationChallengeResponse.authorization_code,
    }
  }

  public async requestAccessToken(agentContext: AgentContext, options: OpenId4VciTokenRequestOptions) {
    const { metadata, credentialOfferPayload } = options.resolvedCredentialOffer
    const client = this.getClient(agentContext)
    const oauth2Client = this.getOauth2Client(agentContext)

    const authorizationServer = options.code
      ? credentialOfferPayload.grants?.authorization_code?.authorization_server
      : credentialOfferPayload.grants?.[preAuthorizedCodeGrantIdentifier]?.authorization_server
    const authorizationServerMetadata = getAuthorizationServerMetadataFromList(
      metadata.authorizationServers,
      authorizationServer ?? metadata.authorizationServers[0].issuer
    )

    // TODO: should allow dpop input parameter for if it was already bound earlier
    const isDpopSupported = oauth2Client.isDpopSupported({
      authorizationServerMetadata,
    })
    const dpop = isDpopSupported.supported
      ? await this.getDpopOptions(agentContext, {
          dpopSigningAlgValuesSupported: isDpopSupported.dpopSigningAlgValuesSupported,
        })
      : undefined

    const result = options.code
      ? await client.retrieveAuthorizationCodeAccessTokenFromOffer({
          issuerMetadata: metadata,
          credentialOffer: credentialOfferPayload,
          authorizationCode: options.code,
          dpop,
          pkceCodeVerifier: options.codeVerifier,
          redirectUri: options.redirectUri,
          additionalRequestPayload: {
            // TODO: handle it as part of client auth once we support
            // assertion based client authentication
            client_id: options.clientId,
          },
        })
      : await client.retrievePreAuthorizedCodeAccessTokenFromOffer({
          credentialOffer: credentialOfferPayload,
          issuerMetadata: metadata,
          dpop,
          txCode: options.txCode,
        })

    return {
      ...result,
      dpop: dpop
        ? {
            ...result.dpop,
            alg: dpop.signer.alg as JwaSignatureAlgorithm,
            jwk: getJwkFromJson(dpop.signer.publicJwk),
          }
        : undefined,
    }
  }

  public async acceptCredentialOffer(
    agentContext: AgentContext,
    options: {
      resolvedCredentialOffer: OpenId4VciResolvedCredentialOffer
      acceptCredentialOfferOptions: OpenId4VciAcceptCredentialOfferOptions
      accessToken: string
      cNonce?: string
      dpop?: OpenId4VciDpopRequestOptions
      clientId?: string
    }
  ) {
    const { resolvedCredentialOffer, acceptCredentialOfferOptions } = options
    const { metadata, offeredCredentialConfigurations } = resolvedCredentialOffer
    const { credentialConfigurationIds, credentialBindingResolver, verifyCredentialStatus, requestBatch } =
      acceptCredentialOfferOptions
    const client = this.getClient(agentContext)

    if (credentialConfigurationIds?.length === 0) {
      throw new CredoError(`'credentialConfigurationIds' may not be empty`)
    }

    const supportedJwaSignatureAlgorithms = getSupportedJwaSignatureAlgorithms(agentContext)

    const allowedProofOfPossessionSigAlgs = acceptCredentialOfferOptions.allowedProofOfPossessionSignatureAlgorithms
    const possibleProofOfPossessionSigAlgs = allowedProofOfPossessionSigAlgs
      ? allowedProofOfPossessionSigAlgs.filter((algorithm) => supportedJwaSignatureAlgorithms.includes(algorithm))
      : supportedJwaSignatureAlgorithms

    if (possibleProofOfPossessionSigAlgs.length === 0) {
      throw new CredoError(
        [
          `No possible proof of possession signature algorithm found.`,
          `Signature algorithms supported by the Agent '${supportedJwaSignatureAlgorithms.join(', ')}'`,
          `Allowed Signature algorithms '${allowedProofOfPossessionSigAlgs?.join(', ')}'`,
        ].join('\n')
      )
    }

    const receivedCredentials: Array<OpenId4VciCredentialResponse> = []
    let cNonce = options.cNonce
    let dpopNonce = options.dpop?.nonce

    const credentialConfigurationsToRequest =
      credentialConfigurationIds?.map((id) => {
        if (!offeredCredentialConfigurations[id]) {
          const offeredCredentialIds = Object.keys(offeredCredentialConfigurations).join(', ')
          throw new CredoError(
            `Credential to request '${id}' is not present in offered credentials. Offered credentials are ${offeredCredentialIds}`
          )
        }
        return [id, offeredCredentialConfigurations[id]] as const
      }) ?? Object.entries(offeredCredentialConfigurations)

    // If we don't have a nonce yet, we need to first get one
    if (!cNonce) {
      // Best option is to use nonce endpoint (draft 14+)
      if (!metadata.credentialIssuer.nonce_endpoint) {
        const nonceResponse = await client.requestNonce({ issuerMetadata: metadata })
        cNonce = nonceResponse.c_nonce
      } else {
        // Otherwise we will send a dummy request
        await client
          .retrieveCredentials({
            issuerMetadata: metadata,
            accessToken: options.accessToken,
            credentialConfigurationId: credentialConfigurationsToRequest[0][0],
            dpop: options.dpop
              ? await this.getDpopOptions(agentContext, {
                  ...options.dpop,
                  nonce: dpopNonce,
                  dpopSigningAlgValuesSupported: [options.dpop.alg],
                })
              : undefined,
          })
          .catch((e) => {
            if (e instanceof Oid4vciRetrieveCredentialsError && e.response.credentialErrorResponseResult?.success) {
              cNonce = e.response.credentialErrorResponseResult.output.c_nonce
            }
          })
      }
    }

    if (!cNonce) {
      throw new CredoError('No cNonce provided and unable to acquire cNonce from the credential issuer')
    }

    // If true: use max from issuer or otherwise 1
    // If number not 0: use the number
    // Else: use 1
    const batchSize =
      requestBatch === true ? metadata.credentialIssuer.batch_credential_issuance?.batch_size ?? 1 : requestBatch || 1
    if (typeof requestBatch === 'number' && requestBatch > 1 && !metadata.credentialIssuer.batch_credential_issuance) {
      throw new CredoError(
        `Credential issuer '${metadata.credentialIssuer.credential_issuer}' does not support batch credential issuance using the 'proofs' request property. Onlt 'proof' supported.`
      )
    }

    for (const [offeredCredentialId, offeredCredentialConfiguration] of credentialConfigurationsToRequest) {
      // Get all options for the credential request (such as which kid to use, the signature algorithm, etc)
      const { jwtSigner } = await this.getCredentialRequestOptions(agentContext, {
        possibleProofOfPossessionSignatureAlgorithms: possibleProofOfPossessionSigAlgs,
        offeredCredential: {
          id: offeredCredentialId,
          configuration: offeredCredentialConfiguration,
        },
        credentialBindingResolver,
      })

      const jwts: string[] = []
      for (let i = 0; i < batchSize; i++) {
        const { jwt } = await client.createCredentialRequestJwtProof({
          credentialConfigurationId: offeredCredentialId,
          issuerMetadata: resolvedCredentialOffer.metadata,
          signer: jwtSigner,
          clientId: options.clientId,
          nonce: cNonce,
        })
        this.logger.debug('Generated credential request proof of possesion jwt', { jwt })
        jwts.push(jwt)
      }

      const { credentialResponse, dpop } = await client.retrieveCredentials({
        issuerMetadata: metadata,
        accessToken: options.accessToken,
        credentialConfigurationId: offeredCredentialId,
        dpop: options.dpop
          ? await this.getDpopOptions(agentContext, {
              ...options.dpop,
              nonce: dpopNonce,
              dpopSigningAlgValuesSupported: [options.dpop.alg],
            })
          : undefined,
        proofs: batchSize > 1 ? { jwt: jwts } : undefined,
        proof:
          batchSize === 1
            ? {
                proof_type: 'jwt',
                jwt: jwts[0],
              }
            : undefined,
      })

      // Set new nonce values
      cNonce = credentialResponse.c_nonce
      dpopNonce = dpop?.nonce

      // Create credential, but we don't store it yet (only after the user has accepted the credential)
      const credential = await this.handleCredentialResponse(agentContext, credentialResponse, {
        verifyCredentialStatus: verifyCredentialStatus ?? false,
        credentialIssuerMetadata: metadata.credentialIssuer,
        format: offeredCredentialConfiguration.format as OpenId4VciCredentialFormatProfile,
        credentialConfigurationId: offeredCredentialId,
      })

      this.logger.debug(
        'received credential',
        credential.credentials.map((c) =>
          c instanceof Mdoc ? { issuerSignedNamespaces: c.issuerSignedNamespaces, base64Url: c.base64Url } : c
        )
      )
      receivedCredentials.push({ ...credential, credentialConfigurationId: offeredCredentialId })
    }

    return {
      credentials: receivedCredentials,
      dpop: options.dpop
        ? {
            ...options.dpop,
            nonce: dpopNonce,
          }
        : undefined,
      cNonce,
    }
  }

  /**
   * Get the options for the credential request. Internally this will resolve the proof of possession
   * requirements, and based on that it will call the proofOfPossessionVerificationMethodResolver to
   * allow the caller to select the correct verification method based on the requirements for the proof
   * of possession.
   */
  private async getCredentialRequestOptions(
    agentContext: AgentContext,
    options: {
      credentialBindingResolver: OpenId4VciCredentialBindingResolver
      possibleProofOfPossessionSignatureAlgorithms: JwaSignatureAlgorithm[]
      offeredCredential: {
        id: string
        configuration: OpenId4VciCredentialConfigurationSupported
      }
    }
  ) {
    const { signatureAlgorithms, supportedDidMethods, supportsAllDidMethods, supportsJwk } =
      this.getProofOfPossessionRequirements(agentContext, {
        credentialToRequest: options.offeredCredential,
        possibleProofOfPossessionSignatureAlgorithms: options.possibleProofOfPossessionSignatureAlgorithms,
      })

    const JwkClasses = signatureAlgorithms.map((signatureAlgorithm) => {
      const JwkClass = getJwkClassFromJwaSignatureAlgorithm(signatureAlgorithm)
      if (!JwkClass) {
        throw new CredoError(`Could not determine JWK key type of the JWA signature algorithm '${signatureAlgorithm}'`)
      }
      return JwkClass
    })
    const keyTypes = JwkClasses.map((JwkClass): KeyType => JwkClass.keyType)

    const supportedVerificationMethods = keyTypes.flatMap((keyType) =>
      getSupportedVerificationMethodTypesFromKeyType(keyType)
    )
    const format = options.offeredCredential.configuration.format as OpenId4VciSupportedCredentialFormats
    const supportsAnyMethod = supportedDidMethods !== undefined || supportsAllDidMethods || supportsJwk

    // Now we need to determine how the credential will be bound to us
    const credentialBinding = await options.credentialBindingResolver({
      agentContext,
      credentialFormat: format,
      signatureAlgorithms,
      supportedVerificationMethods,
      keyTypes: JwkClasses.map((JwkClass): KeyType => JwkClass.keyType),
      credentialConfigurationId: options.offeredCredential.id,
      supportsAllDidMethods,
      supportedDidMethods,
      supportsJwk,
    })

    let jwk: Jwk
    // Make sure the issuer of proof of possession is valid according to openid issuer metadata
    if (credentialBinding.method === 'did') {
      // Test binding method
      if (
        !supportsAllDidMethods &&
        // If supportedDidMethods is undefined, it means the issuer didn't include the binding methods in the metadata
        // The user can still select a verification method, but we can't validate it
        supportedDidMethods !== undefined &&
        !supportedDidMethods.find(
          (supportedDidMethod) => credentialBinding.didUrl.startsWith(supportedDidMethod) && supportsAnyMethod
        )
      ) {
        const { method } = parseDid(credentialBinding.didUrl)
        const supportedDidMethodsString = supportedDidMethods.join(', ')
        throw new CredoError(
          `Resolved credential binding for proof of possession uses did method '${method}', but issuer only supports '${supportedDidMethodsString}'`
        )
      }

      const key = await getKeyFromDid(agentContext, credentialBinding.didUrl)
      jwk = getJwkFromKey(key)
      if (!keyTypes.includes(key.keyType)) {
        throw new CredoError(
          `Credential binding returned did url that points to key with type '${
            key.keyType
          }', but one of '${keyTypes.join(', ')}' was expected`
        )
      }
    } else if (credentialBinding.method === 'jwk') {
      if (!supportsJwk && supportsAnyMethod) {
        throw new CredoError(
          `Resolved credential binding for proof of possession uses jwk, but openid issuer does not support 'jwk' or 'cose_key' cryptographic binding method`
        )
      }

      jwk = credentialBinding.jwk
      if (!keyTypes.includes(credentialBinding.jwk.key.keyType)) {
        throw new CredoError(
          `Credential binding returned jwk with key with type '${
            credentialBinding.jwk.key.keyType
          }', but one of '${keyTypes.join(', ')}' was expected`
        )
      }
    } else {
      // @ts-expect-error currently if/else if exhaustive, but once we add new option it will give ts error
      throw new CredoError(`Unsupported credential binding method ${credentialBinding.method}`)
    }

    const alg = jwk.supportedSignatureAlgorithms.find((alg) => signatureAlgorithms.includes(alg))
    if (!alg) {
      // Should not happen, to make ts happy
      throw new CredoError(`Unable to determine alg for key type ${jwk.keyType}`)
    }

    const jwtSigner: JwtSigner =
      credentialBinding.method === 'did'
        ? {
            method: credentialBinding.method,
            didUrl: credentialBinding.didUrl,
            alg,
          }
        : {
            method: 'jwk',
            publicJwk: credentialBinding.jwk.toJson(),
            alg,
          }

    return { credentialBinding, signatureAlgorithm: alg, jwtSigner }
  }

  /**
   * Get the requirements for creating the proof of possession. Based on the allowed
   * credential formats, the allowed proof of possession signature algorithms, and the
   * credential type, this method will select the best credential format and signature
   * algorithm to use, based on the order of preference.
   */
  private getProofOfPossessionRequirements(
    agentContext: AgentContext,
    options: {
      credentialToRequest: {
        id: string
        configuration: OpenId4VciCredentialConfigurationSupported
      }
      possibleProofOfPossessionSignatureAlgorithms: JwaSignatureAlgorithm[]
    }
  ): OpenId4VciProofOfPossessionRequirements {
    const { credentialToRequest } = options

    if (
      !openId4VciSupportedCredentialFormats.includes(
        credentialToRequest.configuration.format as OpenId4VciSupportedCredentialFormats
      )
    ) {
      throw new CredoError(
        [
          `Requested credential with format '${credentialToRequest.configuration.format}',`,
          `for the credential with id '${credentialToRequest.id},`,
          `but the wallet only supports the following formats '${openId4VciSupportedCredentialFormats.join(', ')}'`,
        ].join('\n')
      )
    }

    // For each of the supported algs, find the key types, then find the proof types
    const signatureSuiteRegistry = agentContext.dependencyManager.resolve(SignatureSuiteRegistry)

    let signatureAlgorithms: JwaSignatureAlgorithm[] = []

    if (credentialToRequest.configuration.proof_types_supported) {
      if (!credentialToRequest.configuration.proof_types_supported.jwt) {
        throw new CredoError(
          `Unsupported proof type(s) ${Object.keys(credentialToRequest.configuration.proof_types_supported).join(
            ', '
          )}. Supported proof type(s) are: jwt`
        )
      }
    }

    const proofSigningAlgsSupported =
      credentialToRequest.configuration.proof_types_supported?.jwt?.proof_signing_alg_values_supported

    // If undefined, it means the issuer didn't include the cryptographic suites in the metadata
    // We just guess that the first one is supported
    if (proofSigningAlgsSupported === undefined) {
      signatureAlgorithms = options.possibleProofOfPossessionSignatureAlgorithms
    } else {
      switch (credentialToRequest.configuration.format) {
        case OpenId4VciCredentialFormatProfile.JwtVcJson:
        case OpenId4VciCredentialFormatProfile.JwtVcJsonLd:
        case OpenId4VciCredentialFormatProfile.SdJwtVc:
        case OpenId4VciCredentialFormatProfile.MsoMdoc:
          signatureAlgorithms = options.possibleProofOfPossessionSignatureAlgorithms.filter((signatureAlgorithm) =>
            proofSigningAlgsSupported.includes(signatureAlgorithm)
          )
          break
        case OpenId4VciCredentialFormatProfile.LdpVc:
          signatureAlgorithms = options.possibleProofOfPossessionSignatureAlgorithms.filter((signatureAlgorithm) => {
            const JwkClass = getJwkClassFromJwaSignatureAlgorithm(signatureAlgorithm)
            if (!JwkClass) return false

            const matchingSuite = signatureSuiteRegistry.getAllByKeyType(JwkClass.keyType)
            if (matchingSuite.length === 0) return false

            return proofSigningAlgsSupported.includes(matchingSuite[0].proofType)
          })
          break
        default:
          throw new CredoError(`Unsupported credential format.`)
      }
    }

    if (signatureAlgorithms.length === 0) {
      throw new CredoError(
        `Could not establish signature algorithm for format ${credentialToRequest.configuration.format} and id ${
          credentialToRequest.id
        }. Server supported signature algorithms are '${
          proofSigningAlgsSupported?.join(', ') ?? 'Not defined'
        }', available are '${options.possibleProofOfPossessionSignatureAlgorithms.join(', ')}'`
      )
    }

    const issuerSupportedBindingMethods = credentialToRequest.configuration.cryptographic_binding_methods_supported
    const supportsAllDidMethods = issuerSupportedBindingMethods?.includes('did') ?? false
    const supportedDidMethods = issuerSupportedBindingMethods?.filter((method) => method.startsWith('did:'))

    // The cryptographic_binding_methods_supported describe the cryptographic key material that the issued Credential is bound to.
    const supportsCoseKey = issuerSupportedBindingMethods?.includes('cose_key') ?? false
    const supportsJwk = issuerSupportedBindingMethods?.includes('jwk') || supportsCoseKey

    return {
      signatureAlgorithms,
      supportedDidMethods,
      supportsAllDidMethods,
      supportsJwk,
    }
  }

  private async handleCredentialResponse(
    agentContext: AgentContext,
    credentialResponse: CredentialResponse,
    options: {
      verifyCredentialStatus: boolean
      credentialIssuerMetadata: OpenId4VciCredentialIssuerMetadata
      format: OpenId4VciCredentialFormatProfile
      credentialConfigurationId: string
    }
  ): Promise<OpenId4VciCredentialResponse> {
    const { verifyCredentialStatus, credentialConfigurationId } = options
    this.logger.debug('Credential response', credentialResponse)

    const credentials =
      credentialResponse.credentials ?? (credentialResponse.credential ? [credentialResponse.credential] : undefined)
    if (!credentials) {
      throw new CredoError(`Credential response returned neither 'credentials' nor 'credential' parameter.`)
    }

    const notificationId = credentialResponse.notification_id

    const format = options.format
    if (format === OpenId4VciCredentialFormatProfile.SdJwtVc) {
      if (!credentials.every((c) => typeof c === 'string')) {
        throw new CredoError(
          `Received credential(s) of format ${format}, but not all credential(s) are a string. ${JSON.stringify(
            credentials
          )}`
        )
      }

      const sdJwtVcApi = agentContext.dependencyManager.resolve(SdJwtVcApi)
      const verificationResults = await Promise.all(
        credentials.map((compactSdJwtVc, index) =>
          sdJwtVcApi.verify({
            compactSdJwtVc,
            // Only load and verify it for the first instance
            fetchTypeMetadata: index === 0,
          })
        )
      )

      if (!verificationResults.every((result) => result.isValid)) {
        agentContext.config.logger.error('Failed to validate credential(s)', { verificationResults })
        throw new CredoError(
          `Failed to validate sd-jwt-vc credentials. Results = ${JSON.stringify(verificationResults)}`
        )
      }

      return {
        credentials: verificationResults.map((result) => result.sdJwtVc),
        notificationId,
        credentialConfigurationId,
      }
    } else if (
      options.format === OpenId4VciCredentialFormatProfile.JwtVcJson ||
      options.format === OpenId4VciCredentialFormatProfile.JwtVcJsonLd
    ) {
      if (!credentials.every((c) => typeof c === 'string')) {
        throw new CredoError(
          `Received credential(s) of format ${format}, but not all credential(s) are a string. ${JSON.stringify(
            credentials
          )}`
        )
      }

      const result = await Promise.all(
        credentials.map(async (c) => {
          const credential = W3cJwtVerifiableCredential.fromSerializedJwt(c)
          const result = await this.w3cCredentialService.verifyCredential(agentContext, {
            credential,
            verifyCredentialStatus,
          })

          return { credential, result }
        })
      )

      if (!result.every((c) => c.result.isValid)) {
        agentContext.config.logger.error('Failed to validate credentials', { result })
        throw new CredoError(
          `Failed to validate credential, error = ${result
            .map((e) => e.result.error?.message)
            .filter(Boolean)
            .join(', ')}`
        )
      }

      return { credentials: result.map((r) => r.credential), notificationId, credentialConfigurationId }
    } else if (format === OpenId4VciCredentialFormatProfile.LdpVc) {
      if (!credentials.every((c) => typeof c === 'object')) {
        throw new CredoError(
          `Received credential(s) of format ${format}, but not all credential(s) are an object. ${JSON.stringify(
            credentials
          )}`
        )
      }
      const result = await Promise.all(
        credentials.map(async (c) => {
          const credential = W3cJsonLdVerifiableCredential.fromJson(c)
          const result = await this.w3cCredentialService.verifyCredential(agentContext, {
            credential,
            verifyCredentialStatus,
          })

          return { credential, result }
        })
      )

      if (!result.every((c) => c.result.isValid)) {
        agentContext.config.logger.error('Failed to validate credentials', { result })
        throw new CredoError(
          `Failed to validate credential, error = ${result
            .map((e) => e.result.error?.message)
            .filter(Boolean)
            .join(', ')}`
        )
      }

      return { credentials: result.map((r) => r.credential), notificationId, credentialConfigurationId }
    } else if (format === OpenId4VciCredentialFormatProfile.MsoMdoc) {
      if (!credentials.every((c) => typeof c === 'string')) {
        throw new CredoError(
          `Received credential(s) of format ${format}, but not all credential(s) are a string. ${JSON.stringify(
            credentials
          )}`
        )
      }
      const mdocApi = agentContext.dependencyManager.resolve(MdocApi)
      const result = await Promise.all(
        credentials.map(async (credential) => {
          const mdoc = Mdoc.fromBase64Url(credential)
          const result = await mdocApi.verify(mdoc, {})
          return {
            result,
            mdoc,
          }
        })
      )

      if (!result.every((r) => r.result.isValid)) {
        agentContext.config.logger.error('Failed to validate credentials', { result })
        throw new CredoError(
          `Failed to validate mdoc credential(s). \n - ${result
            .map((r, i) => (r.result.isValid ? undefined : `(${i}) ${r.result.error}`))
            .filter(Boolean)
            .join('\n - ')}`
        )
      }

      return { credentials: result.map((c) => c.mdoc), notificationId, credentialConfigurationId }
    }

    throw new CredoError(`Unsupported credential format ${options.format}`)
  }

  private getClient(agentContext: AgentContext) {
    return new Oid4vciClient({
      callbacks: getOid4vciCallbacks(agentContext),
    })
  }

  private getOauth2Client(agentContext: AgentContext) {
    return new Oauth2Client({
      callbacks: getOid4vciCallbacks(agentContext),
    })
  }
}
