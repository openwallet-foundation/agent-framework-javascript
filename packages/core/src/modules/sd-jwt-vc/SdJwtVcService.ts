import type {
  SdJwtVcSignOptions,
  SdJwtVcPresentOptions,
  SdJwtVcVerifyOptions,
  SdJwtVcPayload,
  SdJwtVcHeader,
  SdJwtVcHolderBinding,
  SdJwtVcIssuer,
} from './SdJwtVcOptions'
import type { JwkJson, Key } from '../../crypto'
import type { Query, QueryOptions } from '../../storage/StorageService'
import type { SDJwt } from '@sd-jwt/core'
import type { Signer, Verifier, PresentationFrame, DisclosureFrame } from '@sd-jwt/types'

import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc'
import { uint8ArrayToBase64Url } from '@sd-jwt/utils'
import { injectable } from 'tsyringe'

import { AgentContext } from '../../agent'
import { JwtPayload, Jwk, getJwkFromJson, getJwkFromKey } from '../../crypto'
import { CredoError } from '../../error'
import { X509Service } from '../../modules/x509/X509Service'
import { TypedArrayEncoder, nowInSeconds } from '../../utils'
import { getDomainFromUrl } from '../../utils/domain'
import { fetchWithTimeout } from '../../utils/fetch'
import { DidResolverService, parseDid, getKeyFromVerificationMethod } from '../dids'
import { X509Certificate, X509ModuleConfig } from '../x509'

import { SdJwtVcError } from './SdJwtVcError'
import { decodeSdJwtVc, sdJwtVcHasher } from './decodeSdJwtVc'
import { SdJwtVcRecord, SdJwtVcRepository } from './repository'
import { SdJwtVcTypeMetadata } from './typeMetadata'

type SdJwtVcConfig = SDJwtVcInstance['userConfig']

export interface SdJwtVc<
  Header extends SdJwtVcHeader = SdJwtVcHeader,
  Payload extends SdJwtVcPayload = SdJwtVcPayload
> {
  compact: string
  header: Header

  // TODO: payload type here is a lie, as it is the signed payload (so fields replaced with _sd)
  payload: Payload
  prettyClaims: Payload

  typeMetadata?: SdJwtVcTypeMetadata
}

export interface CnfPayload {
  jwk?: JwkJson
  kid?: string
}

export interface VerificationResult {
  isValid: boolean
  isValidJwtPayload?: boolean
  isSignatureValid?: boolean
  isStatusValid?: boolean
  isNotBeforeValid?: boolean
  isExpiryTimeValid?: boolean
  areRequiredClaimsIncluded?: boolean
  isKeyBindingValid?: boolean
  containsExpectedKeyBinding?: boolean
  containsRequiredVcProperties?: boolean
}

/**
 * @internal
 */
@injectable()
export class SdJwtVcService {
  private sdJwtVcRepository: SdJwtVcRepository

  public constructor(sdJwtVcRepository: SdJwtVcRepository) {
    this.sdJwtVcRepository = sdJwtVcRepository
  }

  public async sign<Payload extends SdJwtVcPayload>(agentContext: AgentContext, options: SdJwtVcSignOptions<Payload>) {
    const { payload, disclosureFrame, hashingAlgorithm } = options

    // default is sha-256
    if (hashingAlgorithm && hashingAlgorithm !== 'sha-256') {
      throw new SdJwtVcError(`Unsupported hashing algorithm used: ${hashingAlgorithm}`)
    }

    const issuer = await this.extractKeyFromIssuer(agentContext, options.issuer)

    // holer binding is optional
    const holderBinding = options.holder
      ? await this.extractKeyFromHolderBinding(agentContext, options.holder)
      : undefined

    const header = {
      alg: issuer.alg,
      typ: 'vc+sd-jwt',
      kid: issuer.kid,
      x5c: issuer.x5c,
    } as const

    const sdjwt = new SDJwtVcInstance({
      ...this.getBaseSdJwtConfig(agentContext),
      signer: this.signer(agentContext, issuer.key),
      hashAlg: 'sha-256',
      signAlg: issuer.alg,
    })

    if (!payload.vct || typeof payload.vct !== 'string') {
      throw new SdJwtVcError("Missing required parameter 'vct'")
    }

    const compact = await sdjwt.issue(
      {
        ...payload,
        cnf: holderBinding?.cnf,
        iss: issuer.iss,
        iat: nowInSeconds(),
        vct: payload.vct,
      },
      disclosureFrame as DisclosureFrame<Payload>,
      { header }
    )

    const prettyClaims = (await sdjwt.getClaims(compact)) as Payload
    const a = await sdjwt.decode(compact)
    const sdjwtPayload = a.jwt?.payload as Payload | undefined
    if (!sdjwtPayload) {
      throw new SdJwtVcError('Invalid sd-jwt-vc state.')
    }

    return {
      compact,
      prettyClaims,
      header: header,
      payload: sdjwtPayload,
    } satisfies SdJwtVc<typeof header, Payload>
  }

  public fromCompact<Header extends SdJwtVcHeader = SdJwtVcHeader, Payload extends SdJwtVcPayload = SdJwtVcPayload>(
    compactSdJwtVc: string,
    typeMetadata?: SdJwtVcTypeMetadata
  ): SdJwtVc<Header, Payload> {
    return decodeSdJwtVc(compactSdJwtVc, typeMetadata)
  }

  public async present<Payload extends SdJwtVcPayload = SdJwtVcPayload>(
    agentContext: AgentContext,
    { compactSdJwtVc, presentationFrame, verifierMetadata }: SdJwtVcPresentOptions<Payload>
  ): Promise<string> {
    const sdjwt = new SDJwtVcInstance(this.getBaseSdJwtConfig(agentContext))

    const sdJwtVc = await sdjwt.decode(compactSdJwtVc)

    const holderBinding = this.parseHolderBindingFromCredential(sdJwtVc)
    if (!holderBinding && verifierMetadata) {
      throw new SdJwtVcError("Verifier metadata provided, but credential has no 'cnf' claim to create a KB-JWT from")
    }

    const holder = holderBinding ? await this.extractKeyFromHolderBinding(agentContext, holderBinding) : undefined
    sdjwt.config({
      kbSigner: holder ? this.signer(agentContext, holder.key) : undefined,
      kbSignAlg: holder?.alg,
    })

    const compactDerivedSdJwtVc = await sdjwt.present(compactSdJwtVc, presentationFrame as PresentationFrame<Payload>, {
      kb: verifierMetadata
        ? {
            payload: {
              iat: verifierMetadata.issuedAt,
              nonce: verifierMetadata.nonce,
              aud: verifierMetadata.audience,
            },
          }
        : undefined,
    })

    return compactDerivedSdJwtVc
  }

  private assertValidX5cJwtIssuer(agentContext: AgentContext, iss: string, leafCertificate: X509Certificate) {
    if (!iss.startsWith('https://') && !(iss.startsWith('http://') && agentContext.config.allowInsecureHttpUrls)) {
      throw new SdJwtVcError('The X509 certificate issuer must be a HTTPS URI.')
    }

    if (!leafCertificate.sanUriNames?.includes(iss) && !leafCertificate.sanDnsNames?.includes(getDomainFromUrl(iss))) {
      throw new SdJwtVcError(
        `The 'iss' claim in the payload does not match a 'SAN-URI' name and the domain extracted from the HTTPS URI does not match a 'SAN-DNS' name in the x5c certificate.`
      )
    }
  }

  public async verify<Header extends SdJwtVcHeader = SdJwtVcHeader, Payload extends SdJwtVcPayload = SdJwtVcPayload>(
    agentContext: AgentContext,
    { compactSdJwtVc, keyBinding, requiredClaimKeys, fetchTypeMetadata }: SdJwtVcVerifyOptions
  ): Promise<
    | { isValid: true; verification: VerificationResult; sdJwtVc: SdJwtVc<Header, Payload> }
    | { isValid: false; verification: VerificationResult; sdJwtVc?: SdJwtVc<Header, Payload>; error: Error }
  > {
    const sdjwt = new SDJwtVcInstance({
      ...this.getBaseSdJwtConfig(agentContext),
      // FIXME: will break if using url but no type metadata
      // https://github.com/openwallet-foundation/sd-jwt-js/issues/258
      // loadTypeMetadataFormat: false,
    })

    const verificationResult: VerificationResult = {
      isValid: false,
    }

    let sdJwtVc: SDJwt
    let _error: Error | undefined = undefined

    try {
      sdJwtVc = await sdjwt.decode(compactSdJwtVc)
      if (!sdJwtVc.jwt) throw new CredoError('Invalid sd-jwt-vc')
    } catch (error) {
      return {
        isValid: false,
        verification: verificationResult,
        error,
      }
    }

    const returnSdJwtVc: SdJwtVc<Header, Payload> = {
      payload: sdJwtVc.jwt.payload as Payload,
      header: sdJwtVc.jwt.header as Header,
      compact: compactSdJwtVc,
      prettyClaims: await sdJwtVc.getClaims(sdJwtVcHasher),
    } satisfies SdJwtVc<Header, Payload>

    try {
      const credentialIssuer = await this.parseIssuerFromCredential(agentContext, sdJwtVc)
      const issuer = await this.extractKeyFromIssuer(agentContext, credentialIssuer)
      const holderBinding = this.parseHolderBindingFromCredential(sdJwtVc)
      const holder = holderBinding ? await this.extractKeyFromHolderBinding(agentContext, holderBinding) : undefined

      sdjwt.config({
        verifier: this.verifier(agentContext, issuer.key),
        kbVerifier: holder ? this.verifier(agentContext, holder.key) : undefined,
      })

      const requiredKeys = requiredClaimKeys ? [...requiredClaimKeys, 'vct'] : ['vct']

      try {
        await sdjwt.verify(compactSdJwtVc, requiredKeys, keyBinding !== undefined)

        verificationResult.isSignatureValid = true
        verificationResult.areRequiredClaimsIncluded = true
        verificationResult.isStatusValid = true
      } catch (error) {
        _error = error
        verificationResult.isSignatureValid = false
        verificationResult.areRequiredClaimsIncluded = false
        verificationResult.isStatusValid = false
      }

      try {
        JwtPayload.fromJson(returnSdJwtVc.payload).validate()
        verificationResult.isValidJwtPayload = true
      } catch (error) {
        _error = error
        verificationResult.isValidJwtPayload = false
      }

      // If keyBinding is present, verify the key binding
      try {
        if (keyBinding) {
          if (!sdJwtVc.kbJwt || !sdJwtVc.kbJwt.payload) {
            throw new SdJwtVcError('Keybinding is required for verification of the sd-jwt-vc')
          }

          // Assert `aud` and `nonce` claims
          if (sdJwtVc.kbJwt.payload.aud !== keyBinding.audience) {
            throw new SdJwtVcError('The key binding JWT does not contain the expected audience')
          }

          if (sdJwtVc.kbJwt.payload.nonce !== keyBinding.nonce) {
            throw new SdJwtVcError('The key binding JWT does not contain the expected nonce')
          }

          verificationResult.isKeyBindingValid = true
          verificationResult.containsExpectedKeyBinding = true
          verificationResult.containsRequiredVcProperties = true
        }
      } catch (error) {
        _error = error
        verificationResult.isKeyBindingValid = false
        verificationResult.containsExpectedKeyBinding = false
        verificationResult.containsRequiredVcProperties = false
      }

      try {
        const vct = returnSdJwtVc.payload?.vct
        if (fetchTypeMetadata && typeof vct === 'string' && vct.startsWith('https://')) {
          // modify the uri based on https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-04.html#section-6.3.1
          const vctElements = vct.split('/')
          vctElements.splice(3, 0, '.well-known/vct')
          const vctUrl = vctElements.join('/')

          const response = await agentContext.config.agentDependencies.fetch(vctUrl)
          if (response.ok) {
            const typeMetadata = await response.json()
            returnSdJwtVc.typeMetadata = typeMetadata as SdJwtVcTypeMetadata
          }
        }
      } catch (error) {
        // we allow vct without type metadata for now
      }
    } catch (error) {
      verificationResult.isValid = false
      return {
        isValid: false,
        error,
        verification: verificationResult,
        sdJwtVc: returnSdJwtVc,
      }
    }

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { isValid: _, ...allVerifications } = verificationResult
    verificationResult.isValid = Object.values(allVerifications).every((verification) => verification === true)

    if (_error) {
      return {
        isValid: false,
        error: _error,
        sdJwtVc: returnSdJwtVc,
        verification: verificationResult,
      }
    }

    return {
      isValid: true,
      verification: verificationResult,
      sdJwtVc: returnSdJwtVc,
    }
  }

  public async store(agentContext: AgentContext, compactSdJwtVc: string) {
    const sdJwtVcRecord = new SdJwtVcRecord({
      compactSdJwtVc,
    })
    await this.sdJwtVcRepository.save(agentContext, sdJwtVcRecord)

    return sdJwtVcRecord
  }

  public async getById(agentContext: AgentContext, id: string): Promise<SdJwtVcRecord> {
    return await this.sdJwtVcRepository.getById(agentContext, id)
  }

  public async getAll(agentContext: AgentContext): Promise<Array<SdJwtVcRecord>> {
    return await this.sdJwtVcRepository.getAll(agentContext)
  }

  public async findByQuery(
    agentContext: AgentContext,
    query: Query<SdJwtVcRecord>,
    queryOptions?: QueryOptions
  ): Promise<Array<SdJwtVcRecord>> {
    return await this.sdJwtVcRepository.findByQuery(agentContext, query, queryOptions)
  }

  public async deleteById(agentContext: AgentContext, id: string) {
    await this.sdJwtVcRepository.deleteById(agentContext, id)
  }

  public async update(agentContext: AgentContext, sdJwtVcRecord: SdJwtVcRecord) {
    await this.sdJwtVcRepository.update(agentContext, sdJwtVcRecord)
  }

  private async resolveDidUrl(agentContext: AgentContext, didUrl: string) {
    const didResolver = agentContext.dependencyManager.resolve(DidResolverService)
    const didDocument = await didResolver.resolveDidDocument(agentContext, didUrl)

    return {
      verificationMethod: didDocument.dereferenceKey(didUrl, ['assertionMethod']),
      didDocument,
    }
  }

  /**
   * @todo validate the JWT header (alg)
   */
  private signer(agentContext: AgentContext, key: Key): Signer {
    return async (input: string) => {
      const signedBuffer = await agentContext.wallet.sign({ key, data: TypedArrayEncoder.fromString(input) })
      return uint8ArrayToBase64Url(signedBuffer)
    }
  }

  /**
   * @todo validate the JWT header (alg)
   */
  private verifier(agentContext: AgentContext, key: Key): Verifier {
    return async (message: string, signatureBase64Url: string) => {
      if (!key) {
        throw new SdJwtVcError('The public key used to verify the signature is missing')
      }

      return await agentContext.wallet.verify({
        signature: TypedArrayEncoder.fromBase64(signatureBase64Url),
        key,
        data: TypedArrayEncoder.fromString(message),
      })
    }
  }

  private async extractKeyFromIssuer(agentContext: AgentContext, issuer: SdJwtVcIssuer) {
    if (issuer.method === 'did') {
      const parsedDid = parseDid(issuer.didUrl)
      if (!parsedDid.fragment) {
        throw new SdJwtVcError(
          `didUrl '${issuer.didUrl}' does not contain a '#'. Unable to derive key from did document`
        )
      }

      const { verificationMethod } = await this.resolveDidUrl(agentContext, issuer.didUrl)
      const key = getKeyFromVerificationMethod(verificationMethod)
      const supportedSignatureAlgorithms = getJwkFromKey(key).supportedSignatureAlgorithms
      if (supportedSignatureAlgorithms.length === 0) {
        throw new SdJwtVcError(`No supported JWA signature algorithms found for key with keyType ${key.keyType}`)
      }
      const alg = supportedSignatureAlgorithms[0]

      return {
        alg,
        key,
        iss: parsedDid.did,
        kid: `#${parsedDid.fragment}`,
      }
    }

    if (issuer.method === 'x5c') {
      const leafCertificate = X509Service.getLeafCertificate(agentContext, { certificateChain: issuer.x5c })
      const key = leafCertificate.publicKey
      const supportedSignatureAlgorithms = getJwkFromKey(key).supportedSignatureAlgorithms
      if (supportedSignatureAlgorithms.length === 0) {
        throw new SdJwtVcError(`No supported JWA signature algorithms found for key with keyType ${key.keyType}`)
      }
      const alg = supportedSignatureAlgorithms[0]

      this.assertValidX5cJwtIssuer(agentContext, issuer.issuer, leafCertificate)

      return {
        key,
        iss: issuer.issuer,
        x5c: issuer.x5c,
        alg,
      }
    }

    throw new SdJwtVcError("Unsupported credential issuer. Only 'did' and 'x5c' is supported at the moment.")
  }

  private async parseIssuerFromCredential<Header extends SdJwtVcHeader, Payload extends SdJwtVcPayload>(
    agentContext: AgentContext,
    sdJwtVc: SDJwt<Header, Payload>
  ): Promise<SdJwtVcIssuer> {
    if (!sdJwtVc.jwt?.payload) {
      throw new SdJwtVcError('Credential not exist')
    }

    if (!sdJwtVc.jwt?.payload['iss']) {
      throw new SdJwtVcError('Credential does not contain an issuer')
    }

    const iss = sdJwtVc.jwt.payload['iss'] as string

    if (sdJwtVc.jwt.header?.x5c) {
      if (!Array.isArray(sdJwtVc.jwt.header.x5c)) {
        throw new SdJwtVcError('Invalid x5c header in credential. Not an array.')
      }
      if (sdJwtVc.jwt.header.x5c.length === 0) {
        throw new SdJwtVcError('Invalid x5c header in credential. Empty array.')
      }
      if (sdJwtVc.jwt.header.x5c.some((x5c) => typeof x5c !== 'string')) {
        throw new SdJwtVcError('Invalid x5c header in credential. Not an array of strings.')
      }

      const trustedCertificates = agentContext.dependencyManager.resolve(X509ModuleConfig).trustedCertificates
      if (!trustedCertificates) {
        throw new SdJwtVcError(
          'No trusted certificates configured for X509 certificate chain validation. Issuer cannot be verified.'
        )
      }

      await X509Service.validateCertificateChain(agentContext, {
        certificateChain: sdJwtVc.jwt.header.x5c,
        trustedCertificates,
      })

      return {
        method: 'x5c',
        x5c: sdJwtVc.jwt.header.x5c,
        issuer: iss,
      }
    }

    if (iss.startsWith('did:')) {
      // If `did` is used, we require a relative KID to be present to identify
      // the key used by issuer to sign the sd-jwt-vc

      if (!sdJwtVc.jwt?.header) {
        throw new SdJwtVcError('Credential does not contain a header')
      }

      if (!sdJwtVc.jwt.header['kid']) {
        throw new SdJwtVcError('Credential does not contain a kid in the header')
      }

      const issuerKid = sdJwtVc.jwt.header['kid'] as string

      let didUrl: string
      if (issuerKid.startsWith('#')) {
        didUrl = `${iss}${issuerKid}`
      } else if (issuerKid.startsWith('did:')) {
        const didFromKid = parseDid(issuerKid)
        if (didFromKid.did !== iss) {
          throw new SdJwtVcError(
            `kid in header is an absolute DID URL, but the did (${didFromKid.did}) does not match with the 'iss' did (${iss})`
          )
        }

        didUrl = issuerKid
      } else {
        throw new SdJwtVcError(
          'Invalid issuer kid for did. Only absolute or relative (starting with #) did urls are supported.'
        )
      }

      return {
        method: 'did',
        didUrl,
      }
    }
    throw new SdJwtVcError("Unsupported 'iss' value. Only did is supported at the moment.")
  }

  private parseHolderBindingFromCredential<Header extends SdJwtVcHeader, Payload extends SdJwtVcPayload>(
    sdJwtVc: SDJwt<Header, Payload>
  ): SdJwtVcHolderBinding | null {
    if (!sdJwtVc.jwt?.payload) {
      throw new SdJwtVcError('Credential not exist')
    }

    if (!sdJwtVc.jwt?.payload['cnf']) {
      return null
    }
    const cnf: CnfPayload = sdJwtVc.jwt.payload['cnf']

    if (cnf.jwk) {
      return {
        method: 'jwk',
        jwk: cnf.jwk,
      }
    } else if (cnf.kid) {
      if (!cnf.kid.startsWith('did:') || !cnf.kid.includes('#')) {
        throw new SdJwtVcError('Invalid holder kid for did. Only absolute KIDs for cnf are supported')
      }
      return {
        method: 'did',
        didUrl: cnf.kid,
      }
    }

    throw new SdJwtVcError("Unsupported credential holder binding. Only 'did' and 'jwk' are supported at the moment.")
  }

  private async extractKeyFromHolderBinding(agentContext: AgentContext, holder: SdJwtVcHolderBinding) {
    if (holder.method === 'did') {
      const parsedDid = parseDid(holder.didUrl)
      if (!parsedDid.fragment) {
        throw new SdJwtVcError(
          `didUrl '${holder.didUrl}' does not contain a '#'. Unable to derive key from did document`
        )
      }

      const { verificationMethod } = await this.resolveDidUrl(agentContext, holder.didUrl)
      const key = getKeyFromVerificationMethod(verificationMethod)
      const supportedSignatureAlgorithms = getJwkFromKey(key).supportedSignatureAlgorithms
      if (supportedSignatureAlgorithms.length === 0) {
        throw new SdJwtVcError(`No supported JWA signature algorithms found for key with keyType ${key.keyType}`)
      }
      const alg = supportedSignatureAlgorithms[0]

      return {
        alg,
        key,
        cnf: {
          // We need to include the whole didUrl here, otherwise the verifier
          // won't know which did it is associated with
          kid: holder.didUrl,
        },
      }
    } else if (holder.method === 'jwk') {
      const jwk = holder.jwk instanceof Jwk ? holder.jwk : getJwkFromJson(holder.jwk)
      const key = jwk.key
      const alg = jwk.supportedSignatureAlgorithms[0]

      return {
        alg,
        key,
        cnf: {
          jwk: jwk.toJson(),
        },
      }
    }

    throw new SdJwtVcError("Unsupported credential holder binding. Only 'did' and 'jwk' are supported at the moment.")
  }

  private getBaseSdJwtConfig(agentContext: AgentContext): SdJwtVcConfig {
    return {
      hasher: sdJwtVcHasher,
      statusListFetcher: this.getStatusListFetcher(agentContext),
      saltGenerator: agentContext.wallet.generateNonce,
    }
  }

  private getStatusListFetcher(agentContext: AgentContext) {
    return async (uri: string) => {
      const response = await fetchWithTimeout(agentContext.config.agentDependencies.fetch, uri)
      if (!response.ok) {
        throw new CredoError(
          `Received invalid response with status ${
            response.status
          } when fetching status list from ${uri}. ${await response.text()}`
        )
      }

      return await response.text()
    }
  }
}
