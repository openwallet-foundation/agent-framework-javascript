import type { AgentContext } from '../../../agent/context'
import type { VerifyJwsResult } from '../../../crypto/JwsService'
import type { DidPurpose, VerificationMethod } from '../../dids'
import type {
  RevokeCredentialOptions,
  W3cJwtSignCredentialOptions,
  W3cJwtSignPresentationOptions,
  W3cJwtVerifyCredentialOptions,
  W3cJwtVerifyPresentationOptions,
} from '../W3cCredentialServiceOptions'
import type { SingleValidationResult, W3cVerifyCredentialResult, W3cVerifyPresentationResult } from '../models'

import { JwsService } from '../../../crypto'
import { getJwkFromKey, getJwkClassFromJwaSignatureAlgorithm } from '../../../crypto/jose/jwk'
import { CredoError } from '../../../error'
import { injectable } from '../../../plugins'
import { asArray, isDid, MessageValidator } from '../../../utils'
import { getKeyDidMappingByKeyType, DidResolverService, getKeyFromVerificationMethod } from '../../dids'
import { X509ModuleConfig } from '../../x509'
import { W3cJsonLdVerifiableCredential } from '../data-integrity'

import { W3cJwtVerifiableCredential } from './W3cJwtVerifiableCredential'
import { W3cJwtVerifiablePresentation } from './W3cJwtVerifiablePresentation'
import { getJwtPayloadFromCredential } from './credentialTransformer'
import { getJwtPayloadFromPresentation } from './presentationTransformer'

/**
 * Supports signing and verification of credentials according to the [Verifiable Credential Data Model](https://www.w3.org/TR/vc-data-model)
 * using [Json Web Tokens](https://www.w3.org/TR/vc-data-model/#json-web-token).
 */
@injectable()
export class W3cJwtCredentialService {
  private jwsService: JwsService

  public constructor(jwsService: JwsService) {
    this.jwsService = jwsService
  }

  /**
   * Signs a credential
   */
  public async signCredential(
    agentContext: AgentContext,
    options: W3cJwtSignCredentialOptions
  ): Promise<W3cJwtVerifiableCredential> {
    // Validate the instance
    MessageValidator.validateSync(options.credential)

    // Get the JWT payload for the JWT based on the JWT Encoding rules form the VC-DATA-MODEL
    // https://www.w3.org/TR/vc-data-model/#jwt-encoding
    const jwtPayload = getJwtPayloadFromCredential(options.credential)

    if (!isDid(options.verificationMethod)) {
      throw new CredoError(`Only did identifiers are supported as verification method`)
    }

    const verificationMethod = await this.resolveVerificationMethod(agentContext, options.verificationMethod, [
      'assertionMethod',
    ])
    const key = getKeyFromVerificationMethod(verificationMethod)

    const jwt = await this.jwsService.createJwsCompact(agentContext, {
      payload: jwtPayload,
      key,
      protectedHeaderOptions: {
        typ: 'JWT',
        alg: options.alg,
        kid: options.verificationMethod,
      },
    })

    // TODO: this re-parses and validates the credential in the JWT, which is not necessary.
    // We should somehow create an instance of W3cJwtVerifiableCredential directly from the JWT
    const jwtVc = W3cJwtVerifiableCredential.fromSerializedJwt(jwt)

    return jwtVc
  }

  /**
   * Verifies the signature(s) of a credential
   *
   * @param credential the credential to be verified
   * @returns the verification result
   */
  public async verifyCredential(
    agentContext: AgentContext,
    options: W3cJwtVerifyCredentialOptions
  ): Promise<W3cVerifyCredentialResult> {
    // NOTE: this is mostly from the JSON-LD service that adds this option. Once we support
    // the same granular validation results, we can remove this and the user could just check
    // which of the validations failed. Supporting for consistency with the JSON-LD service for now.
    const verifyCredentialStatus = options.verifyCredentialStatus ?? true

    const validationResults: W3cVerifyCredentialResult = {
      isValid: false,
      validations: {},
    }

    try {
      let credential: W3cJwtVerifiableCredential
      try {
        // If instance is provided as input, we want to validate the credential (otherwise it's done in the fromSerializedJwt method below)
        if (options.credential instanceof W3cJwtVerifiableCredential) {
          MessageValidator.validateSync(options.credential.credential)
        }

        credential =
          options.credential instanceof W3cJwtVerifiableCredential
            ? options.credential
            : W3cJwtVerifiableCredential.fromSerializedJwt(options.credential)

        // Verify the JWT payload (verifies whether it's not expired, etc...)
        credential.jwt.payload.validate()

        validationResults.validations.dataModel = {
          isValid: true,
        }
      } catch (error) {
        validationResults.validations.dataModel = {
          isValid: false,
          error,
        }

        return validationResults
      }

      const issuerVerificationMethod = await this.getVerificationMethodForJwtCredential(agentContext, {
        credential,
        purpose: ['assertionMethod'],
      })
      const issuerPublicKey = getKeyFromVerificationMethod(issuerVerificationMethod)
      const issuerPublicJwk = getJwkFromKey(issuerPublicKey)

      let signatureResult: VerifyJwsResult | undefined = undefined
      try {
        // Verify the JWS signature
        signatureResult = await this.jwsService.verifyJws(agentContext, {
          jws: credential.jwt.serializedJwt,
          // We have pre-fetched the key based on the issuer/signer of the credential
          jwkResolver: () => issuerPublicJwk,
        })

        if (!signatureResult.isValid) {
          validationResults.validations.signature = {
            isValid: false,
            error: new CredoError('Invalid JWS signature'),
          }
        } else {
          validationResults.validations.signature = {
            isValid: true,
          }
        }
      } catch (error) {
        validationResults.validations.signature = {
          isValid: false,
          error,
        }
      }

      // Validate whether the credential is signed with the 'issuer' id
      // NOTE: this uses the verificationMethod.controller. We may want to use the verificationMethod.id?
      if (credential.issuerId !== issuerVerificationMethod.controller) {
        validationResults.validations.issuerIsSigner = {
          isValid: false,
          error: new CredoError(
            `Credential is signed using verification method ${issuerVerificationMethod.id}, while the issuer of the credential is '${credential.issuerId}'`
          ),
        }
      } else {
        validationResults.validations.issuerIsSigner = {
          isValid: true,
        }
      }

      // Validate whether the `issuer` of the credential is also the signer
      const issuerIsSigner = signatureResult?.signerKeys.some(
        (signerKey) => signerKey.fingerprint === issuerPublicKey.fingerprint
      )
      if (!issuerIsSigner) {
        validationResults.validations.issuerIsSigner = {
          isValid: false,
          error: new CredoError('Credential is not signed by the issuer of the credential'),
        }
      } else {
        validationResults.validations.issuerIsSigner = {
          isValid: true,
        }
      }

      // Validate credentialStatus
      if (verifyCredentialStatus && !credential.credentialStatus) {
        validationResults.validations.credentialStatus = {
          isValid: true,
        }
      } else if (verifyCredentialStatus && credential.credentialStatus) {
        validationResults.validations.credentialStatus = {
          isValid: false,
          error: new CredoError('Verifying credential status is not supported for JWT VCs'),
        }
      }

      validationResults.isValid = Object.values(validationResults.validations).every((v) => v.isValid)

      return validationResults
    } catch (error) {
      validationResults.error = error
      return validationResults
    }
  }

  /**
   * Signs a presentation including the credentials it includes
   *
   * @param presentation the presentation to be signed
   * @returns the signed presentation
   */
  public async signPresentation(
    agentContext: AgentContext,
    options: W3cJwtSignPresentationOptions
  ): Promise<W3cJwtVerifiablePresentation> {
    // Validate the instance
    MessageValidator.validateSync(options.presentation)

    // Get the JWT payload for the JWT based on the JWT Encoding rules form the VC-DATA-MODEL
    // https://www.w3.org/TR/vc-data-model/#jwt-encoding
    const jwtPayload = getJwtPayloadFromPresentation(options.presentation)

    // Set the nonce so it's included in the signature
    jwtPayload.additionalClaims.nonce = options.challenge
    jwtPayload.aud = options.domain

    const verificationMethod = await this.resolveVerificationMethod(agentContext, options.verificationMethod, [
      'authentication',
    ])

    const jwt = await this.jwsService.createJwsCompact(agentContext, {
      payload: jwtPayload,
      key: getKeyFromVerificationMethod(verificationMethod),
      protectedHeaderOptions: {
        typ: 'JWT',
        alg: options.alg,
        kid: options.verificationMethod,
      },
    })

    // TODO: this re-parses and validates the presentation in the JWT, which is not necessary.
    // We should somehow create an instance of W3cJwtVerifiablePresentation directly from the JWT
    const jwtVp = W3cJwtVerifiablePresentation.fromSerializedJwt(jwt)

    return jwtVp
  }

  /**
   * Verifies a presentation including the credentials it includes
   *
   * @param presentation the presentation to be verified
   * @returns the verification result
   */
  public async verifyPresentation(
    agentContext: AgentContext,
    options: W3cJwtVerifyPresentationOptions
  ): Promise<W3cVerifyPresentationResult> {
    const validationResults: W3cVerifyPresentationResult = {
      isValid: false,
      validations: {},
    }

    try {
      let presentation: W3cJwtVerifiablePresentation
      try {
        // If instance is provided as input, we want to validate the presentation
        if (options.presentation instanceof W3cJwtVerifiablePresentation) {
          MessageValidator.validateSync(options.presentation.presentation)
        }

        presentation =
          options.presentation instanceof W3cJwtVerifiablePresentation
            ? options.presentation
            : W3cJwtVerifiablePresentation.fromSerializedJwt(options.presentation)

        // Verify the JWT payload (verifies whether it's not expired, etc...)
        presentation.jwt.payload.validate()

        // Make sure challenge matches nonce
        if (options.challenge !== presentation.jwt.payload.additionalClaims.nonce) {
          throw new CredoError(`JWT payload 'nonce' does not match challenge '${options.challenge}'`)
        }

        const audArray = asArray(presentation.jwt.payload.aud)
        if (options.domain && !audArray.includes(options.domain)) {
          throw new CredoError(`JWT payload 'aud' does not include domain '${options.domain}'`)
        }

        validationResults.validations.dataModel = {
          isValid: true,
        }
      } catch (error) {
        validationResults.validations.dataModel = {
          isValid: false,
          error,
        }

        return validationResults
      }

      const proverVerificationMethod = await this.getVerificationMethodForJwtCredential(agentContext, {
        credential: presentation,
        purpose: ['authentication'],
      })
      const proverPublicKey = getKeyFromVerificationMethod(proverVerificationMethod)
      const proverPublicJwk = getJwkFromKey(proverPublicKey)

      const getTrustedCertificatesForVerification = agentContext.dependencyManager.isRegistered(X509ModuleConfig)
        ? agentContext.dependencyManager.resolve(X509ModuleConfig).getTrustedCertificatesForVerification
        : undefined

      let signatureResult: VerifyJwsResult | undefined = undefined
      try {
        // Verify the JWS signature
        signatureResult = await this.jwsService.verifyJws(agentContext, {
          jws: presentation.jwt.serializedJwt,
          // We have pre-fetched the key based on the singer/holder of the presentation
          jwkResolver: () => proverPublicJwk,
          trustedCertificates:
            options.trustedCertificates ??
            (await getTrustedCertificatesForVerification?.(agentContext, options.verificationContext)),
        })

        if (!signatureResult.isValid) {
          validationResults.validations.presentationSignature = {
            isValid: false,
            error: new CredoError('Invalid JWS signature on presentation'),
          }
        } else {
          validationResults.validations.presentationSignature = {
            isValid: true,
          }
        }
      } catch (error) {
        validationResults.validations.presentationSignature = {
          isValid: false,
          error,
        }
      }

      // Validate whether the presentation is signed with the 'holder' id
      // NOTE: this uses the verificationMethod.controller. We may want to use the verificationMethod.id?
      if (presentation.holderId && proverVerificationMethod.controller !== presentation.holderId) {
        validationResults.validations.holderIsSigner = {
          isValid: false,
          error: new CredoError(
            `Presentation is signed using verification method ${proverVerificationMethod.id}, while the holder of the presentation is '${presentation.holderId}'`
          ),
        }
      } else {
        // If no holderId is present, this validation passes by default as there can't be
        // a mismatch between the 'holder' property and the signer of the presentation.
        validationResults.validations.holderIsSigner = {
          isValid: true,
        }
      }

      // To keep things simple, we only support JWT VCs in JWT VPs for now
      const credentials = asArray(presentation.presentation.verifiableCredential)

      // Verify all credentials in parallel, and await the result
      validationResults.validations.credentials = await Promise.all(
        credentials.map(async (credential) => {
          if (credential instanceof W3cJsonLdVerifiableCredential) {
            return {
              isValid: false,
              error: new CredoError(
                'Credential is of format ldp_vc. presentations in jwt_vp format can only contain credentials in jwt_vc format'
              ),
              validations: {},
            }
          }

          const credentialResult = await this.verifyCredential(agentContext, {
            credential,
            verifyCredentialStatus: options.verifyCredentialStatus,
          })

          let credentialSubjectAuthentication: SingleValidationResult

          // Check whether any of the credentialSubjectIds for each credential is the same as the controller of the verificationMethod
          // This authenticates the presentation creator controls one of the credentialSubject ids.
          // NOTE: this doesn't take into account the case where the credentialSubject is no the holder. In the
          // future we can add support for other flows, but for now this is the most common use case.
          // TODO: should this be handled on a higher level? I don't really see it being handled in the jsonld lib
          // or in the did-jwt-vc lib (it seems they don't even verify the credentials itself), but we probably need some
          // more experience on the use cases before we loosen the restrictions (as it means we need to handle it on a higher layer).
          const credentialSubjectIds = credential.credentialSubjectIds
          const presentationAuthenticatesCredentialSubject = credentialSubjectIds.some(
            (subjectId) => proverVerificationMethod.controller === subjectId
          )

          if (credentialSubjectIds.length > 0 && !presentationAuthenticatesCredentialSubject) {
            credentialSubjectAuthentication = {
              isValid: false,
              error: new CredoError(
                'Credential has one or more credentialSubject ids, but presentation does not authenticate credential subject'
              ),
            }
          } else {
            credentialSubjectAuthentication = {
              isValid: true,
            }
          }

          return {
            ...credentialResult,
            isValid: credentialResult.isValid && credentialSubjectAuthentication.isValid,
            validations: {
              ...credentialResult.validations,
              credentialSubjectAuthentication,
            },
          }
        })
      )

      // Deeply nested check whether all validations have passed
      validationResults.isValid = Object.values(validationResults.validations).every((v) =>
        Array.isArray(v) ? v.every((vv) => vv.isValid) : v.isValid
      )

      return validationResults
    } catch (error) {
      validationResults.error = error
      return validationResults
    }
  }

  private async resolveVerificationMethod(
    agentContext: AgentContext,
    verificationMethod: string,
    allowsPurposes?: DidPurpose[]
  ): Promise<VerificationMethod> {
    const didResolver = agentContext.dependencyManager.resolve(DidResolverService)
    const didDocument = await didResolver.resolveDidDocument(agentContext, verificationMethod)

    return didDocument.dereferenceKey(verificationMethod, allowsPurposes)
  }

  /**
   * This method tries to find the verification method associated with the JWT credential or presentation.
   * This verification method can then be used to verify the credential or presentation signature.
   *
   * The following methods are used to extract the verification method:
   *  - verification method is resolved based on the `kid` in the protected header
   *    - either as absolute reference (e.g. `did:example:123#key-1`)
   *    - or as relative reference to the `iss` of the JWT (e.g. `iss` is `did:example:123` and `kid` is `#key-1`)
   *  - the did document is resolved based on the `iss` field, after which the verification method is extracted based on the `alg`
   *    used to sign the JWT and the specified `purpose`. Only a single verification method may be present, and in all other cases,
   *    an error is thrown.
   *
   * The signer (`iss`) of the JWT is verified against the `controller` of the verificationMethod resolved in the did
   * document. This means if the `iss` of a credential is `did:example:123` and the controller of the verificationMethod
   * is `did:example:456`, an error is thrown to prevent the JWT from successfully being verified.
   *
   * In addition the JWT must conform to one of the following rules:
   *   - MUST be a credential and have an `iss` field and MAY have an absolute or relative `kid`
   *   - MUST not be a credential AND ONE of the following:
   *      - have an `iss` field and MAY have an absolute or relative `kid`
   *      - does not have an `iss` field and MUST have an absolute `kid`
   */
  private async getVerificationMethodForJwtCredential(
    agentContext: AgentContext,
    options: {
      credential: W3cJwtVerifiableCredential | W3cJwtVerifiablePresentation
      purpose?: DidPurpose[]
    }
  ) {
    const { credential, purpose } = options
    const kid = credential.jwt.header.kid

    const didResolver = agentContext.dependencyManager.resolve(DidResolverService)

    // The signerId is the `holder` of the presentation or the `issuer` of the credential
    // For a credential only the `iss` COULD be enough to resolve the signer key (see method comments)
    const signerId = credential.jwt.payload.iss

    let verificationMethod: VerificationMethod

    // If the kid starts with # we assume it is a relative did url, and we resolve it based on the `iss` and the `kid`
    if (kid?.startsWith('#')) {
      if (!signerId) {
        throw new CredoError(`JWT 'kid' MUST be absolute when when no 'iss' is present in JWT payload`)
      }

      const didDocument = await didResolver.resolveDidDocument(agentContext, signerId)
      verificationMethod = didDocument.dereferenceKey(`${signerId}${kid}`, purpose)
    }
    // this is a full did url (todo check if it contains a #)
    else if (kid && isDid(kid)) {
      const didDocument = await didResolver.resolveDidDocument(agentContext, kid)

      verificationMethod = didDocument.dereferenceKey(kid, purpose)

      if (signerId && didDocument.id !== signerId) {
        throw new CredoError(`kid '${kid}' does not match id of signer (holder/issuer) '${signerId}'`)
      }
    } else {
      if (!signerId) {
        throw new CredoError(`JWT 'iss' MUST be present in payload when no 'kid' is specified`)
      }

      // Find the verificationMethod in the did document based on the alg and proofPurpose
      const jwkClass = getJwkClassFromJwaSignatureAlgorithm(credential.jwt.header.alg)
      if (!jwkClass) throw new CredoError(`Unsupported JWT alg '${credential.jwt.header.alg}'`)

      const { supportedVerificationMethodTypes } = getKeyDidMappingByKeyType(jwkClass.keyType)

      const didDocument = await didResolver.resolveDidDocument(agentContext, signerId)
      const verificationMethods =
        didDocument.assertionMethod
          ?.map((v) => (typeof v === 'string' ? didDocument.dereferenceVerificationMethod(v) : v))
          .filter((v) => supportedVerificationMethodTypes.includes(v.type)) ?? []

      if (verificationMethods.length === 0) {
        throw new CredoError(
          `No verification methods found for signer '${signerId}' and key type '${jwkClass.keyType}' for alg '${credential.jwt.header.alg}'. Unable to determine which public key is associated with the credential.`
        )
      } else if (verificationMethods.length > 1) {
        throw new CredoError(
          `Multiple verification methods found for signer '${signerId}' and key type '${jwkClass.keyType}' for alg '${credential.jwt.header.alg}'. Unable to determine which public key is associated with the credential.`
        )
      }

      verificationMethod = verificationMethods[0]
    }

    // Verify the controller of the verificationMethod matches the signer of the credential
    if (signerId && verificationMethod.controller !== signerId) {
      throw new CredoError(
        `Verification method controller '${verificationMethod.controller}' does not match the signer '${signerId}'`
      )
    }

    return verificationMethod
  }

  // temporarily disable no unused var
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  public async revokeCredential(_agentContext: AgentContext, _options: RevokeCredentialOptions) {
    // revoke jwt cred
    throw new CredoError(`Revocation support not implemented for jwtVc`)
  }
}
