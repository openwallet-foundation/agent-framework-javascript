import type { ProofPurpose, W3cJsonLdVerifiablePresentation } from './data-integrity'
import type { W3cJsonLdVerifiableCredential } from './data-integrity/models/W3cJsonLdVerifiableCredential'
import type { W3cJwtVerifiableCredential } from './jwt-vc/W3cJwtVerifiableCredential'
import type { W3cJwtVerifiablePresentation } from './jwt-vc/W3cJwtVerifiablePresentation'
import type { ClaimFormat, W3cVerifiableCredential } from './models'
import type { W3cCredential } from './models/credential/W3cCredential'
import type { W3cPresentation } from './models/presentation/W3cPresentation'
import type { JwaSignatureAlgorithm } from '../../crypto/jose/jwa'
import type { SingleOrArray } from '../../utils/type'
import type { EncodedX509Certificate } from '../x509'

export type W3cSignCredentialOptions<Format extends ClaimFormat.JwtVc | ClaimFormat.LdpVc | undefined = undefined> =
  Format extends ClaimFormat.JwtVc
    ? W3cJwtSignCredentialOptions
    : Format extends ClaimFormat.LdpVc
    ? W3cJsonLdSignCredentialOptions
    : W3cJwtSignCredentialOptions | W3cJsonLdSignCredentialOptions
export type W3cVerifyCredentialOptions<Format extends ClaimFormat.JwtVc | ClaimFormat.LdpVc | undefined = undefined> =
  Format extends ClaimFormat.JwtVc
    ? W3cJwtVerifyCredentialOptions
    : Format extends ClaimFormat.LdpVc
    ? W3cJsonLdVerifyCredentialOptions
    : W3cJwtVerifyCredentialOptions | W3cJsonLdVerifyCredentialOptions
export type W3cSignPresentationOptions<Format extends ClaimFormat.JwtVp | ClaimFormat.LdpVp | undefined = undefined> =
  Format extends ClaimFormat.JwtVp
    ? W3cJwtSignPresentationOptions
    : Format extends ClaimFormat.LdpVp
    ? W3cJsonLdSignPresentationOptions
    : W3cJwtSignPresentationOptions | W3cJsonLdSignPresentationOptions
export type W3cVerifyPresentationOptions = W3cJwtVerifyPresentationOptions | W3cJsonLdVerifyPresentationOptions

interface W3cSignCredentialOptionsBase {
  /**
   * The format of the credential to be signed.
   *
   * @see https://identity.foundation/claim-format-registry
   */
  format: ClaimFormat

  /**
   * The credential to be signed.
   */
  credential: W3cCredential

  /**
   * URI of the verificationMethod to be used for signing the credential.
   *
   * Must be a valid did url pointing to a key.
   */
  verificationMethod: string
}

export interface W3cJwtSignCredentialOptions extends W3cSignCredentialOptionsBase {
  format: ClaimFormat.JwtVc

  /**
   * The alg to be used for signing the credential.
   *
   * Must be a valid JWA signature algorithm.
   */
  alg: JwaSignatureAlgorithm
}

export interface W3cJsonLdSignCredentialOptions extends W3cSignCredentialOptionsBase {
  /**
   * The format of the credential to be signed. Must be either `jwt_vc` or `ldp_vc`.
   * @see https://identity.foundation/claim-format-registry
   */
  format: ClaimFormat.LdpVc

  /**
   * The proofType to be used for signing the credential.
   *
   * Must be a valid Linked Data Signature suite.
   */
  proofType: string

  proofPurpose?: ProofPurpose
  created?: string
}

interface W3cVerifyCredentialOptionsBase {
  credential: unknown

  /**
   * Whether to verify the credentialStatus, if present.
   */
  verifyCredentialStatus?: boolean
}

export interface W3cJwtVerifyCredentialOptions extends W3cVerifyCredentialOptionsBase {
  credential: W3cJwtVerifiableCredential | string // string must be encoded VC JWT
}

export interface W3cJsonLdVerifyCredentialOptions extends W3cVerifyCredentialOptionsBase {
  credential: W3cJsonLdVerifiableCredential
  proofPurpose?: ProofPurpose
}

export interface W3cCreatePresentationOptions {
  credentials: SingleOrArray<W3cVerifiableCredential>
  id?: string
  holder?: string
}

interface W3cSignPresentationOptionsBase {
  /**
   * The format of the presentation to be signed.
   *
   * @see https://identity.foundation/claim-format-registry
   */
  format: ClaimFormat

  /**
   * The presentation to be signed.
   */
  presentation: W3cPresentation

  /**
   * URI of the verificationMethod to be used for signing the presentation.
   *
   * Must be a valid did url pointing to a key.
   */
  verificationMethod: string

  /**
   * The challenge / nonce to be used in the proof to prevent replay attacks.
   */
  challenge: string

  /**
   * The domain / aud to be used in the proof to assert the intended recipient.
   */
  domain?: string
}

export interface W3cJsonLdSignPresentationOptions extends W3cSignPresentationOptionsBase {
  format: ClaimFormat.LdpVp

  /**
   * The proofType to be used for signing the presentation.
   *
   * Must be a valid Linked Data Signature suite.
   */
  proofType: string

  proofPurpose: ProofPurpose
}

export interface W3cJwtSignPresentationOptions extends W3cSignPresentationOptionsBase {
  format: ClaimFormat.JwtVp

  /**
   * The alg to be used for signing the presentation.
   *
   * Must be a valid JWA signature algorithm.
   */
  alg: JwaSignatureAlgorithm
}

interface W3cVerifyPresentationOptionsBase {
  /**
   * The presentation to be verified.
   */
  presentation: unknown

  /**
   * The challenge / nonce that must present in the presentation prevent replay attacks.
   */
  challenge: string

  /**
   * The domain / aud to be used in the proof to assert the intended recipient.
   */
  domain?: string

  /**
   * Whether to verify the credentialStatus, if present.
   */
  verifyCredentialStatus?: boolean
}

export interface W3cJwtVerifyPresentationOptions extends W3cVerifyPresentationOptionsBase {
  presentation: W3cJwtVerifiablePresentation | string // string must be encoded VP JWT
  trustedCertificates?: EncodedX509Certificate[]
}

export interface W3cJsonLdVerifyPresentationOptions extends W3cVerifyPresentationOptionsBase {
  presentation: W3cJsonLdVerifiablePresentation
  purpose?: ProofPurpose
}

export interface StoreCredentialOptions {
  credential: W3cVerifiableCredential
}

/**
 * Interface for W3cCredentialsApi.revokeCredential. revoke a w3c credential.
 */
export interface RevokeCredentialOptions {
  credentialRecordId: string
}
