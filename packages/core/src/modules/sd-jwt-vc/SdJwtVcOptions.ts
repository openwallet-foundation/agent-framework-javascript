import type { JwkJson, Jwk } from '../../crypto'
import type { HashName } from '../../utils'
import type { DisclosureFrame, PresentationFrame } from '@sd-jwt/core'

// TODO: extend with required claim names for input (e.g. vct)
export type SdJwtVcPayload = Record<string, unknown>
export type SdJwtVcHeader = Record<string, unknown>

export interface SdJwtVcHolderDidBinding {
  method: 'did'
  didUrl: string
}

export interface SdJwtVcHolderJwkBinding {
  method: 'jwk'
  jwk: JwkJson | Jwk
}

export interface SdJwtVcIssuerDid {
  method: 'did'
  // didUrl referencing a specific key in a did document.
  didUrl: string
}

// We support jwk and did based binding for the holder at the moment
export type SdJwtVcHolderBinding = SdJwtVcHolderDidBinding | SdJwtVcHolderJwkBinding

// We only support did based issuance currently, but we might want to add support
// for x509 or issuer metadata (as defined in SD-JWT VC) in the future
export type SdJwtVcIssuer = SdJwtVcIssuerDid

export interface SdJwtVcSignOptions<Payload extends SdJwtVcPayload = SdJwtVcPayload> {
  payload: Payload
  holder: SdJwtVcHolderBinding
  issuer: SdJwtVcIssuer
  disclosureFrame?: DisclosureFrame<Payload>

  /**
   * Default of sha2-256 will be used if not provided
   */
  hashingAlgorithm?: HashName
}

export type SdJwtVcPresentOptions<Payload extends SdJwtVcPayload = SdJwtVcPayload> = {
  compactSdJwtVc: string

  /**
   * Use true to disclose everything
   */
  presentationFrame: PresentationFrame<Payload> | true

  /**
   * This information is received out-of-band from the verifier.
   * The claims will be used to create a normal JWT, used for key binding.
   */
  verifierMetadata: {
    audience: string
    nonce: string
    issuedAt: number
  }
}

export type SdJwtVcVerifyOptions = {
  compactSdJwtVc: string

  /**
   * If the key binding object is present, the sd-jwt is required to have a key binding jwt attached
   * and will be validated against the provided key binding options.
   */
  keyBinding?: {
    /**
     * The expected `aud` value in the payload of the KB-JWT. The value of this is dependant on the
     * exchange protocol used.
     */
    audience: string

    /**
     * The expected `nonce` value in the payload of the KB-JWT. The value of this is dependant on the
     * exchange protocol used.
     */
    nonce: string
  }

  // TODO: update to requiredClaimFrame
  requiredClaimKeys?: Array<string>
}
