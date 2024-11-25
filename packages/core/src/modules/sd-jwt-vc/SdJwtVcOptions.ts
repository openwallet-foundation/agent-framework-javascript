import type { JwkJson, Jwk, HashName } from '../../crypto'

// TODO: extend with required claim names for input (e.g. vct)
export type SdJwtVcPayload = Record<string, unknown>
export type SdJwtVcHeader = Record<string, unknown>

export interface IDisclosureFrame {
  _sd?: string[]
  _sd_decoy?: number
  [x: string]: string[] | number | IDisclosureFrame | undefined
}

export interface IPresentationFrame {
  [x: string]: boolean | IPresentationFrame
}

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

export interface SdJwtVcIssuerX5c {
  method: 'x5c'
  /**
   *
   * Array of base64-encoded certificate strings in the DER-format.
   *
   * The certificate containing the public key corresponding to the key used to digitally sign the JWS MUST be the first certificate.
   */
  x5c: string[]

  /**
   * The issuer of the JWT. Should be a HTTPS URI.
   *
   * The issuer value must either match a `uniformResourceIdentifier` SAN entry of the leaf entity certificate
   * or the domain name in the `iss` value matches a `dNSName` SAN entry of the leaf-entity certificate.
   */
  issuer: string
}

// We support jwk and did based binding for the holder at the moment
export type SdJwtVcHolderBinding = SdJwtVcHolderDidBinding | SdJwtVcHolderJwkBinding

// We only support did based issuance currently, but we might want to add support
// for x509 or issuer metadata (as defined in SD-JWT VC) in the future
export type SdJwtVcIssuer = SdJwtVcIssuerDid | SdJwtVcIssuerX5c

export interface SdJwtVcSignOptions<Payload extends SdJwtVcPayload = SdJwtVcPayload> {
  payload: Payload

  /**
   * If holder is not provided, we don't bind the SD-JWT VC to a key (so bearer VC)
   */
  holder?: SdJwtVcHolderBinding
  issuer: SdJwtVcIssuer
  disclosureFrame?: IDisclosureFrame

  /**
   * Default of sha-256 will be used if not provided
   */
  hashingAlgorithm?: HashName
}

// TODO: use the payload type once types are fixed
// eslint-disable-next-line @typescript-eslint/no-unused-vars
export type SdJwtVcPresentOptions<Payload extends SdJwtVcPayload = SdJwtVcPayload> = {
  compactSdJwtVc: string

  /**
   * Use true to disclose everything
   */
  presentationFrame?: IPresentationFrame

  /**
   * This information is received out-of-band from the verifier.
   * The claims will be used to create a normal JWT, used for key binding.
   *
   * If not defined, a KB-JWT will not be created
   */
  verifierMetadata?: {
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

  /**
   * Whether to fetch the `vct` type metadata if the `vct` is an https URL.
   *
   * It will will not influence the verification result if fetching of type metadata fails
   */
  fetchTypeMetadata?: boolean
}
