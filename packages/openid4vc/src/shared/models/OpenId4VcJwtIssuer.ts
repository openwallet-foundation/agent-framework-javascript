import type { Jwk } from '@credo-ts/core'

interface OpenId4VcJwtIssuerDid {
  method: 'did'
  didUrl: string
}

export interface OpenId4VcIssuerX5c {
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

interface OpenId4VcJwtIssuerJwk {
  method: 'jwk'
  jwk: Jwk
}

export interface OpenId4VcJwtIssuerFederation {
  method: 'openid-federation'
}

export type OpenId4VcJwtIssuer =
  | OpenId4VcJwtIssuerDid
  | OpenId4VcIssuerX5c
  | OpenId4VcJwtIssuerJwk
  | OpenId4VcJwtIssuerFederation
