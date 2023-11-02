import type { HashName, JwaSignatureAlgorithm } from '@aries-framework/core'
import type { DisclosureFrame } from 'jwt-sd'

export type SdJwtCreateOptions<Payload extends Record<string, unknown> = Record<string, unknown>> = {
  holderDidUrl: string
  issuerDidUrl: string
  issuerOverrideJsonWebAlgorithm?: JwaSignatureAlgorithm
  disclosureFrame?: DisclosureFrame<Payload>
  hashingAlgorithm?: HashName
}

export type SdJwtReceiveOptions = {
  issuerDidUrl: string
  holderDidUrl: string
}

/**
 * `includedDisclosureIndices` is not the best API, but it is the best alternative until something like `PEX` is supported
 */
export type SdJwtPresentOptions = {
  holderOverrideJsonWebAlgorithm?: JwaSignatureAlgorithm
  includedDisclosureIndices?: Array<number>

  /**
   * This information is received out-of-band from the verifier.
   * The claims will be used to create a normal JWT, used for key binding.
   */
  verifierMetadata: {
    verifierDid: string
    nonce: string
    issuedAt: number
  }
}

/**
 * `requiredClaimKeys` is not the best API, but it is the best alternative until something like `PEX` is supported
 */
export type SdJwtVerifyOptions = {
  holderDidUrl: string
  verifierDid: string
  requiredClaimKeys?: Array<string>
}
