import type { Key } from '@credo-ts/core'

export interface ResolvedDidCommService {
  id: string
  serviceEndpoint: string
  recipientKeys: Key[]
  routingKeys: Key[]
}

export type ProtocolVersion = `${number}.${number}`
export interface PlaintextMessage {
  '@type': string
  '@id': string
  '~thread'?: {
    thid?: string
    pthid?: string
  }
  [key: string]: unknown
}

export type EncryptedMessage = {
  /**
   * The "protected" member MUST be present and contain the value
   * BASE64URL(UTF8(JWE Protected Header)) when the JWE Protected
   * Header value is non-empty; otherwise, it MUST be absent.  These
   * Header Parameter values are integrity protected.
   */
  protected: string

  /**
   * The "iv" member MUST be present and contain the value
   * BASE64URL(JWE Initialization Vector) when the JWE Initialization
   * Vector value is non-empty; otherwise, it MUST be absent.
   */
  iv: string

  /**
   * The "ciphertext" member MUST be present and contain the value
   * BASE64URL(JWE Ciphertext).
   */
  ciphertext: string

  /**
   * The "tag" member MUST be present and contain the value
   * BASE64URL(JWE Authentication Tag) when the JWE Authentication Tag
   * value is non-empty; otherwise, it MUST be absent.
   */
  tag: string
}

export enum DidCommMimeType {
  V0 = 'application/ssi-agent-wire',
  V1 = 'application/didcomm-envelope-enc',
}

export interface OutboundPackage {
  payload: EncryptedMessage
  responseRequested?: boolean
  endpoint?: string
  connectionId?: string
}
