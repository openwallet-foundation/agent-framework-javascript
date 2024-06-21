import type { OpenId4VcVerificationSessionRecord } from './repository'
import type {
  OpenId4VcJwtIssuer,
  OpenId4VcSiopAuthorizationResponsePayload,
  OpenId4VcSiopIdTokenPayload,
} from '../shared'
import type {
  DifPresentationExchangeDefinition,
  DifPresentationExchangeSubmission,
  DifPresentationExchangeDefinitionV2,
  VerifiablePresentation,
} from '@credo-ts/core'

export interface OpenId4VcSiopCreateAuthorizationRequestOptions {
  /**
   * Signing information for the request JWT. This will be used to sign the request JWT
   * and to set the client_id for registration of client_metadata.
   */
  requestSigner: OpenId4VcJwtIssuer

  /**
   * Whether to reuqest an ID Token. Enabled by defualt when `presentationExchange` is not provided,
   * disabled by default when `presentationExchange` is provided.
   */
  idToken?: boolean

  /**
   * A DIF Presentation Definition (v2) can be provided to request a Verifiable Presentation using OpenID4VP.
   */
  presentationExchange?: {
    definition: DifPresentationExchangeDefinitionV2
  }
}

export interface OpenId4VcSiopVerifyAuthorizationResponseOptions {
  /**
   * The authorization response received from the OpenID Provider (OP).
   */
  authorizationResponse: OpenId4VcSiopAuthorizationResponsePayload
}

export interface OpenId4VcSiopCreateAuthorizationRequestReturn {
  authorizationRequest: string
  verificationSession: OpenId4VcVerificationSessionRecord
}

/**
 * Either `idToken` and/or `presentationExchange` will be present.
 */
export interface OpenId4VcSiopVerifiedAuthorizationResponse {
  idToken?: {
    payload: OpenId4VcSiopIdTokenPayload
  }

  presentationExchange?: {
    submission: DifPresentationExchangeSubmission
    definition: DifPresentationExchangeDefinition
    presentations: Array<VerifiablePresentation>
  }
}

export interface OpenId4VcSiopCreateVerifierOptions {
  /**
   * Id of the verifier, not the id of the verifier record. Will be exposed publicly
   */
  verifierId?: string
}
