import type { AnonCredsCredentialValue } from '../utils/credential'

export const anonCredsPredicateType = ['>=', '>', '<=', '<'] as const
export type AnonCredsPredicateType = (typeof anonCredsPredicateType)[number]

export interface AnonCredsProofRequestRestriction {
  schema_id?: string
  schema_issuer_id?: string
  schema_name?: string
  schema_version?: string
  issuer_id?: string
  cred_def_id?: string
  rev_reg_id?: string

  // Deprecated, but kept for backwards compatibility with legacy indy anoncreds implementations
  schema_issuer_did?: string
  issuer_did?: string

  // the following keys can be used for every `attribute name` in credential.
  [key: `attr::${string}::marker`]: '1' | '0'
  [key: `attr::${string}::value`]: string
}

export interface AnonCredsNonRevokedInterval {
  from?: number
  to?: number
}

export interface AnonCredsCredentialOffer {
  schema_id: string
  cred_def_id: string
  nonce: string
  key_correctness_proof: Record<string, unknown>
}

export interface AnonCredsCredentialRequest {
  // prover_did is deprecated, however it is kept for backwards compatibility with legacy anoncreds implementations
  prover_did?: string
  entropy?: string
  cred_def_id: string
  blinded_ms: Record<string, unknown>
  blinded_ms_correctness_proof: Record<string, unknown>
  nonce: string
}

export type AnonCredsCredentialValues = Record<string, AnonCredsCredentialValue>

export interface AnonCredsCredential {
  schema_id: string
  cred_def_id: string
  rev_reg_id?: string
  values: Record<string, AnonCredsCredentialValue>
  signature: unknown
  signature_correctness_proof: unknown
  rev_reg?: unknown
  witness?: unknown
}

export interface AnonCredsProof {
  requested_proof: {
    revealed_attrs: Record<
      string,
      {
        sub_proof_index: number
        raw: string
        encoded: string
      }
    >
    // revealed_attr_groups is only defined if there's a requested attribute using `names`
    revealed_attr_groups?: Record<
      string,
      {
        sub_proof_index: number
        values: {
          [key: string]: {
            raw: string
            encoded: string
          }
        }
      }
    >
    unrevealed_attrs: Record<
      string,
      {
        sub_proof_index: number
      }
    >
    self_attested_attrs: Record<string, string>

    predicates: Record<string, { sub_proof_index: number }>
  }
  // TODO: extend types for proof property
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  proof: any
  identifiers: Array<{
    schema_id: string
    cred_def_id: string
    rev_reg_id?: string
    timestamp?: number
  }>
}

export interface AnonCredsRequestedAttribute {
  name?: string
  names?: string[]
  restrictions?: AnonCredsProofRequestRestriction[]
  non_revoked?: AnonCredsNonRevokedInterval
}

export interface AnonCredsRequestedPredicate {
  name: string
  p_type: AnonCredsPredicateType
  p_value: number
  restrictions?: AnonCredsProofRequestRestriction[]
  non_revoked?: AnonCredsNonRevokedInterval
}

export interface AnonCredsProofRequest {
  name: string
  version: string
  nonce: string
  requested_attributes: Record<string, AnonCredsRequestedAttribute>
  requested_predicates: Record<string, AnonCredsRequestedPredicate>
  non_revoked?: AnonCredsNonRevokedInterval
  ver?: '1.0' | '2.0'
}
