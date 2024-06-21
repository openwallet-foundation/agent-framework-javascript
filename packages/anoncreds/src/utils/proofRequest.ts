import type { AnonCredsProofRequest } from '../models/exchange'

import {
  isUnqualifiedCredentialDefinitionId,
  isUnqualifiedSchemaId,
  isUnqualifiedIndyDid,
  isUnqualifiedRevocationRegistryId,
} from './indyIdentifiers'

export function proofRequestUsesUnqualifiedIdentifiers(proofRequest: AnonCredsProofRequest) {
  // We assume that if any identifier is unqualified, all of them are unqualified as well
  return [
    ...Object.values(proofRequest.requested_attributes),
    ...Object.values(proofRequest.requested_predicates),
  ].some((attribute) =>
    attribute.restrictions?.some(
      (restriction) =>
        (restriction.cred_def_id && isUnqualifiedCredentialDefinitionId(restriction.cred_def_id)) ||
        (restriction.schema_id && isUnqualifiedSchemaId(restriction.schema_id)) ||
        (restriction.issuer_did && isUnqualifiedIndyDid(restriction.issuer_did)) ||
        (restriction.issuer_id && isUnqualifiedIndyDid(restriction.issuer_id)) ||
        (restriction.schema_issuer_did && isUnqualifiedIndyDid(restriction.schema_issuer_did)) ||
        (restriction.schema_issuer_id && isUnqualifiedIndyDid(restriction.schema_issuer_id)) ||
        (restriction.rev_reg_id && isUnqualifiedRevocationRegistryId(restriction.rev_reg_id))
    )
  )
}
