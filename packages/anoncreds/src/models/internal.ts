import type { AnonCredsClaimRecord } from '../utils/credential'

export interface AnonCredsCredentialInfo {
  credentialId: string
  attributes: AnonCredsClaimRecord
  schemaId: string
  credentialDefinitionId: string
  revocationRegistryId: string | null
  credentialRevocationId: string | null
  methodName: string
  createdAt: Date
  updatedAt: Date
  linkSecretId: string
}

export interface AnonCredsRequestedAttributeMatch {
  credentialId: string
  timestamp?: number
  revealed: boolean
  credentialInfo: AnonCredsCredentialInfo
  revoked?: boolean
}

export interface AnonCredsRequestedPredicateMatch {
  credentialId: string
  timestamp?: number
  credentialInfo: AnonCredsCredentialInfo
  revoked?: boolean
}

export interface AnonCredsSelectedCredentials {
  attributes: Record<string, AnonCredsRequestedAttributeMatch>
  predicates: Record<string, AnonCredsRequestedPredicateMatch>
  selfAttestedAttributes: Record<string, string>
}

export interface AnonCredsLinkSecretBlindingData {
  v_prime: string
  vr_prime: string | null
}
