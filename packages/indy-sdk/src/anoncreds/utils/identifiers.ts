/**
 * NOTE: this file is available in both the indy-sdk and indy-vdr packages. If making changes to
 * this file, make sure to update both files if applicable.
 */

import {
  unqualifiedSchemaIdRegex,
  unqualifiedCredentialDefinitionIdRegex,
  unqualifiedRevocationRegistryIdRegex,
  didIndyCredentialDefinitionIdRegex,
  didIndyRevocationRegistryIdRegex,
  didIndySchemaIdRegex,
  didIndyRegex,
} from '@credo-ts/anoncreds'

// combines both legacy and did:indy anoncreds identifiers and also the issuer id
const indySdkAnonCredsRegexes = [
  // NOTE: we only include the qualified issuer id here, as we don't support registering objects based on legacy issuer ids.
  // you can still resolve using legacy issuer ids, but you need to use the full did:indy identifier when registering.
  // As we find a matching anoncreds registry based on the issuerId only when creating an object, this will make sure
  // it will throw an no registry found for identifier error.
  // issuer id
  didIndyRegex,

  // schema
  didIndySchemaIdRegex,
  unqualifiedSchemaIdRegex,

  // credential definition
  didIndyCredentialDefinitionIdRegex,
  unqualifiedCredentialDefinitionIdRegex,

  // revocation registry
  unqualifiedRevocationRegistryIdRegex,
  didIndyRevocationRegistryIdRegex,
]

export const indySdkAnonCredsRegistryIdentifierRegex = new RegExp(
  indySdkAnonCredsRegexes.map((r) => r.source).join('|')
)

export function getDidIndySchemaId(namespace: string, unqualifiedDid: string, name: string, version: string) {
  return `did:indy:${namespace}:${unqualifiedDid}/anoncreds/v0/SCHEMA/${name}/${version}`
}

export function getDidIndyCredentialDefinitionId(
  namespace: string,
  unqualifiedDid: string,
  schemaSeqNo: string | number,
  tag: string
) {
  return `did:indy:${namespace}:${unqualifiedDid}/anoncreds/v0/CLAIM_DEF/${schemaSeqNo}/${tag}`
}

export function getDidIndyRevocationRegistryDefinitionId(
  namespace: string,
  unqualifiedDid: string,
  schemaSeqNo: string | number,
  credentialDefinitionTag: string,
  revocationRegistryTag: string
) {
  return `did:indy:${namespace}:${unqualifiedDid}/anoncreds/v0/REV_REG_DEF/${schemaSeqNo}/${credentialDefinitionTag}/${revocationRegistryTag}`
}
