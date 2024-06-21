import type { AnonCredsCredentialDefinition, AnonCredsRevocationRegistryDefinition, AnonCredsSchema } from '../models'

import { CredoError } from '@credo-ts/core'

const didIndyAnonCredsBase =
  /(did:indy:((?:[a-z][_a-z0-9-]*)(?::[a-z][_a-z0-9-]*)?):([1-9A-HJ-NP-Za-km-z]{21,22}))\/anoncreds\/v0/

// <namespaceIdentifier>:2:<schemaName>:<schemaVersion>
export const unqualifiedSchemaIdRegex = /^([a-zA-Z0-9]{21,22}):2:(.+):([0-9.]+)$/
// did:indy:<namespace>:<namespaceIdentifier>/anoncreds/v0/SCHEMA/<schemaName>/<schemaVersion>
export const didIndySchemaIdRegex = new RegExp(`^${didIndyAnonCredsBase.source}/SCHEMA/(.+)/([0-9.]+)$`)

export const unqualifiedSchemaVersionRegex = /^(\d+\.)?(\d+\.)?(\*|\d+)$/
export const unqualifiedIndyDidRegex = /^(did:sov:)?[a-zA-Z0-9]{21,22}$/

// <namespaceIdentifier>:3:CL:<schemaSeqNo>:<tag>
export const unqualifiedCredentialDefinitionIdRegex = /^([a-zA-Z0-9]{21,22}):3:CL:([1-9][0-9]*):(.+)$/
// did:indy:<namespace>:<namespaceIdentifier>/anoncreds/v0/CLAIM_DEF/<schemaSeqNo>/<tag>
export const didIndyCredentialDefinitionIdRegex = new RegExp(
  `^${didIndyAnonCredsBase.source}/CLAIM_DEF/([1-9][0-9]*)/(.+)$`
)

// <namespaceIdentifier>:4:<namespaceIdentifier>:3:CL:<schemaSeqNo>:<credentialDefinitionTag>:CL_ACCUM:<revocationRegistryTag>
export const unqualifiedRevocationRegistryIdRegex =
  /^([a-zA-Z0-9]{21,22}):4:[a-zA-Z0-9]{21,22}:3:CL:([1-9][0-9]*):(.+):CL_ACCUM:(.+)$/
// did:indy:<namespace>:<namespaceIdentifier>/anoncreds/v0/REV_REG_DEF/<schemaSeqNo>/<credentialDefinitionTag>/<revocationRegistryTag>
export const didIndyRevocationRegistryIdRegex = new RegExp(
  `^${didIndyAnonCredsBase.source}/REV_REG_DEF/([1-9][0-9]*)/(.+)/(.+)$`
)

export const didIndyRegex = /^did:indy:((?:[a-z][_a-z0-9-]*)(?::[a-z][_a-z0-9-]*)?):([1-9A-HJ-NP-Za-km-z]{21,22})$/

export function getUnqualifiedSchemaId(unqualifiedDid: string, name: string, version: string) {
  return `${unqualifiedDid}:2:${name}:${version}`
}

export function getUnqualifiedCredentialDefinitionId(
  unqualifiedDid: string,
  schemaSeqNo: string | number,
  tag: string
) {
  return `${unqualifiedDid}:3:CL:${schemaSeqNo}:${tag}`
}

// TZQuLp43UcYTdtc3HewcDz:4:TZQuLp43UcYTdtc3HewcDz:3:CL:98158:BaustellenzertifikateNU1:CL_ACCUM:1-100
export function getUnqualifiedRevocationRegistryDefinitionId(
  unqualifiedDid: string,
  schemaSeqNo: string | number,
  credentialDefinitionTag: string,
  revocationRegistryTag: string
) {
  return `${unqualifiedDid}:4:${unqualifiedDid}:3:CL:${schemaSeqNo}:${credentialDefinitionTag}:CL_ACCUM:${revocationRegistryTag}`
}

export function isUnqualifiedIndyDid(did: string) {
  return unqualifiedIndyDidRegex.test(did)
}

export function isUnqualifiedCredentialDefinitionId(credentialDefinitionId: string) {
  return unqualifiedCredentialDefinitionIdRegex.test(credentialDefinitionId)
}

export function isUnqualifiedRevocationRegistryId(revocationRegistryId: string) {
  return unqualifiedRevocationRegistryIdRegex.test(revocationRegistryId)
}

export function isUnqualifiedSchemaId(schemaId: string) {
  return unqualifiedSchemaIdRegex.test(schemaId)
}

export function isDidIndySchemaId(schemaId: string) {
  return didIndySchemaIdRegex.test(schemaId)
}

export function isDidIndyCredentialDefinitionId(credentialDefinitionId: string) {
  return didIndyCredentialDefinitionIdRegex.test(credentialDefinitionId)
}

export function isDidIndyRevocationRegistryId(revocationRegistryId: string) {
  return didIndyRevocationRegistryIdRegex.test(revocationRegistryId)
}

export function parseIndyDid(did: string) {
  const match = did.match(didIndyRegex)
  if (match) {
    const [, namespace, namespaceIdentifier] = match
    return { namespace, namespaceIdentifier }
  } else {
    throw new CredoError(`${did} is not a valid did:indy did`)
  }
}

interface ParsedIndySchemaId {
  did: string
  namespaceIdentifier: string
  schemaName: string
  schemaVersion: string
  namespace?: string
}

export function parseIndySchemaId(schemaId: string): ParsedIndySchemaId {
  const didIndyMatch = schemaId.match(didIndySchemaIdRegex)
  if (didIndyMatch) {
    const [, did, namespace, namespaceIdentifier, schemaName, schemaVersion] = didIndyMatch

    return {
      did,
      namespaceIdentifier,
      schemaName,
      schemaVersion,
      namespace,
    }
  }

  const legacyMatch = schemaId.match(unqualifiedSchemaIdRegex)
  if (legacyMatch) {
    const [, did, schemaName, schemaVersion] = legacyMatch

    return {
      did,
      namespaceIdentifier: did,
      schemaName,
      schemaVersion,
    }
  }

  throw new Error(`Invalid schema id: ${schemaId}`)
}

interface ParsedIndyCredentialDefinitionId {
  did: string
  namespaceIdentifier: string
  schemaSeqNo: string
  tag: string
  namespace?: string
}

export function parseIndyCredentialDefinitionId(credentialDefinitionId: string): ParsedIndyCredentialDefinitionId {
  const didIndyMatch = credentialDefinitionId.match(didIndyCredentialDefinitionIdRegex)
  if (didIndyMatch) {
    const [, did, namespace, namespaceIdentifier, schemaSeqNo, tag] = didIndyMatch

    return {
      did,
      namespaceIdentifier,
      schemaSeqNo,
      tag,
      namespace,
    }
  }

  const legacyMatch = credentialDefinitionId.match(unqualifiedCredentialDefinitionIdRegex)
  if (legacyMatch) {
    const [, did, schemaSeqNo, tag] = legacyMatch

    return {
      did,
      namespaceIdentifier: did,
      schemaSeqNo,
      tag,
    }
  }

  throw new Error(`Invalid credential definition id: ${credentialDefinitionId}`)
}

interface ParsedIndyRevocationRegistryId {
  did: string
  namespaceIdentifier: string
  schemaSeqNo: string
  credentialDefinitionTag: string
  revocationRegistryTag: string
  namespace?: string
}

export function parseIndyRevocationRegistryId(revocationRegistryId: string): ParsedIndyRevocationRegistryId {
  const didIndyMatch = revocationRegistryId.match(didIndyRevocationRegistryIdRegex)
  if (didIndyMatch) {
    const [, did, namespace, namespaceIdentifier, schemaSeqNo, credentialDefinitionTag, revocationRegistryTag] =
      didIndyMatch

    return {
      did,
      namespaceIdentifier,
      schemaSeqNo,
      credentialDefinitionTag,
      revocationRegistryTag,
      namespace,
    }
  }

  const legacyMatch = revocationRegistryId.match(unqualifiedRevocationRegistryIdRegex)
  if (legacyMatch) {
    const [, did, schemaSeqNo, credentialDefinitionTag, revocationRegistryTag] = legacyMatch

    return {
      did,
      namespaceIdentifier: did,
      schemaSeqNo,
      credentialDefinitionTag,
      revocationRegistryTag,
    }
  }

  throw new Error(`Invalid revocation registry id: ${revocationRegistryId}`)
}

export function getIndyNamespaceFromIndyDid(identifier: string): string {
  let namespace: string | undefined
  if (isDidIndySchemaId(identifier)) {
    namespace = parseIndySchemaId(identifier).namespace
  } else if (isDidIndyCredentialDefinitionId(identifier)) {
    namespace = parseIndyCredentialDefinitionId(identifier).namespace
  } else if (isDidIndyRevocationRegistryId(identifier)) {
    namespace = parseIndyRevocationRegistryId(identifier).namespace
  } else {
    namespace = parseIndyDid(identifier).namespace
  }
  if (!namespace) throw new CredoError(`Cannot get indy namespace of identifier '${identifier}'`)
  return namespace
}

export function getUnQualifiedDidIndyDid(identifier: string): string {
  if (isUnqualifiedIndyDid(identifier)) return identifier

  if (isDidIndySchemaId(identifier)) {
    const { schemaName, schemaVersion, namespaceIdentifier } = parseIndySchemaId(identifier)
    return getUnqualifiedSchemaId(namespaceIdentifier, schemaName, schemaVersion)
  } else if (isDidIndyCredentialDefinitionId(identifier)) {
    const { schemaSeqNo, tag, namespaceIdentifier } = parseIndyCredentialDefinitionId(identifier)
    return getUnqualifiedCredentialDefinitionId(namespaceIdentifier, schemaSeqNo, tag)
  } else if (isDidIndyRevocationRegistryId(identifier)) {
    const { namespaceIdentifier, schemaSeqNo, credentialDefinitionTag, revocationRegistryTag } =
      parseIndyRevocationRegistryId(identifier)
    return getUnqualifiedRevocationRegistryDefinitionId(
      namespaceIdentifier,
      schemaSeqNo,
      credentialDefinitionTag,
      revocationRegistryTag
    )
  }

  const { namespaceIdentifier } = parseIndyDid(identifier)
  return namespaceIdentifier
}

export function isIndyDid(identifier: string): boolean {
  return identifier.startsWith('did:indy:')
}

export function getQualifiedDidIndyDid(identifier: string, namespace: string): string {
  if (isIndyDid(identifier)) return identifier

  if (!namespace || typeof namespace !== 'string') {
    throw new CredoError('Missing required indy namespace')
  }

  if (isUnqualifiedSchemaId(identifier)) {
    const { namespaceIdentifier, schemaName, schemaVersion } = parseIndySchemaId(identifier)
    const schemaId = `did:indy:${namespace}:${namespaceIdentifier}/anoncreds/v0/SCHEMA/${schemaName}/${schemaVersion}`
    return schemaId
  } else if (isUnqualifiedCredentialDefinitionId(identifier)) {
    const { namespaceIdentifier, schemaSeqNo, tag } = parseIndyCredentialDefinitionId(identifier)
    const credentialDefinitionId = `did:indy:${namespace}:${namespaceIdentifier}/anoncreds/v0/CLAIM_DEF/${schemaSeqNo}/${tag}`
    return credentialDefinitionId
  } else if (isUnqualifiedRevocationRegistryId(identifier)) {
    const { namespaceIdentifier, schemaSeqNo, credentialDefinitionTag, revocationRegistryTag } =
      parseIndyRevocationRegistryId(identifier)
    const revocationRegistryId = `did:indy:${namespace}:${namespaceIdentifier}/anoncreds/v0/REV_REG_DEF/${schemaSeqNo}/${credentialDefinitionTag}/${revocationRegistryTag}`
    return revocationRegistryId
  } else if (isUnqualifiedIndyDid(identifier)) {
    return `did:indy:${namespace}:${identifier}`
  } else {
    throw new CredoError(`Cannot created qualified indy identifier for '${identifier}' with namespace '${namespace}'`)
  }
}

// -- schema -- //

export function isUnqualifiedDidIndySchema(schema: AnonCredsSchema) {
  return isUnqualifiedIndyDid(schema.issuerId)
}

export function getUnqualifiedDidIndySchema(schema: AnonCredsSchema): AnonCredsSchema {
  if (isUnqualifiedDidIndySchema(schema)) return { ...schema }
  if (!isIndyDid(schema.issuerId)) {
    throw new CredoError(`IssuerId '${schema.issuerId}' is not a valid qualified did-indy did.`)
  }

  const issuerId = getUnQualifiedDidIndyDid(schema.issuerId)
  return { ...schema, issuerId }
}

export function isQualifiedDidIndySchema(schema: AnonCredsSchema) {
  return !isUnqualifiedIndyDid(schema.issuerId)
}

export function getQualifiedDidIndySchema(schema: AnonCredsSchema, namespace: string): AnonCredsSchema {
  if (isQualifiedDidIndySchema(schema)) return { ...schema }

  return {
    ...schema,
    issuerId: getQualifiedDidIndyDid(schema.issuerId, namespace),
  }
}

// -- credential definition -- //

export function isUnqualifiedDidIndyCredentialDefinition(anonCredsCredentialDefinition: AnonCredsCredentialDefinition) {
  return (
    isUnqualifiedIndyDid(anonCredsCredentialDefinition.issuerId) &&
    isUnqualifiedSchemaId(anonCredsCredentialDefinition.schemaId)
  )
}

export function getUnqualifiedDidIndyCredentialDefinition(
  anonCredsCredentialDefinition: AnonCredsCredentialDefinition
): AnonCredsCredentialDefinition {
  if (isUnqualifiedDidIndyCredentialDefinition(anonCredsCredentialDefinition)) {
    return { ...anonCredsCredentialDefinition }
  }

  const issuerId = getUnQualifiedDidIndyDid(anonCredsCredentialDefinition.issuerId)
  const schemaId = getUnQualifiedDidIndyDid(anonCredsCredentialDefinition.schemaId)

  return { ...anonCredsCredentialDefinition, issuerId, schemaId }
}

export function isQualifiedDidIndyCredentialDefinition(anonCredsCredentialDefinition: AnonCredsCredentialDefinition) {
  return (
    !isUnqualifiedIndyDid(anonCredsCredentialDefinition.issuerId) &&
    !isUnqualifiedSchemaId(anonCredsCredentialDefinition.schemaId)
  )
}

export function getQualifiedDidIndyCredentialDefinition(
  anonCredsCredentialDefinition: AnonCredsCredentialDefinition,
  namespace: string
): AnonCredsCredentialDefinition {
  if (isQualifiedDidIndyCredentialDefinition(anonCredsCredentialDefinition)) return { ...anonCredsCredentialDefinition }

  return {
    ...anonCredsCredentialDefinition,
    issuerId: getQualifiedDidIndyDid(anonCredsCredentialDefinition.issuerId, namespace),
    schemaId: getQualifiedDidIndyDid(anonCredsCredentialDefinition.schemaId, namespace),
  }
}

// -- revocation registry definition -- //

export function isUnqualifiedDidIndyRevocationRegistryDefinition(
  revocationRegistryDefinition: AnonCredsRevocationRegistryDefinition
) {
  return (
    isUnqualifiedIndyDid(revocationRegistryDefinition.issuerId) &&
    isUnqualifiedCredentialDefinitionId(revocationRegistryDefinition.credDefId)
  )
}

export function getUnqualifiedDidIndyRevocationRegistryDefinition(
  revocationRegistryDefinition: AnonCredsRevocationRegistryDefinition
): AnonCredsRevocationRegistryDefinition {
  if (isUnqualifiedDidIndyRevocationRegistryDefinition(revocationRegistryDefinition)) {
    return { ...revocationRegistryDefinition }
  }

  const issuerId = getUnQualifiedDidIndyDid(revocationRegistryDefinition.issuerId)
  const credDefId = getUnQualifiedDidIndyDid(revocationRegistryDefinition.credDefId)

  return { ...revocationRegistryDefinition, issuerId, credDefId }
}

export function isQualifiedRevocationRegistryDefinition(
  revocationRegistryDefinition: AnonCredsRevocationRegistryDefinition
) {
  return (
    !isUnqualifiedIndyDid(revocationRegistryDefinition.issuerId) &&
    !isUnqualifiedCredentialDefinitionId(revocationRegistryDefinition.credDefId)
  )
}

export function getQualifiedDidIndyRevocationRegistryDefinition(
  revocationRegistryDefinition: AnonCredsRevocationRegistryDefinition,
  namespace: string
): AnonCredsRevocationRegistryDefinition {
  if (isQualifiedRevocationRegistryDefinition(revocationRegistryDefinition)) return { ...revocationRegistryDefinition }

  return {
    ...revocationRegistryDefinition,
    issuerId: getQualifiedDidIndyDid(revocationRegistryDefinition.issuerId, namespace),
    credDefId: getQualifiedDidIndyDid(revocationRegistryDefinition.credDefId, namespace),
  }
}
