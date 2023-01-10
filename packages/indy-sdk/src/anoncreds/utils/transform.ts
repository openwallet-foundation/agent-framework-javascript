import type {
  AnonCredsCredentialDefinition,
  AnonCredsRevocationList,
  AnonCredsRevocationRegistryDefinition,
  AnonCredsSchema,
} from '@aries-framework/anoncreds'
import type { CredDef, RevocReg, RevocRegDef, RevocRegDelta, Schema } from 'indy-sdk'

import { didFromCredentialDefinitionId, didFromRevocationRegistryDefinitionId, didFromSchemaId } from './identifiers'

export function anonCredsSchemaFromIndySdk(schema: Schema): AnonCredsSchema {
  const issuerId = didFromSchemaId(schema.id)
  return {
    issuerId,
    name: schema.name,
    version: schema.version,
    attrNames: schema.attrNames,
  }
}

export function indySdkSchemaFromAnonCreds(schemaId: string, schema: AnonCredsSchema, indyLedgerSeqNo: number): Schema {
  return {
    id: schemaId,
    attrNames: schema.attrNames,
    name: schema.name,
    version: schema.version,
    ver: '1.0',
    seqNo: indyLedgerSeqNo,
  }
}

export function anonCredsCredentialDefinitionFromIndySdk(credentialDefinition: CredDef): AnonCredsCredentialDefinition {
  const issuerId = didFromCredentialDefinitionId(credentialDefinition.id)

  return {
    issuerId,
    schemaId: credentialDefinition.schemaId,
    tag: credentialDefinition.tag,
    type: 'CL',
    value: credentialDefinition.value,
  }
}

export function indySdkCredentialDefinitionFromAnonCreds(
  credentialDefinitionId: string,
  credentialDefinition: AnonCredsCredentialDefinition
): CredDef {
  return {
    id: credentialDefinitionId,
    schemaId: credentialDefinition.schemaId,
    tag: credentialDefinition.tag,
    type: credentialDefinition.type,
    value: credentialDefinition.value,
    ver: '1.0',
  }
}

export function anonCredsRevocationRegistryDefinitionFromIndySdk(
  revocationRegistryDefinition: RevocRegDef
): AnonCredsRevocationRegistryDefinition {
  const issuerId = didFromRevocationRegistryDefinitionId(revocationRegistryDefinition.id)

  return {
    issuerId,
    credDefId: revocationRegistryDefinition.credDefId,
    maxCredNum: revocationRegistryDefinition.value.maxCredNum,
    publicKeys: revocationRegistryDefinition.value
      .publicKeys as unknown as AnonCredsRevocationRegistryDefinition['publicKeys'], // FIXME: type is incorrect in @types/indy-sdk
    tag: revocationRegistryDefinition.tag,
    tailsHash: revocationRegistryDefinition.value.tailsHash,
    tailsLocation: revocationRegistryDefinition.value.tailsLocation,
    type: 'CL_ACCUM',
  }
}

export function indySdkRevocationRegistryDefinitionFromAnonCreds(
  revocationRegistryDefinitionId: string,
  revocationRegistryDefinition: AnonCredsRevocationRegistryDefinition
): RevocRegDef {
  return {
    id: revocationRegistryDefinitionId,
    credDefId: revocationRegistryDefinition.credDefId,
    revocDefType: revocationRegistryDefinition.type,
    tag: revocationRegistryDefinition.tag,
    value: {
      issuanceType: 'ISSUANCE_BY_DEFAULT', // NOTE: we always use ISSUANCE_BY_DEFAULT when passing to the indy-sdk. It doesn't matter, as we have the revocation List with the full state
      maxCredNum: revocationRegistryDefinition.maxCredNum,
      publicKeys: revocationRegistryDefinition.publicKeys as unknown as string[], // FIXME: @types/indy-sdk contains incorrect types
      tailsHash: revocationRegistryDefinition.tailsHash,
      tailsLocation: revocationRegistryDefinition.tailsLocation,
    },
    ver: '1.0',
  }
}

export function anonCredsRevocationListFromIndySdk(
  revocationRegistryDefinitionId: string,
  revocationRegistryDefinition: AnonCredsRevocationRegistryDefinition,
  delta: RevocRegDelta,
  timestamp: number,
  isIssuanceByDefault: boolean
): AnonCredsRevocationList {
  // 0 means unrevoked, 1 means revoked
  const defaultState = isIssuanceByDefault ? 0 : 1

  // Fill with default value
  const revocationList = new Array(revocationRegistryDefinition.maxCredNum).fill(defaultState)

  // Set all `issuer` indexes to 0 (not revoked)
  for (const issued of delta.value.issued ?? []) {
    revocationList[issued] = 0
  }

  // Set all `revoked` indexes to 1 (revoked)
  for (const revoked of delta.value.revoked ?? []) {
    revocationList[revoked] = 1
  }

  return {
    issuerId: revocationRegistryDefinition.issuerId,
    currentAccumulator: delta.value.accum,
    revRegId: revocationRegistryDefinitionId,
    revocationList,
    timestamp,
  }
}

export function indySdkRevocationRegistryFromAnonCreds(revocationList: AnonCredsRevocationList): RevocReg {
  return {
    ver: '1.0',
    value: {
      accum: revocationList.currentAccumulator,
    },
  }
}

export function indySdkRevocationDeltaFromAnonCreds(revocationList: AnonCredsRevocationList): RevocRegDelta {
  // Get all indices from the revocationList that are revoked (so have value '1')
  const revokedIndices = revocationList.revocationList.reduce<number[]>(
    (revoked, current, index) => (current === 1 ? [...revoked, index] : revoked),
    []
  )

  return {
    value: {
      accum: revocationList.currentAccumulator,
      issued: [],
      revoked: revokedIndices,
      // NOTE: I don't think this is used?
      prevAccum: '',
    },
    ver: '1.0',
  }
}
