import type { AnonCredsRevocationRegistryDefinitionRecordMetadata } from './anonCredsRevocationRegistryDefinitionRecordMetadataTypes'
import type { AnonCredsRevocationRegistryDefinition } from '../models'
import type { TagsBase } from '@credo-ts/core'

import { BaseRecord, utils } from '@credo-ts/core'

export interface AnonCredsRevocationRegistryDefinitionRecordProps {
  id?: string
  revocationRegistryDefinitionId: string
  revocationRegistryDefinition: AnonCredsRevocationRegistryDefinition
  createdAt?: Date
}

export type DefaultAnonCredsRevocationRegistryDefinitionTags = {
  revocationRegistryDefinitionId: string
  credentialDefinitionId: string
}

export class AnonCredsRevocationRegistryDefinitionRecord extends BaseRecord<
  DefaultAnonCredsRevocationRegistryDefinitionTags,
  TagsBase,
  AnonCredsRevocationRegistryDefinitionRecordMetadata
> {
  public static readonly type = 'AnonCredsRevocationRegistryDefinitionRecord'
  public readonly type = AnonCredsRevocationRegistryDefinitionRecord.type

  public readonly revocationRegistryDefinitionId!: string
  public readonly revocationRegistryDefinition!: AnonCredsRevocationRegistryDefinition

  public constructor(props: AnonCredsRevocationRegistryDefinitionRecordProps) {
    super()

    if (props) {
      this.id = props.id ?? utils.uuid()
      this.revocationRegistryDefinitionId = props.revocationRegistryDefinitionId
      this.revocationRegistryDefinition = props.revocationRegistryDefinition
      this.createdAt = props.createdAt ?? new Date()
    }
  }

  public getTags() {
    return {
      ...this._tags,
      revocationRegistryDefinitionId: this.revocationRegistryDefinitionId,
      credentialDefinitionId: this.revocationRegistryDefinition.credDefId,
    }
  }
}
