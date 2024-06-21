import type { TagsBase } from '@credo-ts/core'

import { BaseRecord, utils } from '@credo-ts/core'

export interface AnonCredsKeyCorrectnessProofRecordProps {
  id?: string
  credentialDefinitionId: string
  value: Record<string, unknown>
  createdAt?: Date
}

export type DefaultAnonCredsKeyCorrectnessProofPrivateTags = {
  credentialDefinitionId: string
}

export class AnonCredsKeyCorrectnessProofRecord extends BaseRecord<
  DefaultAnonCredsKeyCorrectnessProofPrivateTags,
  TagsBase
> {
  public static readonly type = 'AnonCredsKeyCorrectnessProofRecord'
  public readonly type = AnonCredsKeyCorrectnessProofRecord.type

  public readonly credentialDefinitionId!: string
  public readonly value!: Record<string, unknown> // TODO: Define structure

  public constructor(props: AnonCredsKeyCorrectnessProofRecordProps) {
    super()

    if (props) {
      this.id = props.id ?? utils.uuid()
      this.credentialDefinitionId = props.credentialDefinitionId
      this.value = props.value
      this.createdAt = props.createdAt ?? new Date()
    }
  }

  public getTags() {
    return {
      ...this._tags,
      credentialDefinitionId: this.credentialDefinitionId,
    }
  }
}
