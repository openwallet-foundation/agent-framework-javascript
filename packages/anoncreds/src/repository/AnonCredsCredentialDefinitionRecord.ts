import type { AnonCredsCredentialDefinitionRecordMetadata } from './anonCredsCredentialDefinitionRecordMetadataTypes'
import type { AnonCredsCredentialDefinition } from '../models'
import type { TagsBase } from '@credo-ts/core'

import { BaseRecord, utils } from '@credo-ts/core'

import {
  getUnqualifiedCredentialDefinitionId,
  isDidIndyCredentialDefinitionId,
  parseIndyCredentialDefinitionId,
} from '../utils/indyIdentifiers'

export interface AnonCredsCredentialDefinitionRecordProps {
  id?: string
  credentialDefinitionId: string
  credentialDefinition: AnonCredsCredentialDefinition
  methodName: string
  createdAt?: Date
}

export type DefaultAnonCredsCredentialDefinitionTags = {
  schemaId: string
  credentialDefinitionId: string
  issuerId: string
  tag: string
  methodName: string

  // Stores the unqualified variant of the credential definition id, which allows issuing credentials using the legacy
  // credential definition id, even though the credential definition id is stored in the wallet as a qualified id.
  // This is only added when the credential definition id is an did:indy identifier.
  unqualifiedCredentialDefinitionId?: string
}

export class AnonCredsCredentialDefinitionRecord extends BaseRecord<
  DefaultAnonCredsCredentialDefinitionTags,
  TagsBase,
  AnonCredsCredentialDefinitionRecordMetadata
> {
  public static readonly type = 'AnonCredsCredentialDefinitionRecord'
  public readonly type = AnonCredsCredentialDefinitionRecord.type

  public credentialDefinitionId!: string
  public credentialDefinition!: AnonCredsCredentialDefinition

  /**
   * AnonCreds method name. We don't use names explicitly from the registry (there's no identifier for a registry)
   * @see https://hyperledger.github.io/anoncreds-methods-registry/
   */
  public methodName!: string

  public constructor(props: AnonCredsCredentialDefinitionRecordProps) {
    super()

    if (props) {
      this.id = props.id ?? utils.uuid()
      this.createdAt = props.createdAt ?? new Date()
      this.credentialDefinitionId = props.credentialDefinitionId
      this.credentialDefinition = props.credentialDefinition
      this.methodName = props.methodName
    }
  }

  public getTags() {
    let unqualifiedCredentialDefinitionId: string | undefined = undefined
    if (isDidIndyCredentialDefinitionId(this.credentialDefinitionId)) {
      const { namespaceIdentifier, schemaSeqNo, tag } = parseIndyCredentialDefinitionId(this.credentialDefinitionId)

      unqualifiedCredentialDefinitionId = getUnqualifiedCredentialDefinitionId(namespaceIdentifier, schemaSeqNo, tag)
    }

    return {
      ...this._tags,
      credentialDefinitionId: this.credentialDefinitionId,
      schemaId: this.credentialDefinition.schemaId,
      issuerId: this.credentialDefinition.issuerId,
      tag: this.credentialDefinition.tag,
      methodName: this.methodName,
      unqualifiedCredentialDefinitionId,
    }
  }
}
