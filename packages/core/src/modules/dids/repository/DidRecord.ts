import type { DidRecordMetadata } from './didRecordMetadataTypes'
import type { TagsBase } from '../../../storage/BaseRecord'

import { Type } from 'class-transformer'
import { IsEnum, ValidateNested } from 'class-validator'

import { BaseRecord } from '../../../storage/BaseRecord'
import { uuid } from '../../../utils/uuid'
import { DidDocument } from '../domain'
import { DidDocumentRole } from '../domain/DidDocumentRole'
import { parseDid } from '../domain/parse'

import { DidRecordMetadataKeys } from './didRecordMetadataTypes'

export interface DidRecordProps {
  id?: string
  did: string
  role: DidDocumentRole
  didDocument?: DidDocument
  createdAt?: Date
  tags?: CustomDidTags
}

export interface CustomDidTags extends TagsBase {
  recipientKeyFingerprints?: string[]

  // Alternative forms of the did, allowed to be queried by them.
  // Relationship must be verified both ways before setting this tag.
  alternativeDids?: string[]
}

type DefaultDidTags = {
  // We set the recipientKeyFingeprints as a default tag, if the did record has a did document
  // If the did record does not have a did document, we can't calculate it, and it needs to be
  // handled by the creator of the did record
  recipientKeyFingerprints?: string[]

  role: DidDocumentRole
  method: string
  legacyUnqualifiedDid?: string
  methodSpecificIdentifier: string
  did: string
}

export class DidRecord extends BaseRecord<DefaultDidTags, CustomDidTags, DidRecordMetadata> implements DidRecordProps {
  @Type(() => DidDocument)
  @ValidateNested()
  public didDocument?: DidDocument

  public did!: string

  @IsEnum(DidDocumentRole)
  public role!: DidDocumentRole

  public static readonly type = 'DidRecord'
  public readonly type = DidRecord.type

  public constructor(props: DidRecordProps) {
    super()

    if (props) {
      this.id = props.id ?? uuid()
      this.did = props.did
      this.role = props.role
      this.didDocument = props.didDocument
      this.createdAt = props.createdAt ?? new Date()
      this._tags = props.tags ?? {}
    }
  }

  public getTags() {
    const did = parseDid(this.did)

    const legacyDid = this.metadata.get(DidRecordMetadataKeys.LegacyDid)

    return {
      ...this._tags,
      role: this.role,
      method: did.method,
      legacyUnqualifiedDid: legacyDid?.unqualifiedDid,
      did: this.did,
      methodSpecificIdentifier: did.id,

      // Calculate if we have a did document, otherwise use the already present recipient keys
      recipientKeyFingerprints: this.didDocument
        ? this.didDocument.recipientKeys.map((recipientKey) => recipientKey.fingerprint)
        : this._tags.recipientKeyFingerprints,
    }
  }
}
