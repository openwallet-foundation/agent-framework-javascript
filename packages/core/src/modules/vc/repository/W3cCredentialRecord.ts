import type { TagsBase } from '../../../storage/BaseRecord'

import { BaseRecord } from '../../../storage/BaseRecord'
import { uuid } from '../../../utils/uuid'
import { W3cVerifiableCredential, W3cVerifiableCredentialTransformer } from '../models'

export interface W3cCredentialRecordOptions {
  id?: string
  createdAt?: Date
  credential: W3cVerifiableCredential
  tags: CustomW3cCredentialTags
}

export type CustomW3cCredentialTags = TagsBase & {
  /**
   * Expanded types are used for JSON-LD credentials to allow for filtering on the expanded type.
   */
  expandedTypes?: Array<string>
}

export type DefaultW3cCredentialTags = {
  issuerId: string
  subjectIds: Array<string>
  schemaIds: Array<string>
  contexts: Array<string>
  givenId?: string

  // Can be any of the values for claimFormat
  claimFormat: W3cVerifiableCredential['claimFormat']

  proofTypes?: Array<string>
  algs?: Array<string>
}

export class W3cCredentialRecord extends BaseRecord<DefaultW3cCredentialTags, CustomW3cCredentialTags> {
  public static readonly type = 'W3cCredentialRecord'
  public readonly type = W3cCredentialRecord.type

  @W3cVerifiableCredentialTransformer()
  public credential!: W3cVerifiableCredential

  public constructor(props: W3cCredentialRecordOptions) {
    super()
    if (props) {
      this.id = props.id ?? uuid()
      this.createdAt = props.createdAt ?? new Date()
      this._tags = props.tags
      this.credential = props.credential
    }
  }

  public getTags() {
    // Contexts are usually strings, but can sometimes be objects. We're unable to use objects as tags,
    // so we filter out the objects before setting the tags.
    const stringContexts = this.credential.contexts.filter((ctx): ctx is string => typeof ctx === 'string')

    const tags: DefaultW3cCredentialTags = {
      ...this._tags,
      issuerId: this.credential.issuerId,
      subjectIds: this.credential.credentialSubjectIds,
      schemaIds: this.credential.credentialSchemaIds,
      contexts: stringContexts,
      givenId: this.credential.id,
      claimFormat: this.credential.claimFormat,
    }

    // Proof types is used for ldp_vc credentials
    if (this.credential.claimFormat === 'ldp_vc') {
      tags.proofTypes = this.credential.proofTypes
    }

    // Algs is used for jwt_vc credentials
    else if (this.credential.claimFormat === 'jwt_vc') {
      tags.algs = [this.credential.jwt.header.alg]
    }

    return tags
  }
}
