import type { TagsBase } from '../../../storage/BaseRecord'
import type { Constructable } from '../../../utils/mixins'

import { type JwaSignatureAlgorithm } from '../../../crypto'
import { BaseRecord } from '../../../storage/BaseRecord'
import { JsonTransformer } from '../../../utils'
import { uuid } from '../../../utils/uuid'
import { Mdoc } from '../Mdoc'

export type DefaultMdocRecordTags = {
  docType: string

  /**
   *
   * The Jwa Signature Algorithm used to sign the Mdoc.
   */
  alg: JwaSignatureAlgorithm
}

export type MdocRecordStorageProps = {
  id?: string
  createdAt?: Date
  tags?: TagsBase
  mdoc: Mdoc
}

export class MdocRecord extends BaseRecord<DefaultMdocRecordTags> {
  public static readonly type = 'MdocRecord'
  public readonly type = MdocRecord.type
  public base64Url!: string

  public constructor(props: MdocRecordStorageProps) {
    super()

    if (props) {
      this.id = props.id ?? uuid()
      this.createdAt = props.createdAt ?? new Date()
      this.base64Url = props.mdoc.base64Url
      this._tags = props.tags ?? {}
    }
  }

  /**
   * credential is convenience method added to all credential records
   */
  public get credential(): Mdoc {
    return Mdoc.fromBase64Url(this.base64Url)
  }

  /**
   * encoded is convenience method added to all credential records
   */
  public get encoded(): string {
    return this.base64Url
  }

  public getTags() {
    const mdoc = Mdoc.fromBase64Url(this.base64Url)
    const docType = mdoc.docType
    const alg = mdoc.alg

    return {
      ...this._tags,
      docType,
      alg,
    }
  }

  public clone(): this {
    return JsonTransformer.fromJSON(JsonTransformer.toJSON(this), this.constructor as Constructable<this>)
  }
}
