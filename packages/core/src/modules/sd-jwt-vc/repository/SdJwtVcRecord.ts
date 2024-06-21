import type { JwaSignatureAlgorithm } from '../../../crypto'
import type { TagsBase } from '../../../storage/BaseRecord'
import type { Constructable } from '../../../utils/mixins'

import { decodeSdJwtSync } from '@sd-jwt/decode'

import { BaseRecord } from '../../../storage/BaseRecord'
import { Hasher, JsonTransformer } from '../../../utils'
import { uuid } from '../../../utils/uuid'

export type DefaultSdJwtVcRecordTags = {
  vct: string

  /**
   * The sdAlg is the alg used for creating digests for selective disclosures
   */
  sdAlg: string

  /**
   * The alg is the alg used to sign the SD-JWT
   */
  alg: JwaSignatureAlgorithm
}

export type SdJwtVcRecordStorageProps = {
  id?: string
  createdAt?: Date
  tags?: TagsBase
  compactSdJwtVc: string
}

export class SdJwtVcRecord extends BaseRecord<DefaultSdJwtVcRecordTags> {
  public static readonly type = 'SdJwtVcRecord'
  public readonly type = SdJwtVcRecord.type

  // We store the sdJwtVc in compact format.
  public compactSdJwtVc!: string

  // TODO: should we also store the pretty claims so it's not needed to
  // re-calculate the hashes each time? I think for now it's fine to re-calculate
  public constructor(props: SdJwtVcRecordStorageProps) {
    super()

    if (props) {
      this.id = props.id ?? uuid()
      this.createdAt = props.createdAt ?? new Date()
      this.compactSdJwtVc = props.compactSdJwtVc
      this._tags = props.tags ?? {}
    }
  }

  public getTags() {
    const sdjwt = decodeSdJwtSync(this.compactSdJwtVc, Hasher.hash)
    const vct = sdjwt.jwt.payload['vct'] as string
    const sdAlg = sdjwt.jwt.payload['_sd_alg'] as string | undefined
    const alg = sdjwt.jwt.header['alg'] as JwaSignatureAlgorithm

    return {
      ...this._tags,
      vct,
      sdAlg: sdAlg ?? 'sha-256',
      alg,
    }
  }

  public clone(): this {
    return JsonTransformer.fromJSON(JsonTransformer.toJSON(this), this.constructor as Constructable<this>)
  }
}
