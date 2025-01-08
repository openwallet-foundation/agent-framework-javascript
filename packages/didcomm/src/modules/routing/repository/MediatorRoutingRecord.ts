import type { TagsBase } from '@credo-ts/core'

import { BaseRecord, utils } from '@credo-ts/core'

export interface MediatorRoutingRecordProps {
  id?: string
  createdAt?: Date
  routingKeys?: string[]
  tags?: TagsBase
}

export class MediatorRoutingRecord extends BaseRecord implements MediatorRoutingRecordProps {
  public routingKeys!: string[]

  public static readonly type = 'MediatorRoutingRecord'
  public readonly type = MediatorRoutingRecord.type

  public constructor(props: MediatorRoutingRecordProps) {
    super()

    if (props) {
      this.id = props.id ?? utils.uuid()
      this.createdAt = props.createdAt ?? new Date()
      this.routingKeys = props.routingKeys || []
    }
  }

  public getTags() {
    return this._tags
  }
}
