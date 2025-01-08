import type { FeatureOptions } from './Feature'

import { IsOptional, IsString } from 'class-validator'

import { Feature } from './Feature'

export interface ProtocolOptions extends Omit<FeatureOptions, 'type'> {
  roles?: string[]
}

export class Protocol extends Feature {
  public constructor(props: ProtocolOptions) {
    super({ ...props, type: Protocol.type })

    if (props) {
      this.roles = props.roles
    }
  }

  public static readonly type = 'protocol'

  @IsString({ each: true })
  @IsOptional()
  public roles?: string[]
}
