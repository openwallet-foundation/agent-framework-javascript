import type { FeatureOptions } from './Feature'

import { Feature } from './Feature'

export type GovernanceFrameworkOptions = Omit<FeatureOptions, 'type'>

export class GovernanceFramework extends Feature {
  public constructor(props: GovernanceFrameworkOptions) {
    super({ ...props, type: GovernanceFramework.type })
  }

  public static readonly type = 'gov-fw'
}
