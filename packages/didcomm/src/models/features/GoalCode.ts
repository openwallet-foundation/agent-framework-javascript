import type { FeatureOptions } from './Feature'

import { Feature } from './Feature'

export type GoalCodeOptions = Omit<FeatureOptions, 'type'>

export class GoalCode extends Feature {
  public constructor(props: GoalCodeOptions) {
    super({ ...props, type: GoalCode.type })
  }

  public static readonly type = 'goal-code'
}
