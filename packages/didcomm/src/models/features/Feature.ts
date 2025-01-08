import { CredoError, JsonTransformer } from '@credo-ts/core'
import { Expose } from 'class-transformer'
import { IsString } from 'class-validator'

export interface FeatureOptions {
  id: string
  type: string
}

export class Feature {
  public id!: string

  public constructor(props: FeatureOptions) {
    if (props) {
      this.id = props.id
      this.type = props.type
    }
  }

  @IsString()
  @Expose({ name: 'feature-type' })
  public readonly type!: string

  /**
   * Combine this feature with another one, provided both are from the same type
   * and have the same id
   *
   * @param feature object to combine with this one
   * @returns a new object resulting from the combination between this and feature
   */
  public combine(feature: this) {
    if (feature.id !== this.id) {
      throw new CredoError('Can only combine with a feature with the same id')
    }

    const obj1 = JsonTransformer.toJSON(this)
    const obj2 = JsonTransformer.toJSON(feature)

    for (const key in obj2) {
      try {
        if (Array.isArray(obj2[key])) {
          obj1[key] = [...new Set([...obj1[key], ...obj2[key]])]
        } else {
          obj1[key] = obj2[key]
        }
      } catch (e) {
        obj1[key] = obj2[key]
      }
    }
    return JsonTransformer.fromJSON(obj1, Feature)
  }

  public toJSON(): Record<string, unknown> {
    return JsonTransformer.toJSON(this)
  }
}
