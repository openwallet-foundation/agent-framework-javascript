import { Expose } from 'class-transformer'
import { IsString } from 'class-validator'

export interface FeatureQueryOptions {
  featureType: string
  match: string
}

export class FeatureQuery {
  public constructor(options: FeatureQueryOptions) {
    if (options) {
      this.featureType = options.featureType
      this.match = options.match
    }
  }

  @Expose({ name: 'feature-type' })
  @IsString()
  public featureType!: string

  @IsString()
  public match!: string
}
