import { JsonTransformer } from '@credo-ts/core'
import { IsValidMessageType, replaceLegacyDidSovPrefix, parseMessageType } from '@credo-ts/didcomm'
import { Expose, Transform, Type } from 'class-transformer'
import {
  IsIn,
  IsInstance,
  IsInt,
  IsMimeType,
  IsOptional,
  IsString,
  Matches,
  ValidateIf,
  ValidateNested,
} from 'class-validator'

import { anonCredsPredicateType, AnonCredsPredicateType } from '../../../../models'
import { unqualifiedCredentialDefinitionIdRegex } from '../../../../utils'

export interface V1PresentationPreviewAttributeOptions {
  name: string
  credentialDefinitionId?: string
  mimeType?: string
  value?: string
  referent?: string
}

export class V1PresentationPreviewAttribute {
  public constructor(options: V1PresentationPreviewAttributeOptions) {
    if (options) {
      this.name = options.name
      this.credentialDefinitionId = options.credentialDefinitionId
      this.mimeType = options.mimeType
      this.value = options.value
      this.referent = options.referent
    }
  }

  public name!: string

  @Expose({ name: 'cred_def_id' })
  @IsString()
  @ValidateIf((o: V1PresentationPreviewAttribute) => o.referent !== undefined)
  @Matches(unqualifiedCredentialDefinitionIdRegex)
  public credentialDefinitionId?: string

  @Expose({ name: 'mime-type' })
  @IsOptional()
  @IsMimeType()
  public mimeType?: string

  @IsString()
  @IsOptional()
  public value?: string

  @IsString()
  @IsOptional()
  public referent?: string

  public toJSON(): Record<string, unknown> {
    return JsonTransformer.toJSON(this)
  }
}

export interface V1PresentationPreviewPredicateOptions {
  name: string
  credentialDefinitionId: string
  predicate: AnonCredsPredicateType
  threshold: number
}

export class V1PresentationPreviewPredicate {
  public constructor(options: V1PresentationPreviewPredicateOptions) {
    if (options) {
      this.name = options.name
      this.credentialDefinitionId = options.credentialDefinitionId
      this.predicate = options.predicate
      this.threshold = options.threshold
    }
  }

  @IsString()
  public name!: string

  @Expose({ name: 'cred_def_id' })
  @IsString()
  @Matches(unqualifiedCredentialDefinitionIdRegex)
  public credentialDefinitionId!: string

  @IsIn(anonCredsPredicateType)
  public predicate!: AnonCredsPredicateType

  @IsInt()
  public threshold!: number

  public toJSON(): Record<string, unknown> {
    return JsonTransformer.toJSON(this)
  }
}

export interface V1PresentationPreviewOptions {
  attributes?: V1PresentationPreviewAttributeOptions[]
  predicates?: V1PresentationPreviewPredicateOptions[]
}

/**
 * Presentation preview inner message class.
 *
 * This is not a message but an inner object for other messages in this protocol. It is used to construct a preview of the data for the presentation.
 *
 * @see https://github.com/hyperledger/aries-rfcs/blob/master/features/0037-present-proof/README.md#presentation-preview
 */
export class V1PresentationPreview {
  public constructor(options: V1PresentationPreviewOptions) {
    if (options) {
      this.attributes = options.attributes?.map((a) => new V1PresentationPreviewAttribute(a)) ?? []
      this.predicates = options.predicates?.map((p) => new V1PresentationPreviewPredicate(p)) ?? []
    }
  }

  @Expose({ name: '@type' })
  @IsValidMessageType(V1PresentationPreview.type)
  @Transform(({ value }) => replaceLegacyDidSovPrefix(value), {
    toClassOnly: true,
  })
  public readonly type = V1PresentationPreview.type.messageTypeUri
  public static readonly type = parseMessageType('https://didcomm.org/present-proof/1.0/presentation-preview')

  @Type(() => V1PresentationPreviewAttribute)
  @ValidateNested({ each: true })
  @IsInstance(V1PresentationPreviewAttribute, { each: true })
  public attributes!: V1PresentationPreviewAttribute[]

  @Type(() => V1PresentationPreviewPredicate)
  @ValidateNested({ each: true })
  @IsInstance(V1PresentationPreviewPredicate, { each: true })
  public predicates!: V1PresentationPreviewPredicate[]

  public toJSON(): Record<string, unknown> {
    return JsonTransformer.toJSON(this)
  }
}
