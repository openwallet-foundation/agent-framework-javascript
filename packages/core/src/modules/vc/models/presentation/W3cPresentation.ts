import type { W3cHolderOptions } from './W3cHolder'
import type { JsonObject } from '../../../../types'
import type { W3cVerifiableCredential } from '../credential/W3cVerifiableCredential'
import type { ValidationOptions } from 'class-validator'

import { Expose } from 'class-transformer'
import { ValidateNested, buildMessage, IsOptional, ValidateBy } from 'class-validator'

import { SingleOrArray } from '../../../../utils/type'
import { IsUri, IsInstanceOrArrayOfInstances } from '../../../../utils/validators'
import { DifPresentationExchangeSubmission } from '../../../dif-presentation-exchange/models'
import { CREDENTIALS_CONTEXT_V1_URL, VERIFIABLE_PRESENTATION_TYPE } from '../../constants'
import { W3cJsonLdVerifiableCredential } from '../../data-integrity/models/W3cJsonLdVerifiableCredential'
import { W3cJwtVerifiableCredential } from '../../jwt-vc/W3cJwtVerifiableCredential'
import { IsCredentialJsonLdContext } from '../../validators'
import { W3cVerifiableCredentialTransformer } from '../credential/W3cVerifiableCredential'

import { IsW3cHolder, W3cHolder, W3cHolderTransformer } from './W3cHolder'

export interface W3cPresentationOptions {
  id?: string
  context?: Array<string | JsonObject>
  type?: Array<string>
  verifiableCredential: SingleOrArray<W3cVerifiableCredential>
  holder?: string | W3cHolderOptions
  presentationSubmission?: DifPresentationExchangeSubmission
}

export class W3cPresentation {
  public constructor(options: W3cPresentationOptions) {
    if (options) {
      this.id = options.id
      this.context = options.context ?? [CREDENTIALS_CONTEXT_V1_URL]
      this.type = options.type ?? [VERIFIABLE_PRESENTATION_TYPE]
      this.verifiableCredential = options.verifiableCredential
      this.presentationSubmission = options.presentationSubmission

      if (options.holder) {
        this.holder = typeof options.holder === 'string' ? options.holder : new W3cHolder(options.holder)
      }
    }
  }

  @Expose({ name: '@context' })
  @IsCredentialJsonLdContext()
  public context!: Array<string | JsonObject>

  /**
   * NOTE: not validated
   */
  @Expose({ name: 'presentation_submission' })
  public presentationSubmission?: DifPresentationExchangeSubmission

  @IsOptional()
  @IsUri()
  public id?: string

  @IsVerifiablePresentationType()
  public type!: Array<string>

  @W3cHolderTransformer()
  @IsW3cHolder()
  @IsOptional()
  public holder?: string | W3cHolder

  @W3cVerifiableCredentialTransformer()
  @IsInstanceOrArrayOfInstances({ classType: [W3cJsonLdVerifiableCredential, W3cJwtVerifiableCredential] })
  @ValidateNested({ each: true })
  public verifiableCredential!: SingleOrArray<W3cVerifiableCredential>

  public get holderId(): string | null {
    if (!this.holder) return null

    return this.holder instanceof W3cHolder ? this.holder.id : this.holder
  }
}

// Custom validators

export function IsVerifiablePresentationType(validationOptions?: ValidationOptions): PropertyDecorator {
  return ValidateBy(
    {
      name: 'IsVerifiablePresentationType',
      validator: {
        validate: (value): boolean => {
          if (Array.isArray(value)) {
            return value.includes(VERIFIABLE_PRESENTATION_TYPE)
          }
          return false
        },
        defaultMessage: buildMessage(
          (eachPrefix) => eachPrefix + '$property must be an array of strings which includes "VerifiablePresentation"',
          validationOptions
        ),
      },
    },
    validationOptions
  )
}
