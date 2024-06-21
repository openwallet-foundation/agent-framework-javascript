import type { ValidationOptions } from 'class-validator'

import { Transform, TransformationType } from 'class-transformer'
import { IsOptional, ValidateBy, buildMessage, isInstance } from 'class-validator'

import { CredoError } from '../../../../error'

/**
 * @see https://www.w3.org/TR/vc-data-model/#credential-subject
 */

export interface W3cCredentialSubjectOptions {
  id?: string
  // note claims must not contain an id field
  claims?: Record<string, unknown>
}

export class W3cCredentialSubject {
  public constructor(options: W3cCredentialSubjectOptions) {
    if (options) {
      this.id = options.id

      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { id, ...claims } = options.claims ?? {}
      this.claims = Object.keys(claims).length > 0 ? claims : undefined
    }
  }

  @IsOptional()
  public id?: string

  @IsOptional()
  public claims?: Record<string, unknown>
}

export function W3cCredentialSubjectTransformer() {
  return Transform(({ value, type }: { value: W3cCredentialSubjectOptions; type: TransformationType }) => {
    if (type === TransformationType.PLAIN_TO_CLASS) {
      const vToClass = (v: unknown) => {
        if (!v || typeof v !== 'object') throw new CredoError('Invalid credential subject')
        if (isInstance(v, W3cCredentialSubject)) return v
        const { id, ...claims } = v as Record<string, unknown>
        if (id !== undefined && typeof id !== 'string') throw new CredoError('Invalid credential subject id')
        return new W3cCredentialSubject({ id, claims })
      }

      if (Array.isArray(value) && value.length === 0) {
        throw new CredoError('At least one credential subject is required')
      }

      return Array.isArray(value) ? value.map(vToClass) : vToClass(value)
    } else if (type === TransformationType.CLASS_TO_PLAIN) {
      const vToJson = (v: unknown) => {
        if (v instanceof W3cCredentialSubject) return v.id ? { ...v.claims, id: v.id } : { ...v.claims }
        return v
      }

      return Array.isArray(value) ? value.map(vToJson) : vToJson(value)
    }
    // PLAIN_TO_PLAIN
    return value
  })
}

export function IsW3cCredentialSubject(validationOptions?: ValidationOptions): PropertyDecorator {
  return ValidateBy(
    {
      name: 'IsW3cCredentialSubject',
      validator: {
        validate: (value): boolean => {
          return isInstance(value, W3cCredentialSubject)
        },
        defaultMessage: buildMessage(
          (eachPrefix) =>
            eachPrefix + '$property must be an object or an array of objects with an optional id property',
          validationOptions
        ),
      },
    },
    validationOptions
  )
}
