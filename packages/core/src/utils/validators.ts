import type { Constructor } from './mixins'
import type { ValidationOptions } from 'class-validator'

import { isString, ValidateBy, isInstance, buildMessage } from 'class-validator'

export interface IsInstanceOrArrayOfInstancesValidationOptions extends ValidationOptions {
  classType: new (...args: any[]) => any
}

/**
 * Checks if the value is an instance of the specified object.
 */
export function IsStringOrInstance(targetType: Constructor, validationOptions?: ValidationOptions): PropertyDecorator {
  return ValidateBy(
    {
      name: 'isStringOrVerificationMethod',
      constraints: [targetType],
      validator: {
        validate: (value, args): boolean => isString(value) || isInstance(value, args?.constraints[0]),
        defaultMessage: buildMessage((eachPrefix, args) => {
          if (args?.constraints[0]) {
            return eachPrefix + `$property must be of type string or instance of ${args.constraints[0].name as string}`
          } else {
            return (
              eachPrefix + `isStringOrVerificationMethod decorator expects and object as value, but got falsy value.`
            )
          }
        }, validationOptions),
      },
    },
    validationOptions
  )
}

export function IsInstanceOrArrayOfInstances(
  validationOptions: IsInstanceOrArrayOfInstancesValidationOptions
): PropertyDecorator {
  return ValidateBy(
    {
      name: 'isInstanceOrArrayOfInstances',
      validator: {
        validate: (value): boolean => {
          if (Array.isArray(value)) {
            value.forEach((item) => {
              if (!isInstance(item, validationOptions.classType)) {
                return false
              }
            })
            return true
          }
          return isInstance(value, validationOptions.classType)
        },
        defaultMessage: buildMessage(
          (eachPrefix) => eachPrefix + `$property must be a string or instance of ${validationOptions.classType.name}`,
          validationOptions
        ),
      },
    },
    validationOptions
  )
}

export function isStringArray(value: any): value is string[] {
  return Array.isArray(value) && value.every((v) => typeof v === 'string')
}

export const UriValidator = new RegExp('w+:(/?/?)[^s]+')

export function IsUri(validationOptions?: ValidationOptions): PropertyDecorator {
  return ValidateBy(
    {
      name: 'isInstanceOrArrayOfInstances',
      validator: {
        validate: (value): boolean => {
          return UriValidator.test(value)
        },
        defaultMessage: buildMessage(
          (eachPrefix) => eachPrefix + `$property must be a string that matches regex: ${UriValidator.source}`,
          validationOptions
        ),
      },
    },
    validationOptions
  )
}
