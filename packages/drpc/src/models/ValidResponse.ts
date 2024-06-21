import type { ValidationOptions } from 'class-validator'

import { ValidateBy, ValidationError, buildMessage } from 'class-validator'

export function IsValidDrpcResponse(validationOptions?: ValidationOptions): PropertyDecorator {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return function (target: any, propertyKey: string | symbol) {
    ValidateBy(
      {
        name: 'isValidDrpcResponse',
        validator: {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          validate: (value: any): boolean => {
            // Check if value is a valid DrpcResponseObject, an array of DrpcResponseObject (possibly mixed with empty objects), or an empty object
            let isValid = false
            if (Array.isArray(value)) {
              if (value.length > 0) {
                isValid = value.every(isValidDrpcResponse)
              }
            } else {
              isValid = isValidDrpcResponse(value)
            }
            if (!isValid) {
              throw new ValidationError()
            }
            return isValid
          },
          defaultMessage: buildMessage(
            (eachPrefix) => eachPrefix + '$property is not a valid DrpcResponse',
            validationOptions
          ),
        },
      },
      validationOptions
    )(target, propertyKey)
  }
}

export function isValidDrpcResponse(value: any): boolean {
  // Check if value is an object
  if (typeof value !== 'object' || value === null) {
    return false
  }

  // Check if it's an empty object
  if (Object.keys(value).length === 0) {
    return true
  }

  // Check if it's a valid DrpcResponseObject
  if ('jsonrpc' in value && 'id' in value) {
    // Check if 'result' and 'error' are valid
    if ('result' in value && typeof value.result === 'undefined') {
      return false
    }
    if ('error' in value && !isValidDrpcResponseError(value.error)) {
      return false
    }
    return true
  }

  return false
}

function isValidDrpcResponseError(error: any): boolean {
  return typeof error === 'object' && error !== null && 'code' in error && 'message' in error
}
