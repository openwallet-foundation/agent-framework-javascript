import type { ValidationOptions } from 'class-validator'

import { ValidateBy, ValidationError, buildMessage } from 'class-validator'

export function IsValidDrpcRequest(validationOptions?: ValidationOptions): PropertyDecorator {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return function (target: any, propertyKey: string | symbol) {
    ValidateBy(
      {
        name: 'isValidDrpcRequest',
        validator: {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          validate: (value: any): boolean => {
            // Check if value is a DrpcRequestObject or an array of DrpcRequestObject
            let isValid = false
            if (!Array.isArray(value)) {
              isValid = isValidDrpcRequest(value)
            } else {
              isValid = value.every(isValidDrpcRequest)
            }

            if (!isValid) {
              throw new ValidationError()
            }

            return isValid
          },
          defaultMessage: buildMessage(
            (eachPrefix) => eachPrefix + '$property is not a valid DrpcRequest',
            validationOptions
          ),
        },
      },
      validationOptions
    )(target, propertyKey)
  }
}

export function isValidDrpcRequest(value: any): boolean {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false
  }
  return 'jsonrpc' in value && 'method' in value && 'id' in value
}
