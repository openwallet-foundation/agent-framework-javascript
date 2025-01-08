import type { AnonCredsSchema, AnonCredsCredentialValues } from '../models'
import type { CredentialPreviewAttributeOptions, LinkedAttachment } from '@credo-ts/didcomm'

import { Buffer, CredoError, Hasher, TypedArrayEncoder } from '@credo-ts/core'
import { encodeAttachment } from '@credo-ts/didcomm'
import bigInt from 'big-integer'

export type AnonCredsClaimRecord = Record<string, string | number>

export interface AnonCredsCredentialValue {
  raw: string
  encoded: string // Raw value as number in string
}

const isString = (value: unknown): value is string => typeof value === 'string'
const isNumber = (value: unknown): value is number => typeof value === 'number'
const isBoolean = (value: unknown): value is boolean => typeof value === 'boolean'
const isNumeric = (value: string) => /^-?\d+$/.test(value)

const isInt32 = (number: number) => {
  const minI32 = -2147483648
  const maxI32 = 2147483647

  // Check if number is integer and in range of int32
  return Number.isInteger(number) && number >= minI32 && number <= maxI32
}

// TODO: this function can only encode strings
// If encoding numbers we run into problems with 0.0 representing the same value as 0 and is implicitly converted to 0
/**
 * Encode value according to the encoding format described in Aries RFC 0036/0037
 *
 * @param value
 * @returns Encoded version of value
 *
 * @see https://github.com/hyperledger/aries-cloudagent-python/blob/0000f924a50b6ac5e6342bff90e64864672ee935/aries_cloudagent/messaging/util.py#L106-L136
 * @see https://github.com/hyperledger/aries-rfcs/blob/be4ad0a6fb2823bb1fc109364c96f077d5d8dffa/features/0037-present-proof/README.md#verifying-claims-of-indy-based-verifiable-credentials
 * @see https://github.com/hyperledger/aries-rfcs/blob/be4ad0a6fb2823bb1fc109364c96f077d5d8dffa/features/0036-issue-credential/README.md#encoding-claims-for-indy-based-verifiable-credentials
 */
export function encodeCredentialValue(value: unknown) {
  const isEmpty = (value: unknown) => isString(value) && value === ''

  // If bool return bool as number string
  if (isBoolean(value)) {
    return Number(value).toString()
  }

  // If value is int32 return as number string
  if (isNumber(value) && isInt32(value)) {
    return value.toString()
  }

  // If value is an int32 number string return as number string
  if (isString(value) && !isEmpty(value) && !isNaN(Number(value)) && isNumeric(value) && isInt32(Number(value))) {
    return Number(value).toString()
  }

  if (isNumber(value)) {
    value = value.toString()
  }

  // If value is null we must use the string value 'None'
  if (value === null || value === undefined) {
    value = 'None'
  }

  const buffer = TypedArrayEncoder.fromString(String(value))
  const hash = Hasher.hash(buffer, 'sha-256')
  const hex = Buffer.from(hash).toString('hex')

  return bigInt(hex, 16).toString()
}

export const mapAttributeRawValuesToAnonCredsCredentialValues = (
  record: AnonCredsClaimRecord
): Record<string, AnonCredsCredentialValue> => {
  const credentialValues: Record<string, AnonCredsCredentialValue> = {}

  for (const [key, value] of Object.entries(record)) {
    if (typeof value === 'object') {
      throw new CredoError(`Unsupported value type: object for W3cAnonCreds Credential`)
    }
    credentialValues[key] = {
      raw: value.toString(),
      encoded: encodeCredentialValue(value),
    }
  }

  return credentialValues
}

/**
 * Converts int value to string
 * Converts string value:
 * - hash with sha256,
 * - convert to byte array and reverse it
 * - convert it to BigInteger and return as a string
 * @param attributes
 *
 * @returns CredValues
 */
export function convertAttributesToCredentialValues(
  attributes: CredentialPreviewAttributeOptions[]
): AnonCredsCredentialValues {
  return attributes.reduce((credentialValues, attribute) => {
    return {
      [attribute.name]: {
        raw: attribute.value,
        encoded: encodeCredentialValue(attribute.value),
      },
      ...credentialValues,
    }
  }, {})
}

/**
 * Check whether the values of two credentials match (using {@link assertCredentialValuesMatch})
 *
 * @returns a boolean whether the values are equal
 *
 */
export function checkCredentialValuesMatch(
  firstValues: AnonCredsCredentialValues,
  secondValues: AnonCredsCredentialValues
): boolean {
  try {
    assertCredentialValuesMatch(firstValues, secondValues)
    return true
  } catch {
    return false
  }
}

/**
 * Assert two credential values objects match.
 *
 * @param firstValues The first values object
 * @param secondValues The second values object
 *
 * @throws If not all values match
 */
export function assertCredentialValuesMatch(
  firstValues: AnonCredsCredentialValues,
  secondValues: AnonCredsCredentialValues
) {
  const firstValuesKeys = Object.keys(firstValues)
  const secondValuesKeys = Object.keys(secondValues)

  if (firstValuesKeys.length !== secondValuesKeys.length) {
    throw new Error(
      `Number of values in first entry (${firstValuesKeys.length}) does not match number of values in second entry (${secondValuesKeys.length})`
    )
  }

  for (const key of firstValuesKeys) {
    const firstValue = firstValues[key]
    const secondValue = secondValues[key]

    if (!secondValue) {
      throw new Error(`Second cred values object has no value for key '${key}'`)
    }

    if (firstValue.encoded !== secondValue.encoded) {
      throw new Error(`Encoded credential values for key '${key}' do not match`)
    }

    if (firstValue.raw !== secondValue.raw) {
      throw new Error(`Raw credential values for key '${key}' do not match`)
    }
  }
}

/**
 * Check whether the raw value matches the encoded version according to the encoding format described in Aries RFC 0037
 * Use this method to ensure the received proof (over the encoded) value is the same as the raw value of the data.
 *
 * @param raw
 * @param encoded
 * @returns Whether raw and encoded value match
 *
 * @see https://github.com/hyperledger/aries-framework-dotnet/blob/a18bef91e5b9e4a1892818df7408e2383c642dfa/src/Hyperledger.Aries/Utils/CredentialUtils.cs#L78-L89
 * @see https://github.com/hyperledger/aries-rfcs/blob/be4ad0a6fb2823bb1fc109364c96f077d5d8dffa/features/0037-present-proof/README.md#verifying-claims-of-indy-based-verifiable-credentials
 */
export function checkValidCredentialValueEncoding(raw: unknown, encoded: string) {
  return encoded === encodeCredentialValue(raw)
}

export function assertAttributesMatch(schema: AnonCredsSchema, attributes: CredentialPreviewAttributeOptions[]) {
  const schemaAttributes = schema.attrNames
  const credAttributes = attributes.map((a) => a.name)

  const difference = credAttributes
    .filter((x) => !schemaAttributes.includes(x))
    .concat(schemaAttributes.filter((x) => !credAttributes.includes(x)))

  if (difference.length > 0) {
    throw new CredoError(
      `The credential preview attributes do not match the schema attributes (difference is: ${difference}, needs: ${schemaAttributes})`
    )
  }
}

/**
 * Adds attribute(s) to the credential preview that is linked to the given attachment(s)
 *
 * @param attachments a list of the attachments that need to be linked to a credential
 * @param preview the credential previews where the new linked credential has to be appended to
 *
 * @returns a modified version of the credential preview with the linked credentials
 * */
export function createAndLinkAttachmentsToPreview(
  attachments: LinkedAttachment[],
  previewAttributes: CredentialPreviewAttributeOptions[]
) {
  const credentialPreviewAttributeNames = previewAttributes.map((attribute) => attribute.name)
  const newPreviewAttributes = [...previewAttributes]

  attachments.forEach((linkedAttachment) => {
    if (credentialPreviewAttributeNames.includes(linkedAttachment.attributeName)) {
      throw new CredoError(`linkedAttachment ${linkedAttachment.attributeName} already exists in the preview`)
    } else {
      newPreviewAttributes.push({
        name: linkedAttachment.attributeName,
        mimeType: linkedAttachment.attachment.mimeType,
        value: encodeAttachment(linkedAttachment.attachment),
      })
    }
  })

  return newPreviewAttributes
}
