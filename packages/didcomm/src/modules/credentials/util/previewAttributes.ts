import type { CredentialPreviewAttribute } from '../models'

export function arePreviewAttributesEqual(
  firstAttributes: CredentialPreviewAttribute[],
  secondAttributes: CredentialPreviewAttribute[]
) {
  if (firstAttributes.length !== secondAttributes.length) return false

  const secondAttributeMap = secondAttributes.reduce<Record<string, CredentialPreviewAttribute>>(
    (attributeMap, attribute) => ({ ...attributeMap, [attribute.name]: attribute }),
    {}
  )

  // check if no duplicate keys exist
  if (new Set(firstAttributes.map((attribute) => attribute.name)).size !== firstAttributes.length) return false
  if (new Set(secondAttributes.map((attribute) => attribute.name)).size !== secondAttributes.length) return false

  for (const firstAttribute of firstAttributes) {
    const secondAttribute = secondAttributeMap[firstAttribute.name]

    if (!secondAttribute) return false
    if (firstAttribute.value !== secondAttribute.value) return false
    if (firstAttribute.mimeType !== secondAttribute.mimeType) return false
  }

  return true
}
