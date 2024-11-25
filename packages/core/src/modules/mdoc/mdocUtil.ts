export function nameSpacesRecordToMap<
  // eslint-disable-next-line @typescript-eslint/no-unnecessary-type-constraint
  NamespaceValue extends unknown,
  NameSpaces extends Record<string, Record<string, NamespaceValue>>
>(nameSpaces: NameSpaces): Map<string, Map<string, NamespaceValue>> {
  return new Map(Object.entries(nameSpaces).map(([key, value]) => [key, new Map(Object.entries(value))] as const))
}
