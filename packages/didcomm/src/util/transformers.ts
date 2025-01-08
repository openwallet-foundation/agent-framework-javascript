import { DateTime } from 'luxon'

/*
 * Function that parses date from multiple formats
 * including SQL formats.
 */

export function DateParser(value: string): Date {
  const parsedDate = new Date(value)
  if (parsedDate instanceof Date && !isNaN(parsedDate.getTime())) {
    return parsedDate
  }
  const luxonDate = DateTime.fromSQL(value)
  if (luxonDate.isValid) {
    return new Date(luxonDate.toString())
  }
  return new Date()
}
