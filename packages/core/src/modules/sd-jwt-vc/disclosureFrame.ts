import type { JsonObject } from '../../types'

import { isObject } from 'class-validator'

type DisclosureFrame = {
  [key: string]: boolean | DisclosureFrame
}

export function buildDisclosureFrameForPayload(input: JsonObject): DisclosureFrame {
  return Object.fromEntries(
    Object.entries(input).map(([key, value]) => {
      // TODO: Array disclosure frames are not yet supported - treating entire array as disclosed
      if (Array.isArray(value)) {
        return [key, true]
      } else if (isObject(value)) {
        if (Object.keys.length === 0) return [key, false]
        return [key, buildDisclosureFrameForPayload(value)]
      } else {
        return [key, true]
      }
    })
  )
}
