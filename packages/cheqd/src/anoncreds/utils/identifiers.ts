import type { CheqdNetwork } from '@cheqd/sdk'
import type { ParsedDid } from '@credo-ts/core'

import { TypedArrayEncoder, utils } from '@credo-ts/core'
import { isBase58 } from 'class-validator'

const ID_CHAR = '([a-z,A-Z,0-9,-])'
const NETWORK = '(testnet|mainnet)'
const IDENTIFIER = `((?:${ID_CHAR}*:)*(${ID_CHAR}+))`
const PATH = `(/[^#?]*)?`
const QUERY = `([?][^#]*)?`
const VERSION_ID = `(.*?)`
const FRAGMENT = `([#].*)?`

export const cheqdSdkAnonCredsRegistryIdentifierRegex = new RegExp(
  `^did:cheqd:${NETWORK}:${IDENTIFIER}${PATH}${QUERY}${FRAGMENT}$`
)

export const cheqdDidRegex = new RegExp(`^did:cheqd:${NETWORK}:${IDENTIFIER}${QUERY}${FRAGMENT}$`)
export const cheqdDidVersionRegex = new RegExp(
  `^did:cheqd:${NETWORK}:${IDENTIFIER}/version/${VERSION_ID}${QUERY}${FRAGMENT}$`
)
export const cheqdDidVersionsRegex = new RegExp(`^did:cheqd:${NETWORK}:${IDENTIFIER}/versions${QUERY}${FRAGMENT}$`)
export const cheqdDidMetadataRegex = new RegExp(`^did:cheqd:${NETWORK}:${IDENTIFIER}/metadata${QUERY}${FRAGMENT}$`)
export const cheqdResourceRegex = new RegExp(
  `^did:cheqd:${NETWORK}:${IDENTIFIER}/resources/${IDENTIFIER}${QUERY}${FRAGMENT}$`
)
export const cheqdResourceMetadataRegex = new RegExp(
  `^did:cheqd:${NETWORK}:${IDENTIFIER}/resources/${IDENTIFIER}/metadata${QUERY}${FRAGMENT}`
)

export type ParsedCheqdDid = ParsedDid & { network: `${CheqdNetwork}` }
export function parseCheqdDid(didUrl: string): ParsedCheqdDid | null {
  if (didUrl === '' || !didUrl) return null
  const sections = didUrl.match(cheqdSdkAnonCredsRegistryIdentifierRegex)
  if (sections) {
    if (
      !(
        utils.isValidUuid(sections[2]) ||
        (isBase58(sections[2]) && TypedArrayEncoder.fromBase58(sections[2]).length == 16)
      )
    ) {
      return null
    }
    const parts: ParsedCheqdDid = {
      did: `did:cheqd:${sections[1]}:${sections[2]}`,
      method: 'cheqd',
      network: sections[1] as `${CheqdNetwork}`,
      id: sections[2],
      didUrl,
    }
    if (sections[7]) {
      const params = sections[7].slice(1).split('&')
      parts.params = {}
      for (const p of params) {
        const kv = p.split('=')
        parts.params[kv[0]] = kv[1]
      }
    }
    if (sections[6]) parts.path = sections[6]
    if (sections[8]) parts.fragment = sections[8].slice(1)
    return parts
  }
  return null
}

export const cheqdAnonCredsResourceTypes = {
  schema: 'anonCredsSchema',
  credentialDefinition: 'anonCredsCredDef',
  revocationRegistryDefinition: 'anonCredsRevocRegDef',
  revocationStatusList: 'anonCredsStatusList',
}
