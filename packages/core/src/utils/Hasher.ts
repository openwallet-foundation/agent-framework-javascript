import { hash as sha256 } from '@stablelib/sha256'

import { TypedArrayEncoder } from './TypedArrayEncoder'

// TODO: use JWA Hashing Algorithm names
export type HashName = 'sha2-256' | 'sha-256'

type HashingMap = {
  [key in HashName]: (data: Uint8Array) => Uint8Array
}

const hashingMap: HashingMap = {
  'sha2-256': (data) => sha256(data),
  'sha-256': (data) => sha256(data),
}

export class Hasher {
  public static hash(data: Uint8Array | string, hashName: HashName | string): Uint8Array {
    const dataAsUint8Array = typeof data === 'string' ? TypedArrayEncoder.fromString(data) : data
    if (hashName in hashingMap) {
      const hashFn = hashingMap[hashName as HashName]
      return hashFn(dataAsUint8Array)
    }

    throw new Error(`Unsupported hash name '${hashName}'`)
  }
}
