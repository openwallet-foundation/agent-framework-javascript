import { decode, encode, encodingLength } from 'varint'

import { Buffer } from './buffer'

export class VarintEncoder {
  public static decode(data: Uint8Array | number[] | Buffer) {
    const code = decode(data)
    return [code, decode.bytes] as const
  }

  public static encode(int: number) {
    const target = new Buffer(VarintEncoder.encodingLength(int))
    encode(int, target)
    return target
  }

  public static encodeTo(int: number, target: Buffer | Uint8Array, offset = 0) {
    encode(int, target, offset)
    return target
  }

  public static encodingLength(int: number) {
    return encodingLength(int)
  }
}
