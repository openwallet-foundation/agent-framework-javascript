// Question: Spec isn't clear about the endianness. Assumes big-endian here
// since ACA-Py uses big-endian.
export default function timestamp(): Uint8Array {
  let time = Date.now()
  const bytes = []
  for (let i = 0; i < 8; i++) {
    const byte = time & 0xff
    bytes.push(byte)
    time = (time - byte) / 256 // Javascript right shift (>>>) only works on 32 bit integers
  }
  return Uint8Array.from(bytes).reverse()
}

/**
 * Returns the current time in seconds
 */
export function nowInSeconds() {
  return Math.floor(new Date().getTime() / 1000)
}
