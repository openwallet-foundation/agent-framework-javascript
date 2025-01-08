import type { ConnectionRecord } from '../../didcomm/src'

declare global {
  namespace jest {
    interface Matchers<R> {
      toBeConnectedWith(connection: ConnectionRecord): R
    }
  }
}
