import type { PublicKey } from '../publicKey/PublicKey'

export abstract class Authentication {
  public abstract publicKey: PublicKey
}
