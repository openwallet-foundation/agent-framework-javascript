import type { Key } from './Key'
import type { LdKeyPairOptions } from '../modules/vc/data-integrity/models/LdKeyPair'
import type { Wallet } from '../wallet'

import { VerificationMethod } from '../modules/dids'
import { getKeyFromVerificationMethod } from '../modules/dids/domain/key-type/keyDidMapping'
import { LdKeyPair } from '../modules/vc/data-integrity/models/LdKeyPair'
import { JsonTransformer, MessageValidator } from '../utils'
import { Buffer } from '../utils/buffer'

interface WalletKeyPairOptions extends LdKeyPairOptions {
  wallet: Wallet
  key: Key
}

export function createWalletKeyPairClass(wallet: Wallet) {
  return class WalletKeyPair extends LdKeyPair {
    public wallet: Wallet
    public key: Key
    public type: string

    public constructor(options: WalletKeyPairOptions) {
      super(options)
      this.wallet = options.wallet
      this.key = options.key
      this.type = options.key.keyType
    }

    public static async generate(): Promise<WalletKeyPair> {
      throw new Error('Not implemented')
    }

    public fingerprint(): string {
      throw new Error('Method not implemented.')
    }

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    public verifyFingerprint(fingerprint: string): boolean {
      throw new Error('Method not implemented.')
    }

    public static async from(verificationMethod: VerificationMethod): Promise<WalletKeyPair> {
      const vMethod = JsonTransformer.fromJSON(verificationMethod, VerificationMethod)
      MessageValidator.validateSync(vMethod)
      const key = getKeyFromVerificationMethod(vMethod)

      return new WalletKeyPair({
        id: vMethod.id,
        controller: vMethod.controller,
        wallet: wallet,
        key: key,
      })
    }

    /**
     * This method returns a wrapped wallet.sign method. The method is being wrapped so we can covert between Uint8Array and Buffer. This is to make it compatible with the external signature libraries.
     */
    public signer(): { sign: (data: { data: Uint8Array | Uint8Array[] }) => Promise<Uint8Array> } {
      // wrap function for conversion
      const wrappedSign = async (data: { data: Uint8Array | Uint8Array[] }): Promise<Uint8Array> => {
        let converted: Buffer | Buffer[] = []

        // convert uint8array to buffer
        if (Array.isArray(data.data)) {
          converted = data.data.map((d) => Buffer.from(d))
        } else {
          converted = Buffer.from(data.data)
        }

        // sign
        const result = await wallet.sign({
          data: converted,
          key: this.key,
        })

        // convert result buffer to uint8array
        return Uint8Array.from(result)
      }

      return {
        sign: wrappedSign.bind(this),
      }
    }

    /**
     * This method returns a wrapped wallet.verify method. The method is being wrapped so we can covert between Uint8Array and Buffer. This is to make it compatible with the external signature libraries.
     */
    public verifier(): {
      verify: (data: { data: Uint8Array | Uint8Array[]; signature: Uint8Array }) => Promise<boolean>
    } {
      const wrappedVerify = async (data: {
        data: Uint8Array | Uint8Array[]
        signature: Uint8Array
      }): Promise<boolean> => {
        let converted: Buffer | Buffer[] = []

        // convert uint8array to buffer
        if (Array.isArray(data.data)) {
          converted = data.data.map((d) => Buffer.from(d))
        } else {
          converted = Buffer.from(data.data)
        }

        // verify
        return wallet.verify({
          data: converted,
          signature: Buffer.from(data.signature),
          key: this.key,
        })
      }
      return {
        verify: wrappedVerify.bind(this),
      }
    }

    public get publicKeyBuffer(): Uint8Array {
      return new Uint8Array(this.key.publicKey)
    }
  }
}
