import type { Wallet } from '@credo-ts/core'

import { Buffer, CredoError, JsonEncoder, Key, KeyType, TypedArrayEncoder, utils } from '@credo-ts/core'

import { SignatureDecorator } from './SignatureDecorator'

/**
 * Unpack and verify signed data before casting it to the supplied type.
 *
 * @param decorator Signature decorator to unpack and verify
 * @param wallet wallet instance
 *
 * @return Resulting data
 */
export async function unpackAndVerifySignatureDecorator(
  decorator: SignatureDecorator,
  wallet: Wallet
): Promise<Record<string, unknown>> {
  const signerVerkey = decorator.signer
  const key = Key.fromPublicKeyBase58(signerVerkey, KeyType.Ed25519)

  // first 8 bytes are for 64 bit integer from unix epoch
  const signedData = TypedArrayEncoder.fromBase64(decorator.signatureData)
  const signature = TypedArrayEncoder.fromBase64(decorator.signature)

  // const isValid = await wallet.verify(signerVerkey, signedData, signature)
  const isValid = await wallet.verify({ signature, data: signedData, key })

  if (!isValid) {
    throw new CredoError('Signature is not valid')
  }

  // TODO: return Connection instance instead of raw json
  return JsonEncoder.fromBuffer(signedData.slice(8))
}

/**
 * Sign data supplied and return a signature decorator.
 *
 * @param data the data to sign
 * @param wallet the wallet containing a key to use for signing
 * @param signerKey signers verkey
 *
 * @returns Resulting signature decorator.
 */
export async function signData(data: unknown, wallet: Wallet, signerKey: string): Promise<SignatureDecorator> {
  const dataBuffer = Buffer.concat([utils.timestamp(), JsonEncoder.toBuffer(data)])
  const key = Key.fromPublicKeyBase58(signerKey, KeyType.Ed25519)

  const signatureBuffer = await wallet.sign({ key, data: dataBuffer })

  const signatureDecorator = new SignatureDecorator({
    signatureType: 'https://didcomm.org/signature/1.0/ed25519Sha512_single',
    signature: TypedArrayEncoder.toBase64URL(signatureBuffer),
    signatureData: TypedArrayEncoder.toBase64URL(dataBuffer),
    signer: signerKey,
  })

  return signatureDecorator
}
