import type { Wallet } from '@credo-ts/core'

import { AriesFrameworkError } from '@credo-ts/core'

import { IndySdkWallet } from '../wallet/IndySdkWallet'

export function assertIndySdkWallet(wallet: Wallet): asserts wallet is IndySdkWallet {
  if (!(wallet instanceof IndySdkWallet)) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const walletClassName = (wallet as any).constructor?.name ?? 'unknown'
    throw new AriesFrameworkError(`Expected wallet to be instance of IndySdkWallet, found ${walletClassName}`)
  }
}
