import type { InitConfig, WalletConfig } from '@credo-ts/core'

// FIXME: decide what to do with connectionImageUrl, since this would make this module dependant on didcomm
export type TenantConfig = Pick<InitConfig, 'label'> & {
  walletConfig: Pick<WalletConfig, 'id' | 'key' | 'keyDerivationMethod'>
}
