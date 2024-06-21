import type { AbstractCheqdSDKModule, CheqdSDK, DidStdFee, DIDDocument } from '@cheqd/sdk'
import type { QueryAllDidDocVersionsMetadataResponse, SignInfo } from '@cheqd/ts-proto/cheqd/did/v2'
import type { MsgCreateResourcePayload } from '@cheqd/ts-proto/cheqd/resource/v2'
import type { DirectSecp256k1HdWallet, DirectSecp256k1Wallet } from '@cosmjs/proto-signing'
import type { DidDocumentMetadata } from '@credo-ts/core'

import { createCheqdSDK, DIDModule, ResourceModule, CheqdNetwork } from '@cheqd/sdk'
import { CredoError, inject, injectable, InjectionSymbols, Logger } from '@credo-ts/core'

import { CheqdModuleConfig } from '../CheqdModuleConfig'
import { parseCheqdDid } from '../anoncreds/utils/identifiers'
import { getCosmosPayerWallet } from '../dids/didCheqdUtil'

export interface ICheqdLedgerConfig {
  network: string
  rpcUrl: string
  readonly cosmosPayerWallet: Promise<DirectSecp256k1HdWallet | DirectSecp256k1Wallet>
  sdk?: Promise<CheqdSDK>
}

export enum DefaultRPCUrl {
  Mainnet = 'https://rpc.cheqd.net',
  Testnet = 'https://rpc.cheqd.network',
}

@injectable()
export class CheqdLedgerService {
  private networks: ICheqdLedgerConfig[]
  private logger: Logger

  public constructor(cheqdSdkModuleConfig: CheqdModuleConfig, @inject(InjectionSymbols.Logger) logger: Logger) {
    this.logger = logger
    this.networks = cheqdSdkModuleConfig.networks.map((config) => {
      const { network, rpcUrl, cosmosPayerSeed } = config
      return {
        network,
        rpcUrl: rpcUrl ? rpcUrl : network === CheqdNetwork.Mainnet ? DefaultRPCUrl.Mainnet : DefaultRPCUrl.Testnet,
        cosmosPayerWallet: getCosmosPayerWallet(cosmosPayerSeed),
      }
    })
  }

  public async connect() {
    for (const network of this.networks) {
      if (!network.sdk) {
        await this.initializeSdkForNetwork(network)
      } else {
        this.logger.debug(`Not connecting to network ${network} as SDK already initialized`)
      }
    }
  }

  private async getSdk(did: string) {
    const parsedDid = parseCheqdDid(did)
    if (!parsedDid) {
      throw new Error('Invalid DID')
    }
    if (this.networks.length === 0) {
      throw new Error('No cheqd networks configured')
    }

    const network = this.networks.find((network) => network.network === parsedDid.network)
    if (!network) {
      throw new Error(`Network ${network} not found in cheqd networks configuration`)
    }

    if (!network.sdk) {
      const sdk = await this.initializeSdkForNetwork(network)
      if (!sdk) throw new Error(`Cheqd SDK not initialized for network ${parsedDid.network}`)
      return sdk
    }

    try {
      const sdk = await network.sdk
      return sdk
    } catch (error) {
      throw new Error(`Error initializing cheqd sdk for network ${parsedDid.network}: ${error.message}`)
    }
  }

  private async initializeSdkForNetwork(network: ICheqdLedgerConfig) {
    try {
      // Initialize cheqd sdk with promise
      network.sdk = createCheqdSDK({
        modules: [DIDModule as unknown as AbstractCheqdSDKModule, ResourceModule as unknown as AbstractCheqdSDKModule],
        rpcUrl: network.rpcUrl,
        wallet: await network.cosmosPayerWallet.catch((error) => {
          throw new CredoError(`Error initializing cosmos payer wallet: ${error.message}`, { cause: error })
        }),
      })

      return await network.sdk
    } catch (error) {
      this.logger.error(
        `Skipping connection for network ${network.network} in cheqd sdk due to error in initialization: ${error.message}`
      )
      network.sdk = undefined
      return undefined
    }
  }

  public async create(
    didPayload: DIDDocument,
    signInputs: SignInfo[],
    versionId?: string | undefined,
    fee?: DidStdFee
  ) {
    const sdk = await this.getSdk(didPayload.id)
    return sdk.createDidDocTx(signInputs, didPayload, '', fee, undefined, versionId)
  }

  public async update(
    didPayload: DIDDocument,
    signInputs: SignInfo[],
    versionId?: string | undefined,
    fee?: DidStdFee
  ) {
    const sdk = await this.getSdk(didPayload.id)
    return sdk.updateDidDocTx(signInputs, didPayload, '', fee, undefined, versionId)
  }

  public async deactivate(
    didPayload: DIDDocument,
    signInputs: SignInfo[],
    versionId?: string | undefined,
    fee?: DidStdFee
  ) {
    const sdk = await this.getSdk(didPayload.id)
    return sdk.deactivateDidDocTx(signInputs, didPayload, '', fee, undefined, versionId)
  }

  public async resolve(did: string, version?: string) {
    const sdk = await this.getSdk(did)
    return version ? sdk.queryDidDocVersion(did, version) : sdk.queryDidDoc(did)
  }

  public async resolveMetadata(did: string): Promise<{
    didDocumentVersionsMetadata: DidDocumentMetadata[]
    pagination: QueryAllDidDocVersionsMetadataResponse['pagination']
  }> {
    const sdk = await this.getSdk(did)
    return sdk.queryAllDidDocVersionsMetadata(did)
  }

  public async createResource(
    did: string,
    resourcePayload: Partial<MsgCreateResourcePayload>,
    signInputs: SignInfo[],
    fee?: DidStdFee
  ) {
    const sdk = await this.getSdk(did)
    return sdk.createLinkedResourceTx(signInputs, resourcePayload, '', fee, undefined)
  }

  public async resolveResource(did: string, collectionId: string, resourceId: string) {
    const sdk = await this.getSdk(did)
    return sdk.queryLinkedResource(collectionId, resourceId)
  }

  public async resolveCollectionResources(did: string, collectionId: string) {
    const sdk = await this.getSdk(did)
    return sdk.queryLinkedResources(collectionId)
  }

  public async resolveResourceMetadata(did: string, collectionId: string, resourceId: string) {
    const sdk = await this.getSdk(did)
    return sdk.queryLinkedResourceMetadata(collectionId, resourceId)
  }
}
