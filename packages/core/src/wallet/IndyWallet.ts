import type { Logger } from '../logger'
import type { UnpackedMessageContext, WireMessage } from '../types'
import type { Buffer } from '../utils/buffer'
import type { Wallet, DidInfo } from './Wallet'
import type {
  default as Indy,
  Did,
  DidConfig,
  LedgerRequest,
  Verkey,
  WalletConfig,
  WalletCredentials,
  WalletQuery,
  WalletRecord,
  WalletRecordOptions,
  WalletSearchOptions,
} from 'indy-sdk'

import { Lifecycle, scoped } from 'tsyringe'

import { AgentConfig } from '../agent/AgentConfig'
import { AriesFrameworkError } from '../error'
import { JsonEncoder } from '../utils/JsonEncoder'
import { isIndyError } from '../utils/indyError'

import { WalletDuplicateError, WalletNotFoundError, WalletError } from './error'

export interface IndyOpenWallet {
  walletHandle: number
  masterSecretId: string
  walletConfig: WalletConfig
  walletCredentials: WalletCredentials
}

@scoped(Lifecycle.ContainerScoped)
export class IndyWallet implements Wallet {
  private openWalletInfo?: IndyOpenWallet

  private logger: Logger
  private publicDidInfo: DidInfo | undefined
  private indy: typeof Indy

  public constructor(agentConfig: AgentConfig) {
    this.logger = agentConfig.logger
    this.indy = agentConfig.agentDependencies.indy
  }

  public get isInitialized() {
    return this.openWalletInfo !== undefined
  }

  public get publicDid() {
    return this.publicDidInfo
  }

  public get walletHandle() {
    if (!this.isInitialized || !this.openWalletInfo) {
      throw new AriesFrameworkError('Wallet has not been initialized yet')
    }

    return this.openWalletInfo.walletHandle
  }

  public get masterSecretId() {
    if (!this.isInitialized || !this.openWalletInfo) {
      throw new AriesFrameworkError('Wallet has not been initialized yet')
    }

    return this.openWalletInfo.masterSecretId
  }

  public async initialize(walletConfig: WalletConfig, walletCredentials: WalletCredentials) {
    this.logger.info(`Initializing wallet '${walletConfig.id}'`, walletConfig)

    if (this.isInitialized) {
      throw new WalletError(
        'Wallet instance already initialized. Close the currently opened wallet before re-initializing the wallet'
      )
    }

    // Open wallet, creating if it doesn't exist yet
    try {
      await this.open(walletConfig, walletCredentials)
    } catch (error) {
      // If the wallet does not exist yet, create it and try to open again
      if (error instanceof WalletNotFoundError) {
        await this.create(walletConfig, walletCredentials)
        await this.open(walletConfig, walletCredentials)
      } else {
        throw error
      }
    }

    this.logger.debug(`Wallet '${walletConfig.id}' initialized with handle '${this.walletHandle}'`)
  }

  /**
   * @throws {WalletDuplicateError} if the wallet already exists
   * @throws {WalletError} if another error occurs
   */
  public async create(walletConfig: WalletConfig, walletCredentials: WalletCredentials): Promise<void> {
    const storageType = walletConfig.storage_type ?? 'SQLite'
    this.logger.debug(`Creating wallet '${walletConfig.id}' using ${storageType} storage`, {
      storageConfig: walletConfig.storage_config,
    })

    try {
      await this.indy.createWallet(walletConfig, walletCredentials)
    } catch (error) {
      if (isIndyError(error, 'WalletAlreadyExistsError')) {
        const errorMessage = `Wallet '${walletConfig.id}' already exists`
        this.logger.debug(errorMessage)

        throw new WalletDuplicateError(errorMessage, {
          walletType: 'IndyWallet',
          cause: error,
        })
      } else {
        const errorMessage = `Error creating wallet '${walletConfig.id}'`
        this.logger.error(errorMessage, {
          error,
          errorMessage: error.message,
        })

        throw new WalletError(errorMessage, { cause: error })
      }
    }
  }

  /**
   * @throws {WalletNotFoundError} if the wallet does not exist
   * @throws {WalletError} if another error occurs
   */
  public async open(walletConfig: WalletConfig, walletCredentials: WalletCredentials): Promise<void> {
    if (this.isInitialized) {
      throw new WalletError(
        'Wallet instance already initialized. Close the currently opened wallet before re-initializing the wallet'
      )
    }

    try {
      const walletHandle = await this.indy.openWallet(walletConfig, walletCredentials)
      const masterSecretId = await this.createMasterSecret(walletHandle, walletConfig.id)

      this.openWalletInfo = {
        walletConfig,
        walletCredentials,
        walletHandle,
        masterSecretId,
      }
    } catch (error) {
      if (isIndyError(error, 'WalletNotFoundError')) {
        const errorMessage = `Wallet '${walletConfig.id}' not found`
        this.logger.debug(errorMessage)

        throw new WalletNotFoundError(errorMessage, {
          walletType: 'IndyWallet',
          cause: error,
        })
      } else {
        const errorMessage = `Error opening wallet '${walletConfig.id}'`
        this.logger.error(errorMessage, {
          error,
          errorMessage: error.message,
        })

        throw new WalletError(errorMessage, { cause: error })
      }
    }
  }

  /**
   * @throws {WalletNotFoundError} if the wallet does not exist
   * @throws {WalletError} if another error occurs
   */
  public async delete(): Promise<void> {
    const walletInfo = this.openWalletInfo

    if (!this.isInitialized || !walletInfo) {
      throw new WalletError(
        'Can not delete wallet that is not initialized. Make sure to call initialize before deleting the wallet'
      )
    }

    this.logger.info(`Deleting wallet '${walletInfo.walletConfig.id}'`)

    await this.close()

    try {
      await this.indy.deleteWallet(walletInfo.walletConfig, walletInfo.walletCredentials)
    } catch (error) {
      if (isIndyError(error, 'WalletNotFoundError')) {
        const errorMessage = `Error deleting wallet: wallet '${walletInfo.walletConfig.id}' not found`
        this.logger.debug(errorMessage)

        throw new WalletNotFoundError(errorMessage, {
          walletType: 'IndyWallet',
          cause: error,
        })
      } else {
        const errorMessage = `Error deleting wallet '${walletInfo.walletConfig.id}': ${error.message}`
        this.logger.error(errorMessage, {
          error,
          errorMessage: error.message,
        })

        throw new WalletError(errorMessage, { cause: error })
      }
    }
  }

  /**
   * @throws {WalletError} if the wallet is already closed or another error occurs
   */
  public async close(): Promise<void> {
    try {
      await this.indy.closeWallet(this.walletHandle)
      this.openWalletInfo = undefined
      this.publicDidInfo = undefined
    } catch (error) {
      if (isIndyError(error, 'WalletInvalidHandle')) {
        const errorMessage = `Error closing wallet: wallet already closed`
        this.logger.debug(errorMessage)

        throw new WalletError(errorMessage, {
          cause: error,
        })
      } else {
        const errorMessage = `Error closing wallet': ${error.message}`
        this.logger.error(errorMessage, {
          error,
          errorMessage: error.message,
        })

        throw new WalletError(errorMessage, { cause: error })
      }
    }
  }

  /**
   * Create master secret with specified id in currently opened wallet.
   *
   * If a master secret by this id already exists in the current wallet, the method
   * will return without doing anything.
   *
   * @throws {WalletError} if an error occurs
   */
  private async createMasterSecret(walletHandle: number, masterSecretId: string): Promise<string> {
    this.logger.debug(`Creating master secret with id '${masterSecretId}' in wallet with handle '${walletHandle}'`)

    try {
      await this.indy.proverCreateMasterSecret(walletHandle, masterSecretId)

      return masterSecretId
    } catch (error) {
      if (isIndyError(error, 'AnoncredsMasterSecretDuplicateNameError')) {
        // master secret id is the same as the master secret id passed in the create function
        // so if it already exists we can just assign it.
        this.logger.debug(
          `Master secret with id '${masterSecretId}' already exists in wallet with handle '${walletHandle}'`,
          {
            indyError: 'AnoncredsMasterSecretDuplicateNameError',
          }
        )

        return masterSecretId
      } else {
        this.logger.error(`Error creating master secret with id ${masterSecretId}`, {
          indyError: error.indyName,
          error,
        })

        throw new WalletError(
          `Error creating master secret with id ${masterSecretId} in wallet with handle '${walletHandle}'`,
          { cause: error }
        )
      }
    }
  }

  public async initPublicDid(didConfig: DidConfig) {
    const [did, verkey] = await this.createDid(didConfig)
    this.publicDidInfo = {
      did,
      verkey,
    }
  }

  public async createDid(didConfig?: DidConfig): Promise<[Did, Verkey]> {
    return this.indy.createAndStoreMyDid(this.walletHandle, didConfig || {})
  }

  public async pack(payload: Record<string, unknown>, recipientKeys: Verkey[], senderVk: Verkey): Promise<WireMessage> {
    const messageRaw = JsonEncoder.toBuffer(payload)
    const packedMessage = await this.indy.packMessage(this.walletHandle, messageRaw, recipientKeys, senderVk)
    return JsonEncoder.fromBuffer(packedMessage)
  }

  public async unpack(messagePackage: WireMessage): Promise<UnpackedMessageContext> {
    const unpackedMessageBuffer = await this.indy.unpackMessage(this.walletHandle, JsonEncoder.toBuffer(messagePackage))
    const unpackedMessage = JsonEncoder.fromBuffer(unpackedMessageBuffer)
    return {
      recipientVerkey: unpackedMessage.recipient_verkey,
      senderVerkey: unpackedMessage.sender_verkey,
      message: JsonEncoder.fromString(unpackedMessage.message),
    }
  }

  public async sign(data: Buffer, verkey: Verkey): Promise<Buffer> {
    const signatureBuffer = await this.indy.cryptoSign(this.walletHandle, verkey, data)

    return signatureBuffer
  }

  public async verify(signerVerkey: Verkey, data: Buffer, signature: Buffer): Promise<boolean> {
    // check signature
    const isValid = await this.indy.cryptoVerify(signerVerkey, data, signature)

    return isValid
  }

  public async addWalletRecord(type: string, id: string, value: string, tags: Record<string, string>) {
    return this.indy.addWalletRecord(this.walletHandle, type, id, value, tags)
  }

  public async updateWalletRecordValue(type: string, id: string, value: string) {
    return this.indy.updateWalletRecordValue(this.walletHandle, type, id, value)
  }

  public async updateWalletRecordTags(type: string, id: string, tags: Record<string, string>) {
    return this.indy.addWalletRecordTags(this.walletHandle, type, id, tags)
  }

  public async deleteWalletRecord(type: string, id: string) {
    return this.indy.deleteWalletRecord(this.walletHandle, type, id)
  }

  public async search(type: string, query: WalletQuery, options: WalletSearchOptions) {
    const sh: number = await this.indy.openWalletSearch(this.walletHandle, type, query, options)
    const generator = async function* (indy: typeof Indy, wh: number) {
      try {
        while (true) {
          // count should probably be exported as a config?
          const recordSearch = await indy.fetchWalletSearchNextRecords(wh, sh, 10)
          for (const record of recordSearch.records) {
            yield record
          }
        }
      } catch (error) {
        // pass
      } finally {
        await indy.closeWalletSearch(sh)
      }
    }

    return generator(this.indy, this.walletHandle)
  }

  public getWalletRecord(type: string, id: string, options: WalletRecordOptions): Promise<WalletRecord> {
    return this.indy.getWalletRecord(this.walletHandle, type, id, options)
  }

  public signRequest(myDid: Did, request: LedgerRequest) {
    return this.indy.signRequest(this.walletHandle, myDid, request)
  }

  public async generateNonce() {
    return this.indy.generateNonce()
  }
}
