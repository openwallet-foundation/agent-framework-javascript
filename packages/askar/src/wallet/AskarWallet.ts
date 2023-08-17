import type { WalletConfig, WalletConfigRekey, WalletExportImportConfig } from '@aries-framework/core'

import {
  WalletExportPathExistsError,
  WalletInvalidKeyError,
  WalletDuplicateError,
  AriesFrameworkError,
  Logger,
  WalletError,
  InjectionSymbols,
  SigningProviderRegistry,
  FileSystem,
  WalletNotFoundError,
  KeyDerivationMethod,
} from '@aries-framework/core'
// eslint-disable-next-line import/order
import { Store } from '@hyperledger/aries-askar-shared'

import { inject, injectable } from 'tsyringe'

import { AskarErrorCode, isAskarError, keyDerivationMethodToStoreKeyMethod, uriFromWalletConfig } from '../utils'

import { AskarBaseWallet } from './AskarBaseWallet'
import { AskarProfileWallet } from './AskarProfileWallet'

/**
 * @todo: rename after 0.5.0, as we now have multiple types of AskarWallet
 */
@injectable()
export class AskarWallet extends AskarBaseWallet {
  private fileSystem: FileSystem

  private walletConfig?: WalletConfig
  private _store?: Store

  public constructor(
    @inject(InjectionSymbols.Logger) logger: Logger,
    @inject(InjectionSymbols.FileSystem) fileSystem: FileSystem,
    signingKeyProviderRegistry: SigningProviderRegistry
  ) {
    super(logger, signingKeyProviderRegistry)
    this.fileSystem = fileSystem
  }

  public get isProvisioned() {
    return this.walletConfig !== undefined
  }

  public get isInitialized() {
    return this._store !== undefined
  }

  public get store() {
    if (!this._store) {
      throw new AriesFrameworkError(
        'Wallet has not been initialized yet. Make sure to await agent.initialize() before using the agent.'
      )
    }

    return this._store
  }

  public get profile() {
    if (!this.walletConfig) {
      throw new WalletError('No profile configured.')
    }

    return this.walletConfig.id
  }

  /**
   * Dispose method is called when an agent context is disposed.
   */
  public async dispose() {
    if (this.isInitialized) {
      await this.close()
    }
  }

  /**
   * @throws {WalletDuplicateError} if the wallet already exists
   * @throws {WalletError} if another error occurs
   */
  public async create(walletConfig: WalletConfig): Promise<void> {
    await this.createAndOpen(walletConfig)
    await this.close()
  }

  /**
   * TODO: we can add this method, and add custom logic in the tenants module
   * or we can try to register the store on the agent context
   */
  public async getProfileWallet() {
    return new AskarProfileWallet(this.store, this.logger, this.signingKeyProviderRegistry)
  }

  /**
   * @throws {WalletDuplicateError} if the wallet already exists
   * @throws {WalletError} if another error occurs
   */
  public async createAndOpen(walletConfig: WalletConfig): Promise<void> {
    this.logger.debug(`Creating wallet '${walletConfig.id}`)

    const askarWalletConfig = await this.getAskarWalletConfig(walletConfig)

    // Check if database exists
    const { path: filePath } = uriFromWalletConfig(walletConfig, this.fileSystem.dataPath)
    if (filePath && (await this.fileSystem.exists(filePath))) {
      throw new WalletDuplicateError(`Wallet '${walletConfig.id}' already exists.`, {
        walletType: 'AskarWallet',
      })
    }
    try {
      this._store = await Store.provision({
        recreate: false,
        uri: askarWalletConfig.uri,
        profile: askarWalletConfig.profile,
        keyMethod: askarWalletConfig.keyMethod,
        passKey: askarWalletConfig.passKey,
      })
      this.walletConfig = walletConfig
      this._session = await this._store.openSession()
    } catch (error) {
      // FIXME: Askar should throw a Duplicate error code, but is currently returning Encryption
      // And if we provide the very same wallet key, it will open it without any error
      if (
        isAskarError(error) &&
        (error.code === AskarErrorCode.Encryption || error.code === AskarErrorCode.Duplicate)
      ) {
        const errorMessage = `Wallet '${walletConfig.id}' already exists`
        this.logger.debug(errorMessage)

        throw new WalletDuplicateError(errorMessage, {
          walletType: 'AskarWallet',
          cause: error,
        })
      }

      const errorMessage = `Error creating wallet '${walletConfig.id}'`
      this.logger.error(errorMessage, {
        error,
        errorMessage: error.message,
      })

      throw new WalletError(errorMessage, { cause: error })
    }

    this.logger.debug(`Successfully created wallet '${walletConfig.id}'`)
  }

  /**
   * @throws {WalletNotFoundError} if the wallet does not exist
   * @throws {WalletError} if another error occurs
   */
  public async open(walletConfig: WalletConfig): Promise<void> {
    await this._open(walletConfig)
  }

  /**
   * @throws {WalletNotFoundError} if the wallet does not exist
   * @throws {WalletError} if another error occurs
   */
  public async rotateKey(walletConfig: WalletConfigRekey): Promise<void> {
    if (!walletConfig.rekey) {
      throw new WalletError('Wallet rekey undefined!. Please specify the new wallet key')
    }
    await this._open(
      {
        id: walletConfig.id,
        key: walletConfig.key,
        keyDerivationMethod: walletConfig.keyDerivationMethod,
      },
      walletConfig.rekey,
      walletConfig.rekeyDerivationMethod
    )
  }

  /**
   * @throws {WalletNotFoundError} if the wallet does not exist
   * @throws {WalletError} if another error occurs
   */
  private async _open(
    walletConfig: WalletConfig,
    rekey?: string,
    rekeyDerivation?: KeyDerivationMethod
  ): Promise<void> {
    if (this._store) {
      throw new WalletError(
        'Wallet instance already opened. Close the currently opened wallet before re-opening the wallet'
      )
    }

    const askarWalletConfig = await this.getAskarWalletConfig(walletConfig)

    try {
      this._store = await Store.open({
        uri: askarWalletConfig.uri,
        keyMethod: askarWalletConfig.keyMethod,
        passKey: askarWalletConfig.passKey,
      })

      if (rekey) {
        await this._store.rekey({
          passKey: rekey,
          keyMethod: keyDerivationMethodToStoreKeyMethod(rekeyDerivation ?? KeyDerivationMethod.Argon2IMod),
        })
      }
      this._session = await this._store.openSession()

      this.walletConfig = walletConfig
    } catch (error) {
      if (
        isAskarError(error) &&
        (error.code === AskarErrorCode.NotFound ||
          (error.code === AskarErrorCode.Backend && walletConfig.storage?.inMemory))
      ) {
        const errorMessage = `Wallet '${walletConfig.id}' not found`
        this.logger.debug(errorMessage)

        throw new WalletNotFoundError(errorMessage, {
          walletType: 'AskarWallet',
          cause: error,
        })
      } else if (isAskarError(error) && error.code === AskarErrorCode.Encryption) {
        const errorMessage = `Incorrect key for wallet '${walletConfig.id}'`
        this.logger.debug(errorMessage)
        throw new WalletInvalidKeyError(errorMessage, {
          walletType: 'AskarWallet',
          cause: error,
        })
      }
      throw new WalletError(`Error opening wallet ${walletConfig.id}: ${error.message}`, { cause: error })
    }

    this.logger.debug(`Wallet '${walletConfig.id}' opened with handle '${this._store.handle.handle}'`)
  }

  /**
   * @throws {WalletNotFoundError} if the wallet does not exist
   * @throws {WalletError} if another error occurs
   */
  public async delete(): Promise<void> {
    if (!this.walletConfig) {
      throw new WalletError(
        'Can not delete wallet that does not have wallet config set. Make sure to call create wallet before deleting the wallet'
      )
    }

    this.logger.info(`Deleting wallet '${this.walletConfig.id}'`)
    if (this._store) {
      await this.close()
    }

    try {
      const { uri } = uriFromWalletConfig(this.walletConfig, this.fileSystem.dataPath)
      await Store.remove(uri)
    } catch (error) {
      const errorMessage = `Error deleting wallet '${this.walletConfig.id}': ${error.message}`
      this.logger.error(errorMessage, {
        error,
        errorMessage: error.message,
      })

      throw new WalletError(errorMessage, { cause: error })
    }
  }

  public async export(exportConfig: WalletExportImportConfig) {
    if (!this.walletConfig) {
      throw new WalletError(
        'Can not export wallet that does not have wallet config set. Make sure to open it before exporting'
      )
    }

    const { path: destinationPath, key: exportKey } = exportConfig

    const { path: sourcePath } = uriFromWalletConfig(this.walletConfig, this.fileSystem.dataPath)
    if (!sourcePath) {
      throw new WalletError('Export is only supported for SQLite backend')
    }

    try {
      // This method ensures that destination directory is created
      const exportedWalletConfig = await this.getAskarWalletConfig({
        ...this.walletConfig,
        storage: { type: 'sqlite', path: destinationPath },
      })

      // Close this wallet before copying
      await this.close()

      // Export path already exists
      if (await this.fileSystem.exists(destinationPath)) {
        throw new WalletExportPathExistsError(
          `Unable to create export, wallet export at path '${exportConfig.path}' already exists`
        )
      }

      // Copy wallet to the destination path
      await this.fileSystem.copyFile(sourcePath, destinationPath)

      // Open exported wallet and rotate its key to the one requested
      const exportedWalletStore = await Store.open({
        uri: exportedWalletConfig.uri,
        keyMethod: exportedWalletConfig.keyMethod,
        passKey: exportedWalletConfig.passKey,
      })
      await exportedWalletStore.rekey({ keyMethod: exportedWalletConfig.keyMethod, passKey: exportKey })

      await exportedWalletStore.close()

      await this._open(this.walletConfig)
    } catch (error) {
      if (error instanceof WalletExportPathExistsError) throw error

      const errorMessage = `Error exporting wallet '${this.walletConfig.id}': ${error.message}`
      this.logger.error(errorMessage, {
        error,
        errorMessage: error.message,
      })

      throw new WalletError(errorMessage, { cause: error })
    }
  }

  public async import(walletConfig: WalletConfig, importConfig: WalletExportImportConfig) {
    const { path: sourcePath, key: importKey } = importConfig
    const { path: destinationPath } = uriFromWalletConfig(walletConfig, this.fileSystem.dataPath)

    if (!destinationPath) {
      throw new WalletError('Import is only supported for SQLite backend')
    }

    try {
      // This method ensures that destination directory is created
      const importWalletConfig = await this.getAskarWalletConfig(walletConfig)

      // Copy wallet to the destination path
      await this.fileSystem.copyFile(sourcePath, destinationPath)

      // Open imported wallet and rotate its key to the one requested
      const importedWalletStore = await Store.open({
        uri: importWalletConfig.uri,
        keyMethod: importWalletConfig.keyMethod,
        passKey: importKey,
      })

      await importedWalletStore.rekey({ keyMethod: importWalletConfig.keyMethod, passKey: importWalletConfig.passKey })

      await importedWalletStore.close()
    } catch (error) {
      const errorMessage = `Error importing wallet '${walletConfig.id}': ${error.message}`
      this.logger.error(errorMessage, {
        error,
        errorMessage: error.message,
      })

      throw new WalletError(errorMessage, { cause: error })
    }
  }

  /**
   * @throws {WalletError} if the wallet is already closed or another error occurs
   */
  public async close(): Promise<void> {
    this.logger.debug(`Closing wallet ${this.walletConfig?.id}`)
    if (!this._store) {
      throw new WalletError('Wallet is in invalid state, you are trying to close wallet that has no handle.')
    }

    try {
      await this.session.close()
      await this.store.close()
      this._session = undefined
      this._store = undefined
    } catch (error) {
      const errorMessage = `Error closing wallet': ${error.message}`
      this.logger.error(errorMessage, {
        error,
        errorMessage: error.message,
      })

      throw new WalletError(errorMessage, { cause: error })
    }
  }

  private async getAskarWalletConfig(walletConfig: WalletConfig) {
    const { uri, path } = uriFromWalletConfig(walletConfig, this.fileSystem.dataPath)

    // Make sure path exists before creating the wallet
    if (path) {
      await this.fileSystem.createDirectory(path)
    }

    return {
      uri,
      profile: walletConfig.id,
      // FIXME: Default derivation method should be set somewhere in either agent config or some constants
      keyMethod: keyDerivationMethodToStoreKeyMethod(
        walletConfig.keyDerivationMethod ?? KeyDerivationMethod.Argon2IMod
      ),
      passKey: walletConfig.key,
    }
  }
}
