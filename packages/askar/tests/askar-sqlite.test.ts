/* eslint-disable @typescript-eslint/no-non-null-assertion */
import {
  Agent,
  KeyDerivationMethod,
  TypedArrayEncoder,
  utils,
  WalletDuplicateError,
  WalletInvalidKeyError,
  WalletNotFoundError,
} from '@credo-ts/core'
import { Store } from '@hyperledger/aries-askar-shared'
import { tmpdir } from 'os'
import path from 'path'

import { BasicMessageRecord, BasicMessageRepository, BasicMessageRole } from '../..//didcomm'

import { getAskarSqliteAgentOptions } from './helpers'

const aliceAgentOptions = getAskarSqliteAgentOptions('AgentsAlice')
const bobAgentOptions = getAskarSqliteAgentOptions('AgentsBob')

describe('Askar SQLite agents', () => {
  let aliceAgent: Agent
  let bobAgent: Agent

  beforeEach(async () => {
    aliceAgent = new Agent(aliceAgentOptions)
    bobAgent = new Agent(bobAgentOptions)
  })

  afterEach(async () => {
    await aliceAgent.shutdown()
    await bobAgent.shutdown()

    if (aliceAgent.wallet.isProvisioned) {
      await aliceAgent.wallet.delete()
    }
    if (bobAgent.wallet.isProvisioned) {
      await bobAgent.wallet.delete()
    }
  })

  test('open, create and open wallet with different wallet key that it is in agent config', async () => {
    const walletConfig = {
      id: 'mywallet',
      key: 'mysecretwalletkey-0',
    }

    try {
      await aliceAgent.wallet.open(walletConfig)
    } catch (error) {
      if (error instanceof WalletNotFoundError) {
        await aliceAgent.wallet.create(walletConfig)
        await aliceAgent.wallet.open(walletConfig)
      }
    }

    await aliceAgent.initialize()

    expect(aliceAgent.isInitialized).toBe(true)
  })

  test('when opening non-existing wallet throw WalletNotFoundError', async () => {
    const walletConfig = {
      id: 'mywallet',
      key: 'mysecretwalletkey-1',
    }

    await expect(aliceAgent.wallet.open(walletConfig)).rejects.toThrowError(WalletNotFoundError)
  })

  test('when create wallet and shutdown, wallet is closed', async () => {
    const walletConfig = {
      id: 'mywallet',
      key: 'mysecretwalletkey-2',
    }

    await aliceAgent.wallet.create(walletConfig)

    await aliceAgent.shutdown()

    await expect(aliceAgent.wallet.open(walletConfig)).resolves.toBeUndefined()
  })

  test('create wallet with custom key derivation method', async () => {
    const walletConfig = {
      id: 'mywallet',
      key: Store.generateRawKey(TypedArrayEncoder.fromString('mysecretwalletkey')),
      keyDerivationMethod: KeyDerivationMethod.Raw,
    }

    await aliceAgent.wallet.createAndOpen(walletConfig)

    expect(aliceAgent.wallet.isInitialized).toBe(true)
  })

  test('when exporting and importing a wallet, content is copied', async () => {
    await bobAgent.initialize()
    const bobBasicMessageRepository = bobAgent.dependencyManager.resolve(BasicMessageRepository)

    const basicMessageRecord = new BasicMessageRecord({
      id: 'some-id',
      connectionId: 'connId',
      content: 'hello',
      role: BasicMessageRole.Receiver,
      sentTime: 'sentIt',
    })

    // Save in wallet
    await bobBasicMessageRepository.save(bobAgent.context, basicMessageRecord)

    if (!bobAgent.config.walletConfig) {
      throw new Error('No wallet config on bobAgent')
    }

    const backupKey = 'someBackupKey'
    const backupWalletName = `backup-${utils.uuid()}`
    const backupPath = path.join(tmpdir(), backupWalletName)

    // Create backup and delete wallet
    await bobAgent.wallet.export({ path: backupPath, key: backupKey })
    await bobAgent.wallet.delete()

    // Initialize the wallet again and assert record does not exist
    // This should create a new wallet
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    await bobAgent.wallet.initialize(bobAgent.config.walletConfig!)
    expect(await bobBasicMessageRepository.findById(bobAgent.context, basicMessageRecord.id)).toBeNull()
    await bobAgent.wallet.delete()

    // Import backup with SAME wallet id and initialize
    await bobAgent.wallet.import(bobAgent.config.walletConfig, { path: backupPath, key: backupKey })
    await bobAgent.wallet.initialize(bobAgent.config.walletConfig)

    // Expect same basic message record to exist in new wallet
    expect(await bobBasicMessageRepository.getById(bobAgent.context, basicMessageRecord.id)).toMatchObject({
      id: basicMessageRecord.id,
      connectionId: basicMessageRecord.connectionId,
      content: basicMessageRecord.content,
      createdAt: basicMessageRecord.createdAt,
      updatedAt: basicMessageRecord.updatedAt,
      type: basicMessageRecord.type,
    })
  })

  test('throws error when exporting a wallet and importing it with a different walletConfig.id', async () => {
    await bobAgent.initialize()

    if (!bobAgent.config.walletConfig) {
      throw new Error('No wallet config on bobAgent')
    }

    const backupKey = 'someBackupKey'
    const backupWalletName = `backup-${utils.uuid()}`
    const backupPath = path.join(tmpdir(), backupWalletName)

    // Create backup and delete wallet
    await bobAgent.wallet.export({ path: backupPath, key: backupKey })
    await bobAgent.wallet.delete()

    // Import backup with different wallet id and initialize
    await expect(
      bobAgent.wallet.import({ id: backupWalletName, key: backupWalletName }, { path: backupPath, key: backupKey })
    ).rejects.toThrow(
      `Error importing wallet '${backupWalletName}': Trying to import wallet with walletConfig.id ${backupWalletName}, however the wallet contains a default profile with id ${bobAgent.config.walletConfig.id}. The walletConfig.id MUST match with the default profile. In the future this behavior may be changed. See https://github.com/hyperledger/aries-askar/issues/221 for more information.`
    )
  })

  test('throws error when attempting to export and import to existing paths', async () => {
    await bobAgent.initialize()

    if (!bobAgent.config.walletConfig) {
      throw new Error('No wallet config on bobAgent')
    }

    const backupKey = 'someBackupKey'
    const backupWalletName = `backup-${utils.uuid()}`
    const backupPath = path.join(tmpdir(), backupWalletName)

    // Create backup and try to export it again to the same path
    await bobAgent.wallet.export({ path: backupPath, key: backupKey })
    await expect(bobAgent.wallet.export({ path: backupPath, key: backupKey })).rejects.toThrow(
      /Unable to create export/
    )

    await bobAgent.wallet.delete()

    // Import backup with different wallet id and initialize
    await bobAgent.wallet.import(bobAgent.config.walletConfig, { path: backupPath, key: backupKey })
    await bobAgent.wallet.initialize(bobAgent.config.walletConfig)
    await bobAgent.wallet.close()

    // Try to import again an existing wallet
    await expect(
      bobAgent.wallet.import(bobAgent.config.walletConfig, { path: backupPath, key: backupKey })
    ).rejects.toThrow(/Unable to import wallet/)
  })

  test('throws error when attempting to import using wrong key', async () => {
    await bobAgent.initialize()

    if (!bobAgent.config.walletConfig) {
      throw new Error('No wallet config on bobAgent')
    }

    const backupKey = 'someBackupKey'
    const wrongBackupKey = 'wrongBackupKey'
    const backupWalletName = `backup-${utils.uuid()}`
    const backupPath = path.join(tmpdir(), backupWalletName)

    // Create backup and try to export it again to the same path
    await bobAgent.wallet.export({ path: backupPath, key: backupKey })
    await bobAgent.wallet.delete()

    // Try to import backup with wrong key
    await expect(
      bobAgent.wallet.import(bobAgent.config.walletConfig, { path: backupPath, key: wrongBackupKey })
    ).rejects.toThrow()

    // Try to import again using the correct key
    await bobAgent.wallet.import(bobAgent.config.walletConfig, { path: backupPath, key: backupKey })
    await bobAgent.wallet.initialize(bobAgent.config.walletConfig)
    await bobAgent.wallet.close()
  })

  test('changing wallet key', async () => {
    const walletConfig = {
      id: 'mywallet',
      key: 'mysecretwalletkey',
    }

    await aliceAgent.wallet.createAndOpen(walletConfig)
    await aliceAgent.initialize()

    //Close agent
    const walletConfigRekey = {
      id: 'mywallet',
      key: 'mysecretwalletkey',
      rekey: '123',
    }

    await aliceAgent.shutdown()
    await aliceAgent.wallet.rotateKey(walletConfigRekey)
    await aliceAgent.initialize()

    expect(aliceAgent.isInitialized).toBe(true)
  })

  test('when creating already existing wallet throw WalletDuplicateError', async () => {
    const walletConfig = {
      id: 'mywallet',
      key: 'mysecretwalletkey-2',
    }

    await aliceAgent.wallet.create(walletConfig)
    await expect(aliceAgent.wallet.create(walletConfig)).rejects.toThrowError(WalletDuplicateError)
  })

  test('when opening wallet with invalid key throw WalletInvalidKeyError', async () => {
    const walletConfig = {
      id: 'mywallet',
      key: 'mysecretwalletkey-3',
    }

    await aliceAgent.wallet.create(walletConfig)
    await expect(aliceAgent.wallet.open({ ...walletConfig, key: 'abcd' })).rejects.toThrowError(WalletInvalidKeyError)
  })
})
