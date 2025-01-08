import type { DidCommModuleConfig } from '../..//didcomm'
import type { AskarWalletPostgresStorageConfig } from '../src/wallet'
import type { Agent, InitConfig } from '@credo-ts/core'

import { LogLevel, utils } from '@credo-ts/core'
import { ariesAskar } from '@hyperledger/aries-askar-nodejs'
import { registerAriesAskar } from '@hyperledger/aries-askar-shared'
import path from 'path'

import { waitForBasicMessage } from '../../core/tests/helpers'
import { TestLogger } from '../../core/tests/logger'
import { ConnectionsModule, HandshakeProtocol } from '../../didcomm'
import { getDefaultDidcommModules } from '../../didcomm/src/util/modules'
import { agentDependencies } from '../../node/src'
import { AskarModule } from '../src/AskarModule'
import { AskarModuleConfig } from '../src/AskarModuleConfig'
import { AskarWallet } from '../src/wallet'

export const askarModuleConfig = new AskarModuleConfig({ ariesAskar })
registerAriesAskar({ askar: askarModuleConfig.ariesAskar })
export const askarModule = new AskarModule(askarModuleConfig)
export { ariesAskar }

// When using the AskarWallet directly, the native dependency won't be loaded by default.
// So in tests depending on Askar, we import this wallet so we're sure the native dependency is loaded.
export const RegisteredAskarTestWallet = AskarWallet

export const genesisPath = process.env.GENESIS_TXN_PATH
  ? path.resolve(process.env.GENESIS_TXN_PATH)
  : path.join(__dirname, '../../../../network/genesis/local-genesis.txn')

export const publicDidSeed = process.env.TEST_AGENT_PUBLIC_DID_SEED ?? '000000000000000000000000Trustee9'

export const askarPostgresStorageConfig: AskarWalletPostgresStorageConfig = {
  type: 'postgres',
  config: {
    host: 'localhost:5432',
  },
  credentials: {
    account: 'postgres',
    password: 'postgres',
  },
}

export function getAskarPostgresAgentOptions(
  name: string,
  didcommConfig: Partial<DidCommModuleConfig> = {},
  storageConfig: AskarWalletPostgresStorageConfig,
  extraConfig: Partial<InitConfig> = {}
) {
  const random = utils.uuid().slice(0, 4)
  const config: InitConfig = {
    label: `PostgresAgent: ${name} - ${random}`,
    walletConfig: {
      id: `PostgresWallet${name}${random}`,
      key: `Key${name}`,
      storage: storageConfig,
    },
    autoUpdateStorageOnStartup: false,
    logger: new TestLogger(LogLevel.off, name),
    ...extraConfig,
  }
  return {
    config,
    dependencies: agentDependencies,
    modules: {
      ...getDefaultDidcommModules(didcommConfig),
      askar: new AskarModule(askarModuleConfig),
      connections: new ConnectionsModule({
        autoAcceptConnections: true,
      }),
    },
  } as const
}

export function getAskarSqliteAgentOptions(
  name: string,
  didcommConfig: Partial<DidCommModuleConfig> = {},
  extraConfig: Partial<InitConfig> = {},
  inMemory?: boolean
) {
  const random = utils.uuid().slice(0, 4)
  const config: InitConfig = {
    label: `SQLiteAgent: ${name} - ${random}`,
    walletConfig: {
      id: `SQLiteWallet${name} - ${random}`,
      key: `Key${name}`,
      storage: { type: 'sqlite', inMemory },
    },
    autoUpdateStorageOnStartup: false,
    logger: new TestLogger(LogLevel.off, name),
    ...extraConfig,
  }
  return {
    config,
    dependencies: agentDependencies,
    modules: {
      ...getDefaultDidcommModules(didcommConfig),
      askar: new AskarModule(askarModuleConfig),
      connections: new ConnectionsModule({
        autoAcceptConnections: true,
      }),
    },
  } as const
}

/**
 * Basic E2E test: connect two agents, send a basic message and verify it they can be re initialized
 * @param senderAgent
 * @param receiverAgent
 */
export async function e2eTest(senderAgent: Agent, receiverAgent: Agent) {
  const senderReceiverOutOfBandRecord = await senderAgent.modules.oob.createInvitation({
    handshakeProtocols: [HandshakeProtocol.Connections],
  })

  const { connectionRecord: bobConnectionAtReceiversender } = await receiverAgent.modules.oob.receiveInvitation(
    senderReceiverOutOfBandRecord.outOfBandInvitation
  )
  if (!bobConnectionAtReceiversender) throw new Error('Connection not created')

  await receiverAgent.modules.connections.returnWhenIsConnected(bobConnectionAtReceiversender.id)

  const [senderConnectionAtReceiver] = await senderAgent.modules.connections.findAllByOutOfBandId(
    senderReceiverOutOfBandRecord.id
  )
  const senderConnection = await senderAgent.modules.connections.returnWhenIsConnected(senderConnectionAtReceiver.id)

  const message = 'hello, world'
  await senderAgent.modules.basicMessages.sendMessage(senderConnection.id, message)

  const basicMessage = await waitForBasicMessage(receiverAgent, {
    content: message,
  })

  expect(basicMessage.content).toBe(message)

  expect(senderAgent.isInitialized).toBe(true)
  await senderAgent.shutdown()
  expect(senderAgent.isInitialized).toBe(false)
  await senderAgent.initialize()
  expect(senderAgent.isInitialized).toBe(true)
}
