import type { AskarWalletPostgresStorageConfig } from '../src/wallet'
import type { Agent, InitConfig } from '@credo-ts/core'

import { ConnectionsModule, HandshakeProtocol, LogLevel, utils } from '@credo-ts/core'
import { ariesAskar } from '@hyperledger/aries-askar-nodejs'
import { registerAriesAskar } from '@hyperledger/aries-askar-shared'
import path from 'path'

import { waitForBasicMessage } from '../../core/tests/helpers'
import { TestLogger } from '../../core/tests/logger'
import { agentDependencies } from '../../node/src'
import { AskarModule } from '../src/AskarModule'
import { AskarModuleConfig } from '../src/AskarModuleConfig'
import { AskarWallet } from '../src/wallet'

export const askarModuleConfig = new AskarModuleConfig({ ariesAskar })
registerAriesAskar({ askar: askarModuleConfig.ariesAskar })

// When using the AskarWallet directly, the native dependency won't be loaded by default.
// So in tests depending on Askar, we import this wallet so we're sure the native dependency is loaded.
export const RegisteredAskarTestWallet = AskarWallet

export const genesisPath = process.env.GENESIS_TXN_PATH
  ? path.resolve(process.env.GENESIS_TXN_PATH)
  : path.join(__dirname, '../../../../network/genesis/local-genesis.txn')

export const publicDidSeed = process.env.TEST_AGENT_PUBLIC_DID_SEED ?? '000000000000000000000000Trustee9'

export function getPostgresAgentOptions(
  name: string,
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
      askar: new AskarModule(askarModuleConfig),
      connections: new ConnectionsModule({
        autoAcceptConnections: true,
      }),
    },
  } as const
}

export function getSqliteAgentOptions(name: string, extraConfig: Partial<InitConfig> = {}, inMemory?: boolean) {
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
  const senderReceiverOutOfBandRecord = await senderAgent.oob.createInvitation({
    handshakeProtocols: [HandshakeProtocol.Connections],
  })

  const { connectionRecord: bobConnectionAtReceiversender } = await receiverAgent.oob.receiveInvitation(
    senderReceiverOutOfBandRecord.outOfBandInvitation
  )
  if (!bobConnectionAtReceiversender) throw new Error('Connection not created')

  await receiverAgent.connections.returnWhenIsConnected(bobConnectionAtReceiversender.id)

  const [senderConnectionAtReceiver] = await senderAgent.connections.findAllByOutOfBandId(
    senderReceiverOutOfBandRecord.id
  )
  const senderConnection = await senderAgent.connections.returnWhenIsConnected(senderConnectionAtReceiver.id)

  const message = 'hello, world'
  await senderAgent.basicMessages.sendMessage(senderConnection.id, message)

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
