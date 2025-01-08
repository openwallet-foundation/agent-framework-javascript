import type { InitConfig } from '@credo-ts/core'

import { Agent } from '@credo-ts/core'
import { ConnectionsModule } from '@credo-ts/didcomm'
import { agentDependencies } from '@credo-ts/node'

import { InMemoryWalletModule } from '../../../tests/InMemoryWalletModule'
import { uuid } from '../../core/src/utils/uuid'
import { testLogger } from '../../core/tests'
import { getDefaultDidcommModules } from '../../didcomm/src/util/modules'

import { TenantsModule } from '@credo-ts/tenants'

const agentConfig: InitConfig = {
  label: 'Tenant Agent 1',
  walletConfig: {
    id: `tenant sessions e2e agent 1 - ${uuid().slice(0, 4)}`,
    key: `tenant sessions e2e agent 1`,
  },
  logger: testLogger,
}

// Create multi-tenant agent
const agent = new Agent({
  config: agentConfig,
  dependencies: agentDependencies,
  modules: {
    ...getDefaultDidcommModules({ endpoints: ['rxjs:tenant-agent1'] }),
    tenants: new TenantsModule({ sessionAcquireTimeout: 10000 }),
    inMemory: new InMemoryWalletModule(),
    connections: new ConnectionsModule({
      autoAcceptConnections: true,
    }),
  },
})

describe('Tenants Sessions E2E', () => {
  beforeAll(async () => {
    await agent.initialize()
  })

  afterAll(async () => {
    await agent.wallet.delete()
    await agent.shutdown()
  })

  test('create 100 sessions in parallel for the same tenant and close them', async () => {
    const numberOfSessions = 100

    const tenantRecord = await agent.modules.tenants.createTenant({
      config: {
        label: 'Agent 1 Tenant 1',
      },
    })

    const tenantAgentPromises = []

    for (let session = 0; session < numberOfSessions; session++) {
      tenantAgentPromises.push(agent.modules.tenants.getTenantAgent({ tenantId: tenantRecord.id }))
    }

    const tenantAgents = await Promise.all(tenantAgentPromises)

    await Promise.all(tenantAgents.map((tenantAgent) => tenantAgent.endSession()))
  })

  test('create 5 sessions each for 20 tenants in parallel and close them', async () => {
    const numberOfTenants = 20
    const numberOfSessions = 5

    const tenantRecordPromises = []
    for (let tenantNo = 0; tenantNo < numberOfTenants; tenantNo++) {
      const tenantRecordPromise = agent.modules.tenants.createTenant({
        config: {
          label: 'Agent 1 Tenant 1',
        },
      })

      tenantRecordPromises.push(tenantRecordPromise)
    }

    const tenantRecords = await Promise.all(tenantRecordPromises)
    const tenantAgentPromises = []
    for (const tenantRecord of tenantRecords) {
      for (let session = 0; session < numberOfSessions; session++) {
        tenantAgentPromises.push(agent.modules.tenants.getTenantAgent({ tenantId: tenantRecord.id }))
      }
    }

    const tenantAgents = await Promise.all(tenantAgentPromises)

    await Promise.all(tenantAgents.map((tenantAgent) => tenantAgent.endSession()))
  })
})
