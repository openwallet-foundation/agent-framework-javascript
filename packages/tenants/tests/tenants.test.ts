import type { InitConfig } from '@credo-ts/core'

import { ConnectionsModule, OutOfBandRecord, Agent, CacheModule, InMemoryLruCache } from '@credo-ts/core'
import { agentDependencies } from '@credo-ts/node'

import { InMemoryWalletModule } from '../../../tests/InMemoryWalletModule'
import { SubjectInboundTransport } from '../../../tests/transport/SubjectInboundTransport'
import { SubjectOutboundTransport } from '../../../tests/transport/SubjectOutboundTransport'
import { uuid } from '../../core/src/utils/uuid'
import { testLogger } from '../../core/tests'
import { TenantsModule } from '../src/TenantsModule'

const agent1Config: InitConfig = {
  label: 'Tenant Agent 1',
  walletConfig: {
    id: `tenants e2e agent 1 - ${uuid().slice(0, 4)}`,
    key: `tenants e2e agent 1`,
  },
  logger: testLogger,
  endpoints: ['rxjs:tenant-agent1'],
}

const agent2Config: InitConfig = {
  label: 'Tenant Agent 2',
  walletConfig: {
    id: `tenants e2e agent 2 - ${uuid().slice(0, 4)}`,
    key: `tenants e2e agent 2`,
  },
  logger: testLogger,
  endpoints: ['rxjs:tenant-agent2'],
}

// Create multi-tenant agents
const agent1 = new Agent({
  config: agent1Config,
  modules: {
    tenants: new TenantsModule(),
    inMemory: new InMemoryWalletModule(),
    connections: new ConnectionsModule({
      autoAcceptConnections: true,
    }),
    cache: new CacheModule({
      cache: new InMemoryLruCache({ limit: 500 }),
    }),
  },
  dependencies: agentDependencies,
})

const agent2 = new Agent({
  config: agent2Config,
  modules: {
    tenants: new TenantsModule(),
    inMemory: new InMemoryWalletModule(),
    connections: new ConnectionsModule({
      autoAcceptConnections: true,
    }),
    cache: new CacheModule({
      cache: new InMemoryLruCache({ limit: 500 }),
    }),
  },
  dependencies: agentDependencies,
})

// Register inbound and outbound transports (so we can communicate with ourselves)
const agent1InboundTransport = new SubjectInboundTransport()
const agent2InboundTransport = new SubjectInboundTransport()

agent1.registerInboundTransport(agent1InboundTransport)
agent2.registerInboundTransport(agent2InboundTransport)

agent1.registerOutboundTransport(
  new SubjectOutboundTransport({
    'rxjs:tenant-agent1': agent1InboundTransport.ourSubject,
    'rxjs:tenant-agent2': agent2InboundTransport.ourSubject,
  })
)
agent2.registerOutboundTransport(
  new SubjectOutboundTransport({
    'rxjs:tenant-agent1': agent1InboundTransport.ourSubject,
    'rxjs:tenant-agent2': agent2InboundTransport.ourSubject,
  })
)

describe('Tenants E2E', () => {
  beforeAll(async () => {
    await agent1.initialize()
    await agent2.initialize()
  })

  afterAll(async () => {
    await agent1.wallet.delete()
    await agent1.shutdown()
    await agent2.wallet.delete()
    await agent2.shutdown()
  })

  test('create get, find by label, and delete a tenant', async () => {
    // Create tenant
    let tenantRecord1 = await agent1.modules.tenants.createTenant({
      config: {
        label: 'Tenant 1',
      },
    })

    // Retrieve tenant record from storage
    tenantRecord1 = await agent1.modules.tenants.getTenantById(tenantRecord1.id)

    const tenantRecordsByLabel = await agent1.modules.tenants.findTenantsByLabel('Tenant 1')
    expect(tenantRecordsByLabel.length).toBe(1)
    expect(tenantRecordsByLabel[0].id).toBe(tenantRecord1.id)

    // Get tenant agent
    const tenantAgent = await agent1.modules.tenants.getTenantAgent({
      tenantId: tenantRecord1.id,
    })
    await tenantAgent.endSession()

    // Delete tenant agent
    await agent1.modules.tenants.deleteTenantById(tenantRecord1.id)

    // Can not get tenant agent again
    await expect(agent1.modules.tenants.getTenantAgent({ tenantId: tenantRecord1.id })).rejects.toThrow(
      `TenantRecord: record with id ${tenantRecord1.id} not found.`
    )
  })

  test('withTenantAgent returns value from callback', async () => {
    const tenantRecord = await agent1.modules.tenants.createTenant({
      config: {
        label: 'Tenant 2',
      },
    })

    const result = await agent1.modules.tenants.withTenantAgent({ tenantId: tenantRecord.id }, async () => {
      return {
        hello: 'world',
      }
    })

    expect(result).toEqual({ hello: 'world' })
  })

  test('create a connection between two tenants within the same agent', async () => {
    // Create tenants
    const tenantRecord1 = await agent1.modules.tenants.createTenant({
      config: {
        label: 'Tenant 1',
      },
    })
    const tenantRecord2 = await agent1.modules.tenants.createTenant({
      config: {
        label: 'Tenant 2',
      },
    })

    const tenantAgent1 = await agent1.modules.tenants.getTenantAgent({
      tenantId: tenantRecord1.id,
    })

    const tenantAgent2 = await agent1.modules.tenants.getTenantAgent({
      tenantId: tenantRecord2.id,
    })

    // Create and receive oob invitation in scope of tenants
    const outOfBandRecord = await tenantAgent1.oob.createInvitation()
    const { connectionRecord: tenant2ConnectionRecord } = await tenantAgent2.oob.receiveInvitation(
      outOfBandRecord.outOfBandInvitation
    )

    // Retrieve all oob records for the base and tenant agent, only the
    // tenant agent should have a record.
    const baseAgentOutOfBandRecords = await agent1.oob.getAll()
    const tenantAgent1OutOfBandRecords = await tenantAgent1.oob.getAll()
    const tenantAgent2OutOfBandRecords = await tenantAgent2.oob.getAll()

    expect(baseAgentOutOfBandRecords.length).toBe(0)
    expect(tenantAgent1OutOfBandRecords.length).toBe(1)
    expect(tenantAgent2OutOfBandRecords.length).toBe(1)

    if (!tenant2ConnectionRecord) throw new Error('Receive invitation did not return connection record')
    await tenantAgent2.connections.returnWhenIsConnected(tenant2ConnectionRecord.id)

    // Find the connection record for the created oob invitation
    const [connectionRecord] = await tenantAgent1.connections.findAllByOutOfBandId(outOfBandRecord.id)
    await tenantAgent1.connections.returnWhenIsConnected(connectionRecord.id)

    await tenantAgent1.endSession()
    await tenantAgent2.endSession()

    // Delete tenants (will also delete wallets)
    await agent1.modules.tenants.deleteTenantById(tenantAgent1.context.contextCorrelationId)
    await agent1.modules.tenants.deleteTenantById(tenantAgent2.context.contextCorrelationId)
  })

  test('create a connection between two tenants within different agents', async () => {
    // Create tenants
    const tenantRecord1 = await agent1.modules.tenants.createTenant({
      config: {
        label: 'Agent 1 Tenant 1',
      },
    })
    const tenantAgent1 = await agent1.modules.tenants.getTenantAgent({
      tenantId: tenantRecord1.id,
    })

    const tenantRecord2 = await agent2.modules.tenants.createTenant({
      config: {
        label: 'Agent 2 Tenant 1',
      },
    })
    const tenantAgent2 = await agent2.modules.tenants.getTenantAgent({
      tenantId: tenantRecord2.id,
    })

    // Create and receive oob invitation in scope of tenants
    const outOfBandRecord = await tenantAgent1.oob.createInvitation()
    const { connectionRecord: tenant2ConnectionRecord } = await tenantAgent2.oob.receiveInvitation(
      outOfBandRecord.outOfBandInvitation
    )

    if (!tenant2ConnectionRecord) throw new Error('Receive invitation did not return connection record')
    await tenantAgent2.connections.returnWhenIsConnected(tenant2ConnectionRecord.id)

    // Find the connection record for the created oob invitation
    const [connectionRecord] = await tenantAgent1.connections.findAllByOutOfBandId(outOfBandRecord.id)
    await tenantAgent1.connections.returnWhenIsConnected(connectionRecord.id)

    await tenantAgent1.endSession()
    await tenantAgent2.endSession()

    // Delete tenants (will also delete wallets)
    await agent1.modules.tenants.deleteTenantById(tenantRecord1.id)
    await agent2.modules.tenants.deleteTenantById(tenantRecord2.id)
  })

  test('perform actions within the callback of withTenantAgent', async () => {
    const tenantRecord = await agent1.modules.tenants.createTenant({
      config: {
        label: 'Agent 1 Tenant 1',
      },
    })

    await agent1.modules.tenants.withTenantAgent({ tenantId: tenantRecord.id }, async (tenantAgent) => {
      const outOfBandRecord = await tenantAgent.oob.createInvitation()

      expect(outOfBandRecord).toBeInstanceOf(OutOfBandRecord)
      expect(tenantAgent.context.contextCorrelationId).toBe(tenantRecord.id)
      expect(tenantAgent.config.label).toBe('Agent 1 Tenant 1')
    })

    await agent1.modules.tenants.deleteTenantById(tenantRecord.id)
  })

  test('fallback middleware for the tenant manager propagated to the tenant', async () => {
    expect(agent1.dependencyManager.fallbackMessageHandler).toBeUndefined()

    const fallbackFunction = async () => {
      // empty
    }

    agent1.dependencyManager.setFallbackMessageHandler(fallbackFunction)

    expect(agent1.dependencyManager.fallbackMessageHandler).toBe(fallbackFunction)

    const tenantRecord = await agent1.modules.tenants.createTenant({
      config: {
        label: 'Agent 1 Tenant 1',
      },
    })

    const tenantAgent = await agent1.modules.tenants.getTenantAgent({
      tenantId: tenantRecord.id,
    })

    expect(tenantAgent.dependencyManager.fallbackMessageHandler).toBe(fallbackFunction)

    await tenantAgent.endSession()
  })
})
