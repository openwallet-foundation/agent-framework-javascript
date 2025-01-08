import { DependencyManager, InjectionSymbols, Agent, UpdateAssistant, utils } from '@credo-ts/core'
import { MediatorRoutingRecord } from '@credo-ts/didcomm'
import { agentDependencies } from '@credo-ts/node'
import { readFileSync } from 'fs'
import path from 'path'

import { InMemoryStorageService } from '../../../../../tests/InMemoryStorageService'
import { RegisteredAskarTestWallet } from '../../../../askar/tests/helpers'
import { TenantsModule } from '../../TenantsModule'

// Backup date / time is the unique identifier for a backup, needs to be unique for every test
const backupDate = new Date('2023-11-23T22:50:20.522Z')
jest.useFakeTimers().setSystemTime(backupDate)

describe('UpdateAssistant | Tenants | v0.4 - v0.5', () => {
  it(`should correctly update the tenant records`, async () => {
    // We need to mock the uuid generation to make sure we generate consistent uuids for the new records created.
    let uuidCounter = 1
    const uuidSpy = jest.spyOn(utils, 'uuid').mockImplementation(() => `${uuidCounter++}-4e4f-41d9-94c4-f49351b811f1`)

    const tenantRecordsString = readFileSync(path.join(__dirname, '__fixtures__/tenants-no-label-tag-0.4.json'), 'utf8')

    const dependencyManager = new DependencyManager()
    const storageService = new InMemoryStorageService()
    dependencyManager.registerInstance(InjectionSymbols.StorageService, storageService)
    // If we register the AskarModule it will register the storage service, but we use in memory storage here
    dependencyManager.registerContextScoped(InjectionSymbols.Wallet, RegisteredAskarTestWallet)

    const agent = new Agent(
      {
        config: {
          label: 'Test Agent',
          walletConfig: {
            id: `Wallet: 0.5 Update Tenants`,
            key: `Key: 0.5 Update Tenants`,
          },
        },
        dependencies: agentDependencies,
        modules: {
          // We need to include the TenantsModule to run the updates
          tenants: new TenantsModule(),
        },
      },
      dependencyManager
    )

    const updateAssistant = new UpdateAssistant(agent, {
      v0_1ToV0_2: {
        mediationRoleUpdateStrategy: 'doNotChange',
      },
    })

    await updateAssistant.initialize()

    // Set storage after initialization. This mimics as if this wallet
    // is opened as an existing wallet instead of a new wallet
    storageService.contextCorrelationIdToRecords = {
      default: {
        records: JSON.parse(tenantRecordsString),
        creationDate: new Date(),
      },
    }

    expect(await updateAssistant.isUpToDate('0.5')).toBe(false)
    expect(await updateAssistant.getNeededUpdates('0.5')).toEqual([
      {
        fromVersion: '0.4',
        toVersion: '0.5',
        doUpdate: expect.any(Function),
      },
    ])

    await updateAssistant.update({ updateToVersion: '0.5' })

    expect(await updateAssistant.isUpToDate('0.5')).toBe(true)
    expect(await updateAssistant.getNeededUpdates('0.5')).toEqual([])

    await storageService.deleteById(agent.context, MediatorRoutingRecord, 'MEDIATOR_ROUTING_RECORD')
    expect(storageService.contextCorrelationIdToRecords[agent.context.contextCorrelationId].records).toMatchSnapshot()

    await agent.shutdown()
    await agent.wallet.delete()

    uuidSpy.mockReset()
  })
})
