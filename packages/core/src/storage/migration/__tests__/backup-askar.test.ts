import type { FileSystem } from '../../FileSystem'
import type { StorageUpdateError } from '../error/StorageUpdateError'

import { readFileSync, unlinkSync } from 'fs'
import path from 'path'

import { askarModule } from '../../../../../askar/tests/helpers'
import { CredentialExchangeRecord, CredentialRepository } from '../../../../../didcomm/src/modules/credentials'
import { getAgentOptions, getAskarWalletConfig } from '../../../../tests/helpers'
import { Agent } from '../../../agent/Agent'
import { InjectionSymbols } from '../../../constants'
import { CredoError } from '../../../error'
import { JsonTransformer } from '../../../utils'
import { StorageUpdateService } from '../StorageUpdateService'
import { UpdateAssistant } from '../UpdateAssistant'

const agentOptions = getAgentOptions(
  'UpdateAssistant | Backup | Aries Askar',
  {},
  {
    walletConfig: getAskarWalletConfig('UpdateAssistant | Backup | Aries Askar', { inMemory: false }),
  },
  {
    askar: askarModule,
  }
)

const aliceCredentialRecordsString = readFileSync(
  path.join(__dirname, '__fixtures__/alice-4-credentials-0.1.json'),
  'utf8'
)

const backupDate = new Date('2022-03-22T22:50:20.522Z')
jest.useFakeTimers().setSystemTime(backupDate)
const backupIdentifier = backupDate.getTime()

describe('UpdateAssistant | Backup | Aries Askar', () => {
  let updateAssistant: UpdateAssistant
  let agent: Agent
  let backupPath: string

  beforeEach(async () => {
    agent = new Agent(agentOptions)
    const fileSystem = agent.dependencyManager.resolve<FileSystem>(InjectionSymbols.FileSystem)
    backupPath = `${fileSystem.dataPath}/migration/backup/${backupIdentifier}`

    // If tests fail it's possible the cleanup has been skipped. So remove before running tests
    const doesFileSystemExist = await fileSystem.exists(backupPath)
    if (doesFileSystemExist) {
      unlinkSync(backupPath)
    }
    const doesbackupFileSystemExist = await fileSystem.exists(`${backupPath}-error`)
    if (doesbackupFileSystemExist) {
      unlinkSync(`${backupPath}-error`)
    }

    updateAssistant = new UpdateAssistant(agent, {
      v0_1ToV0_2: {
        mediationRoleUpdateStrategy: 'allMediator',
      },
    })

    await updateAssistant.initialize()
  })

  afterEach(async () => {
    await agent.shutdown()
    await agent.wallet.delete()
  })

  it('should create a backup', async () => {
    const aliceCredentialRecordsJson = JSON.parse(aliceCredentialRecordsString)

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const aliceCredentialRecords = Object.values(aliceCredentialRecordsJson).map((data: any) => {
      const record = JsonTransformer.fromJSON(data.value, CredentialExchangeRecord)

      record.setTags(data.tags)
      return record
    })

    const credentialRepository = agent.dependencyManager.resolve(CredentialRepository)
    const storageUpdateService = agent.dependencyManager.resolve(StorageUpdateService)

    // Add 0.1 data and set version to 0.1
    for (const credentialRecord of aliceCredentialRecords) {
      await credentialRepository.save(agent.context, credentialRecord)
    }
    await storageUpdateService.setCurrentStorageVersion(agent.context, '0.1')

    // Expect an update is needed
    expect(await updateAssistant.isUpToDate()).toBe(false)

    const fileSystem = agent.dependencyManager.resolve<FileSystem>(InjectionSymbols.FileSystem)
    // Backup should not exist before update
    expect(await fileSystem.exists(backupPath)).toBe(false)

    const walletSpy = jest.spyOn(agent.wallet, 'export')

    // Create update
    await updateAssistant.update()

    // A wallet export should have been initiated
    expect(walletSpy).toHaveBeenCalledWith({ key: agent.wallet.walletConfig?.key, path: backupPath })

    // Backup should be cleaned after update
    expect(await fileSystem.exists(backupPath)).toBe(false)

    expect(
      (await credentialRepository.getAll(agent.context)).sort((a, b) => a.id.localeCompare(b.id))
    ).toMatchSnapshot()
  })

  it('should restore the backup if an error occurs during the update', async () => {
    const aliceCredentialRecordsJson = JSON.parse(aliceCredentialRecordsString)

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const aliceCredentialRecords = Object.values(aliceCredentialRecordsJson).map((data: any) => {
      const record = JsonTransformer.fromJSON(data.value, CredentialExchangeRecord)

      record.setTags(data.tags)
      return record
    })

    const credentialRepository = agent.dependencyManager.resolve(CredentialRepository)
    const storageUpdateService = agent.dependencyManager.resolve(StorageUpdateService)

    // Add 0.1 data and set version to 0.1
    for (const credentialRecord of aliceCredentialRecords) {
      await credentialRepository.save(agent.context, credentialRecord)
    }
    await storageUpdateService.setCurrentStorageVersion(agent.context, '0.1')

    // Expect an update is needed
    expect(await updateAssistant.isUpToDate()).toBe(false)
    jest.spyOn(updateAssistant, 'getNeededUpdates').mockResolvedValue([
      {
        fromVersion: '0.1',
        toVersion: '0.2',
        doUpdate: async () => {
          throw new CredoError("Uh oh I'm broken")
        },
      },
    ])

    const fileSystem = agent.dependencyManager.resolve<FileSystem>(InjectionSymbols.FileSystem)
    // Backup should not exist before update
    expect(await fileSystem.exists(backupPath)).toBe(false)

    let updateError: StorageUpdateError | undefined = undefined

    try {
      await updateAssistant.update()
    } catch (error) {
      updateError = error
    }

    expect(updateError?.cause?.message).toEqual("Uh oh I'm broken")

    // Only backup error should exist after update
    expect(await fileSystem.exists(backupPath)).toBe(false)
    expect(await fileSystem.exists(`${backupPath}-error`)).toBe(true)

    // Wallet should be same as when we started because of backup
    expect((await credentialRepository.getAll(agent.context)).sort((a, b) => a.id.localeCompare(b.id))).toEqual(
      aliceCredentialRecords.sort((a, b) => a.id.localeCompare(b.id))
    )
  })
})
