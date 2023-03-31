import type { AgentContext } from '../../../agent'

import { IndySdkModule } from '../../../../../indy-sdk/src'
import { getAgentOptions, indySdk } from '../../../../tests'
import { Agent } from '../../../agent/Agent'
import { AgentConfig } from '../../../agent/AgentConfig'
import { JsonTransformer } from '../../../utils'
import { W3cCredentialService } from '../W3cCredentialService'
import { W3cVcModule } from '../W3cVcModule'
import { W3cVerifiableCredential } from '../models'
import { W3cCredentialRepository } from '../repository'

import { customDocumentLoader } from './documentLoader'
import { Ed25519Signature2018Fixtures } from './fixtures'

const modules = {
  w3cVc: new W3cVcModule({
    documentLoader: customDocumentLoader,
  }),
  indySdk: new IndySdkModule({
    indySdk,
  }),
}

const agentOptions = getAgentOptions<typeof modules>('W3cVcApi', {}, modules)

const agent = new Agent(agentOptions)

let w3cCredentialRepository: W3cCredentialRepository
let w3cCredentialService: W3cCredentialService

const testCredential = JsonTransformer.fromJSON(
  Ed25519Signature2018Fixtures.TEST_LD_DOCUMENT_SIGNED,
  W3cVerifiableCredential
)

describe('W3cVcApi', () => {
  beforeAll(() => {
    w3cCredentialRepository = agent.dependencyManager.resolve(W3cCredentialRepository)
    w3cCredentialService = agent.dependencyManager.resolve(W3cCredentialService)
  })

  beforeEach(async () => {
    await agent.initialize()
  })

  afterEach(async () => {
    await agent.shutdown()
    await agent.wallet.delete()
  })

  it('Should successfully store a credential', async () => {
    const repoSpy = jest.spyOn(w3cCredentialRepository, 'save')
    const serviceSpy = jest.spyOn(w3cCredentialService, 'storeCredential')

    await agent.modules.w3cVc.storeCredential({
      credential: testCredential,
    })

    expect(repoSpy).toHaveBeenCalledTimes(1)
    expect(serviceSpy).toHaveBeenCalledTimes(1)
  })

  it('Should successfully retrieve a credential by id', async () => {
    const repoSpy = jest.spyOn(w3cCredentialRepository, 'getById')
    const serviceSpy = jest.spyOn(w3cCredentialService, 'getCredentialRecordById')

    const storedCredential = await agent.modules.w3cVc.storeCredential({
      credential: testCredential,
    })

    const retrievedCredential = await agent.modules.w3cVc.getCredentialRecordById(storedCredential.id)
    expect(storedCredential.id).toEqual(retrievedCredential.id)

    expect(repoSpy).toHaveBeenCalledTimes(1)

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect(repoSpy).toHaveBeenCalledWith((agent as any).agentContext, storedCredential.id)
    expect(serviceSpy).toHaveBeenCalledTimes(1)
  })

  it('Should successfully remove a credential by id', async () => {
    const repoSpy = jest.spyOn(w3cCredentialRepository, 'delete')
    const serviceSpy = jest.spyOn(w3cCredentialService, 'removeCredentialRecord')

    const storedCredential = await agent.modules.w3cVc.storeCredential({
      credential: testCredential,
    })

    await agent.modules.w3cVc.removeCredentialRecord(storedCredential.id)

    expect(repoSpy).toHaveBeenCalledTimes(1)
    expect(serviceSpy).toHaveBeenCalledTimes(1)
    expect(serviceSpy).toHaveBeenCalledWith((agent as any).agentContext, storedCredential.id)

    const allCredentials = await agent.modules.w3cVc.getAllCredentialRecords()
    expect(allCredentials).toHaveLength(0)
  })
})
