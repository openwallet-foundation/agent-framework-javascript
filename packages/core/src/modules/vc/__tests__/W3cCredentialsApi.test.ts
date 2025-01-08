import { getInMemoryAgentOptions } from '../../../../tests'
import { Agent } from '../../../agent/Agent'
import { JsonTransformer } from '../../../utils'
import { W3cCredentialService } from '../W3cCredentialService'
import { W3cCredentialsModule } from '../W3cCredentialsModule'
import { customDocumentLoader } from '../data-integrity/__tests__/documentLoader'
import { Ed25519Signature2018Fixtures } from '../data-integrity/__tests__/fixtures'
import { W3cJsonLdVerifiableCredential } from '../data-integrity/models'
import { W3cCredentialRepository } from '../repository'

const agentOptions = getInMemoryAgentOptions(
  'W3cCredentialsApi',
  {},
  {},
  {
    w3cCredentials: new W3cCredentialsModule({
      documentLoader: customDocumentLoader,
    }),
  }
)

const agent = new Agent(agentOptions)

let w3cCredentialRepository: W3cCredentialRepository
let w3cCredentialService: W3cCredentialService

const testCredential = JsonTransformer.fromJSON(
  Ed25519Signature2018Fixtures.TEST_LD_DOCUMENT_SIGNED,
  W3cJsonLdVerifiableCredential
)

describe('W3cCredentialsApi', () => {
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

    await agent.w3cCredentials.storeCredential({
      credential: testCredential,
    })

    expect(repoSpy).toHaveBeenCalledTimes(1)
    expect(serviceSpy).toHaveBeenCalledTimes(1)
  })

  it('Should successfully retrieve a credential by id', async () => {
    const repoSpy = jest.spyOn(w3cCredentialRepository, 'getById')
    const serviceSpy = jest.spyOn(w3cCredentialService, 'getCredentialRecordById')

    const storedCredential = await agent.w3cCredentials.storeCredential({
      credential: testCredential,
    })

    const retrievedCredential = await agent.w3cCredentials.getCredentialRecordById(storedCredential.id)
    expect(storedCredential.id).toEqual(retrievedCredential.id)

    expect(repoSpy).toHaveBeenCalledTimes(1)

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect(repoSpy).toHaveBeenCalledWith((agent as any).agentContext, storedCredential.id)
    expect(serviceSpy).toHaveBeenCalledTimes(1)
  })

  it('Should successfully remove a credential by id', async () => {
    const repoSpy = jest.spyOn(w3cCredentialRepository, 'deleteById')
    const serviceSpy = jest.spyOn(w3cCredentialService, 'removeCredentialRecord')

    const storedCredential = await agent.w3cCredentials.storeCredential({
      credential: testCredential,
    })

    await agent.w3cCredentials.removeCredentialRecord(storedCredential.id)

    expect(repoSpy).toHaveBeenCalledTimes(1)
    expect(serviceSpy).toHaveBeenCalledTimes(1)
    expect(serviceSpy).toHaveBeenCalledWith(agent.context, storedCredential.id)

    const allCredentials = await agent.w3cCredentials.getAllCredentialRecords()
    expect(allCredentials).toHaveLength(0)
  })
})
