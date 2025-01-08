import type { EventReplaySubject } from './events'
import type { AnonCredsTestsAgent } from '../../anoncreds/tests/legacyAnonCredsSetup'

import { issueLegacyAnonCredsCredential, setupAnonCredsTests } from '../../anoncreds/tests/legacyAnonCredsSetup'
import { ProofState } from '../../didcomm/src/modules/proofs'
import { uuid } from '../src/utils/uuid'

import { waitForProofExchangeRecord } from './helpers'
import testLogger from './logger'

describe('Present Proof Subprotocol', () => {
  let faberAgent: AnonCredsTestsAgent
  let faberReplay: EventReplaySubject
  let aliceAgent: AnonCredsTestsAgent
  let aliceReplay: EventReplaySubject
  let credentialDefinitionId: string
  let faberConnectionId: string
  let aliceConnectionId: string

  beforeAll(async () => {
    testLogger.test('Initializing the agents')
    ;({
      issuerAgent: faberAgent,
      issuerReplay: faberReplay,
      holderAgent: aliceAgent,
      holderReplay: aliceReplay,
      credentialDefinitionId,
      issuerHolderConnectionId: faberConnectionId,
      holderIssuerConnectionId: aliceConnectionId,
    } = await setupAnonCredsTests({
      issuerName: 'Faber agent',
      holderName: 'Alice agent',
      attributeNames: ['name', 'age'],
    }))

    await issueLegacyAnonCredsCredential({
      issuerAgent: faberAgent,
      issuerReplay: faberReplay,
      holderAgent: aliceAgent,
      holderReplay: aliceReplay,
      issuerHolderConnectionId: faberConnectionId,
      offer: {
        attributes: [
          {
            name: 'name',
            value: 'Alice',
          },
          {
            name: 'age',
            value: '50',
          },
        ],
        credentialDefinitionId,
      },
    })
  })

  afterAll(async () => {
    testLogger.test('Shutting down both agents')
    await faberAgent.shutdown()
    await faberAgent.wallet.delete()
    await aliceAgent.shutdown()
    await aliceAgent.wallet.delete()
  })

  test('Alice starts with v1 proof proposal to Faber with parentThreadId', async () => {
    const parentThreadId = uuid()

    // Alice sends a presentation proposal to Faber
    testLogger.test('Alice sends a presentation proposal to Faber')

    const faberProofExchangeRecordPromise = waitForProofExchangeRecord(faberAgent, {
      parentThreadId,
      state: ProofState.ProposalReceived,
    })

    const aliceProofExchangeRecord = await aliceAgent.modules.proofs.proposeProof({
      connectionId: aliceConnectionId,
      protocolVersion: 'v1',
      parentThreadId,
      proofFormats: {
        indy: {
          name: 'abc',
          version: '1.0',
          attributes: [
            {
              name: 'name',
              credentialDefinitionId,
              value: 'Alice',
            },
          ],
          predicates: [
            {
              credentialDefinitionId,
              name: 'age',
              predicate: '>=',
              threshold: 40,
            },
          ],
        },
      },
    })

    expect(aliceProofExchangeRecord.parentThreadId).toBe(parentThreadId)
    const proofsByParentThread = await aliceAgent.modules.proofs.getByParentThreadAndConnectionId(parentThreadId)
    expect(proofsByParentThread.length).toEqual(1)
    expect(proofsByParentThread[0].parentThreadId).toBe(parentThreadId)

    const threadId = aliceProofExchangeRecord.threadId

    testLogger.test('Faber waits for a presentation proposal from Alice')
    let faberProofExchangeRecord = await faberProofExchangeRecordPromise

    // Faber accepts the presentation proposal from Alice
    testLogger.test('Faber accepts the presentation proposal from Alice')
    await faberAgent.modules.proofs.acceptProposal({ proofRecordId: faberProofExchangeRecord.id })

    testLogger.test('Alice waits till it receives presentation ack')
    await waitForProofExchangeRecord(aliceAgent, {
      threadId,
      parentThreadId,
      state: ProofState.RequestReceived,
    })

    // Alice retrieves the requested credentials and accepts the presentation request
    testLogger.test('Alice accepts presentation request from Faber')
    const requestedCredentials = await aliceAgent.modules.proofs.selectCredentialsForRequest({
      proofRecordId: aliceProofExchangeRecord.id,
    })
    await aliceAgent.modules.proofs.acceptRequest({
      proofRecordId: aliceProofExchangeRecord.id,
      proofFormats: requestedCredentials.proofFormats,
    })

    testLogger.test('Faber waits for presentation from Alice')
    faberProofExchangeRecord = await waitForProofExchangeRecord(faberAgent, {
      threadId,
      parentThreadId,
      state: ProofState.PresentationReceived,
    })

    // Faber accepts the presentation provided by Alice
    testLogger.test('Faber accepts the presentation provided by Alice')
    await faberAgent.modules.proofs.acceptPresentation({ proofRecordId: faberProofExchangeRecord.id })

    // Alice waits until she received a presentation acknowledgement
    testLogger.test('Alice waits until she receives a presentation acknowledgement')
    await waitForProofExchangeRecord(aliceAgent, {
      threadId,
      parentThreadId,
      state: ProofState.Done,
    })
  })

  test('Faber starts with v1 proof requests to Alice with parentThreadId', async () => {
    const parentThreadId = uuid()
    testLogger.test('Faber sends presentation request to Alice')

    const aliceProofExchangeRecordPromise = waitForProofExchangeRecord(aliceAgent, {
      parentThreadId,
      state: ProofState.RequestReceived,
    })

    // Faber sends a presentation request to Alice
    testLogger.test('Faber sends a presentation request to Alice')
    const faberProofExchangeRecord = await faberAgent.modules.proofs.requestProof({
      connectionId: faberConnectionId,
      parentThreadId,
      protocolVersion: 'v1',
      proofFormats: {
        indy: {
          name: 'proof-request',
          version: '1.0',
          requested_attributes: {
            name: {
              name: 'name',
              restrictions: [
                {
                  cred_def_id: credentialDefinitionId,
                },
              ],
            },
          },
          requested_predicates: {
            age: {
              name: 'age',
              p_type: '>=',
              p_value: 50,
              restrictions: [
                {
                  cred_def_id: credentialDefinitionId,
                },
              ],
            },
          },
        },
      },
    })

    expect(faberProofExchangeRecord.parentThreadId).toBe(parentThreadId)
    const proofsByParentThread = await faberAgent.modules.proofs.getByParentThreadAndConnectionId(parentThreadId)
    expect(proofsByParentThread.length).toEqual(1)
    expect(proofsByParentThread[0].parentThreadId).toBe(parentThreadId)

    const threadId = faberProofExchangeRecord.threadId

    // Alice waits for presentation request from Faber
    testLogger.test('Alice waits for presentation request from Faber')
    const aliceProofExchangeRecord = await aliceProofExchangeRecordPromise

    // Alice retrieves the requested credentials and accepts the presentation request
    testLogger.test('Alice accepts presentation request from Faber')
    const requestedCredentials = await aliceAgent.modules.proofs.selectCredentialsForRequest({
      proofRecordId: aliceProofExchangeRecord.id,
    })
    await aliceAgent.modules.proofs.acceptRequest({
      proofRecordId: aliceProofExchangeRecord.id,
      proofFormats: requestedCredentials.proofFormats,
    })

    // Faber waits until it receives a presentation from Alice
    testLogger.test('Faber waits for presentation from Alice')
    await waitForProofExchangeRecord(faberAgent, {
      threadId,
      parentThreadId,
      state: ProofState.PresentationReceived,
    })

    // Faber accepts the presentation
    testLogger.test('Faber accept the presentation from Alice')
    await faberAgent.modules.proofs.acceptPresentation({ proofRecordId: faberProofExchangeRecord.id })

    // Alice waits until she receives a presentation acknowledgement
    testLogger.test('Alice waits for acceptance by Faber')
    await waitForProofExchangeRecord(aliceAgent, {
      threadId,
      parentThreadId,
      state: ProofState.Done,
    })
  })

  test('Alice starts with v2 proof proposal to Faber with parentThreadId', async () => {
    const parentThreadId = uuid()

    // Alice sends a presentation proposal to Faber
    testLogger.test('Alice sends a presentation proposal to Faber')

    const faberProofExchangeRecordPromise = waitForProofExchangeRecord(faberAgent, {
      parentThreadId,
      state: ProofState.ProposalReceived,
    })

    const aliceProofExchangeRecord = await aliceAgent.modules.proofs.proposeProof({
      connectionId: aliceConnectionId,
      protocolVersion: 'v2',
      parentThreadId,
      proofFormats: {
        indy: {
          name: 'abc',
          version: '1.0',
          attributes: [
            {
              name: 'name',
              credentialDefinitionId,
              value: 'Alice',
            },
          ],
          predicates: [
            {
              credentialDefinitionId,
              name: 'age',
              predicate: '>=',
              threshold: 40,
            },
          ],
        },
      },
    })

    expect(aliceProofExchangeRecord.parentThreadId).toBe(parentThreadId)
    const proofsByParentThread = await aliceAgent.modules.proofs.getByParentThreadAndConnectionId(parentThreadId)
    expect(proofsByParentThread.length).toEqual(1)
    expect(proofsByParentThread[0].parentThreadId).toBe(parentThreadId)

    const threadId = aliceProofExchangeRecord.threadId

    testLogger.test('Faber waits for a presentation proposal from Alice')
    let faberProofExchangeRecord = await faberProofExchangeRecordPromise

    // Faber accepts the presentation proposal from Alice
    testLogger.test('Faber accepts the presentation proposal from Alice')
    await faberAgent.modules.proofs.acceptProposal({ proofRecordId: faberProofExchangeRecord.id })

    testLogger.test('Alice waits till it receives presentation ack')
    await waitForProofExchangeRecord(aliceAgent, {
      threadId,
      parentThreadId,
      state: ProofState.RequestReceived,
    })

    // Alice retrieves the requested credentials and accepts the presentation request
    testLogger.test('Alice accepts presentation request from Faber')
    const requestedCredentials = await aliceAgent.modules.proofs.selectCredentialsForRequest({
      proofRecordId: aliceProofExchangeRecord.id,
    })
    await aliceAgent.modules.proofs.acceptRequest({
      proofRecordId: aliceProofExchangeRecord.id,
      proofFormats: requestedCredentials.proofFormats,
    })

    testLogger.test('Faber waits for presentation from Alice')
    faberProofExchangeRecord = await waitForProofExchangeRecord(faberAgent, {
      threadId,
      parentThreadId,
      state: ProofState.PresentationReceived,
    })

    // Faber accepts the presentation provided by Alice
    testLogger.test('Faber accepts the presentation provided by Alice')
    await faberAgent.modules.proofs.acceptPresentation({ proofRecordId: faberProofExchangeRecord.id })

    // Alice waits until she received a presentation acknowledgement
    testLogger.test('Alice waits until she receives a presentation acknowledgement')
    await waitForProofExchangeRecord(aliceAgent, {
      threadId,
      parentThreadId,
      state: ProofState.Done,
    })
  })

  test('Faber starts with v2 proof requests to Alice with parentThreadId', async () => {
    const parentThreadId = uuid()
    testLogger.test('Faber sends presentation request to Alice')

    const aliceProofExchangeRecordPromise = waitForProofExchangeRecord(aliceAgent, {
      parentThreadId,
      state: ProofState.RequestReceived,
    })

    // Faber sends a presentation request to Alice
    testLogger.test('Faber sends a presentation request to Alice')
    const faberProofExchangeRecord = await faberAgent.modules.proofs.requestProof({
      connectionId: faberConnectionId,
      parentThreadId,
      protocolVersion: 'v2',
      proofFormats: {
        indy: {
          name: 'proof-request',
          version: '1.0',
          requested_attributes: {
            name: {
              name: 'name',
              restrictions: [
                {
                  cred_def_id: credentialDefinitionId,
                },
              ],
            },
          },
          requested_predicates: {
            age: {
              name: 'age',
              p_type: '>=',
              p_value: 50,
              restrictions: [
                {
                  cred_def_id: credentialDefinitionId,
                },
              ],
            },
          },
        },
      },
    })

    expect(faberProofExchangeRecord.parentThreadId).toBe(parentThreadId)
    const proofsByParentThread = await faberAgent.modules.proofs.getByParentThreadAndConnectionId(parentThreadId)
    expect(proofsByParentThread.length).toEqual(1)
    expect(proofsByParentThread[0].parentThreadId).toBe(parentThreadId)

    const threadId = faberProofExchangeRecord.threadId

    // Alice waits for presentation request from Faber
    testLogger.test('Alice waits for presentation request from Faber')
    const aliceProofExchangeRecord = await aliceProofExchangeRecordPromise

    // Alice retrieves the requested credentials and accepts the presentation request
    testLogger.test('Alice accepts presentation request from Faber')
    const requestedCredentials = await aliceAgent.modules.proofs.selectCredentialsForRequest({
      proofRecordId: aliceProofExchangeRecord.id,
    })
    await aliceAgent.modules.proofs.acceptRequest({
      proofRecordId: aliceProofExchangeRecord.id,
      proofFormats: requestedCredentials.proofFormats,
    })

    // Faber waits until it receives a presentation from Alice
    testLogger.test('Faber waits for presentation from Alice')
    await waitForProofExchangeRecord(faberAgent, {
      threadId,
      parentThreadId,
      state: ProofState.PresentationReceived,
    })

    // Faber accepts the presentation
    testLogger.test('Faber accept the presentation from Alice')
    await faberAgent.modules.proofs.acceptPresentation({ proofRecordId: faberProofExchangeRecord.id })

    // Alice waits until she receives a presentation acknowledgement
    testLogger.test('Alice waits for acceptance by Faber')
    await waitForProofExchangeRecord(aliceAgent, {
      threadId,
      parentThreadId,
      state: ProofState.Done,
    })
  })
})
