import type { Agent, ConnectionRecord, ProofExchangeRecord } from '../src'

import { ProofState } from '../src'
import { TEST_INPUT_DESCRIPTORS_CITIZENSHIP } from '../src/modules/proofs/__tests__/fixtures'
import {
  V2_PRESENTATION_EXCHANGE_PRESENTATION,
  V2_PRESENTATION_EXCHANGE_PRESENTATION_PROPOSAL,
  V2_PRESENTATION_EXCHANGE_PRESENTATION_REQUEST,
} from '../src/modules/proofs/formats/ProofFormats'
import {
  V2PresentationMessage,
  V2ProposalPresentationMessage,
  V2RequestPresentationMessage,
} from '../src/modules/proofs/protocol/v2/messages'
import { DidCommMessageRepository } from '../src/storage/didcomm'

import { setupJsonLdProofsTest, waitForProofExchangeRecord } from './helpers'
import testLogger from './logger'

describe('Present Proof', () => {
  let faberAgent: Agent
  let aliceAgent: Agent
  let aliceConnection: ConnectionRecord
  let faberConnection: ConnectionRecord
  let faberProofRecord: ProofExchangeRecord
  let aliceProofRecord: ProofExchangeRecord
  let didCommMessageRepository: DidCommMessageRepository

  beforeAll(async () => {
    testLogger.test('Initializing the agents')
    ;({ faberAgent, aliceAgent, faberConnection, aliceConnection } = await setupJsonLdProofsTest(
      'Faber agent',
      'Alice agent'
    ))

    didCommMessageRepository = faberAgent.injectionContainer.resolve<DidCommMessageRepository>(DidCommMessageRepository)
  })

  afterAll(async () => {
    testLogger.test('Shutting down both agents')
    await faberAgent.shutdown()
    await faberAgent.wallet.delete()
    await aliceAgent.shutdown()
    await aliceAgent.wallet.delete()
  })

  test('Alice starts with proof proposal to Faber', async () => {
    // Alice sends a presentation proposal to Faber
    testLogger.test('Alice sends a presentation proposal to Faber')

    let faberProofRecordPromise = waitForProofExchangeRecord(faberAgent, {
      state: ProofState.ProposalReceived,
    })

    aliceProofRecord = await aliceAgent.proofs.proposeProof({
      connectionId: aliceConnection.id,
      protocolVersion: 'v2',
      proofFormats: {
        presentationExchange: {
          presentationDefinition: {
            id: 'e950bfe5-d7ec-4303-ad61-6983fb976ac9',
            input_descriptors: [TEST_INPUT_DESCRIPTORS_CITIZENSHIP],
          },
        },
      },
      comment: 'V2 Presentation Exchange propose proof test',
    })

    // Faber waits for a presentation proposal from Alice
    testLogger.test('Faber waits for a presentation proposal from Alice')
    faberProofRecord = await faberProofRecordPromise

    const proposal = await didCommMessageRepository.findAgentMessage(faberAgent.context, {
      associatedRecordId: faberProofRecord.id,
      messageClass: V2ProposalPresentationMessage,
    })

    expect(proposal).toMatchObject({
      type: 'https://didcomm.org/present-proof/2.0/propose-presentation',
      formats: [
        {
          attachmentId: expect.any(String),
          format: V2_PRESENTATION_EXCHANGE_PRESENTATION_PROPOSAL,
        },
      ],
      proposalsAttach: [
        {
          id: expect.any(String),
          mimeType: 'application/json',
          data: {
            json: {
              input_descriptors: expect.any(Array),
            },
          },
        },
      ],
      id: expect.any(String),
      comment: 'V2 Presentation Exchange propose proof test',
    })
    expect(faberProofRecord.id).not.toBeNull()
    expect(faberProofRecord).toMatchObject({
      threadId: faberProofRecord.threadId,
      state: ProofState.ProposalReceived,
      protocolVersion: 'v2',
    })

    const acceptProposalOptions = {
      config: {
        name: 'proof-request',
        version: '1.0',
      },
      proofRecordId: faberProofRecord.id,
    }

    let aliceProofRecordPromise = waitForProofExchangeRecord(aliceAgent, {
      timeoutMs: 200000, // Temporary I have increased timeout as, verify presentation takes time to fetch the data from documentLoader
      threadId: aliceProofRecord.threadId,
      state: ProofState.RequestReceived,
    })

    // Faber accepts the presentation proposal from Alice
    testLogger.test('Faber accepts presentation proposal from Alice')
    faberProofRecord = await faberAgent.proofs.acceptProposal(acceptProposalOptions)

    // Alice waits for presentation request from Faber
    testLogger.test('Alice waits for presentation request from Faber')
    aliceProofRecord = await aliceProofRecordPromise

    const request = await didCommMessageRepository.findAgentMessage(faberAgent.context, {
      associatedRecordId: faberProofRecord.id,
      messageClass: V2RequestPresentationMessage,
    })

    expect(request).toMatchObject({
      type: 'https://didcomm.org/present-proof/2.0/request-presentation',
      id: expect.any(String),
      formats: [
        {
          attachmentId: expect.any(String),
          format: V2_PRESENTATION_EXCHANGE_PRESENTATION_REQUEST,
        },
      ],
      requestPresentationsAttach: [
        {
          id: expect.any(String),
          mimeType: 'application/json',
          data: {
            json: {
              options: {
                challenge: expect.any(String),
                domain: expect.any(String),
              },
              presentationDefinition: {
                id: expect.any(String),
                input_descriptors: [
                  {
                    id: expect.any(String),
                    name: expect.any(String),
                    group: expect.any(Array),
                    schema: expect.any(Array),
                    constraints: {
                      fields: expect.any(Array),
                    },
                  },
                ],
                // format: {
                //   ldpVc: {
                //     proofType: ['Ed25519Signature2018'],
                //   },
                // },
              },
            },
          },
        },
      ],
    })
    expect(aliceProofRecord).toMatchObject({
      id: expect.any(String),
      threadId: faberProofRecord.threadId,
      state: ProofState.RequestReceived,
      protocolVersion: 'v2',
    })

    // Alice retrieves the requested credentials and accepts the presentation request
    testLogger.test('Alice accepts presentation request from Faber')

    const requestedCredentials = await aliceAgent.proofs.autoSelectCredentialsForProofRequest({
      proofRecordId: aliceProofRecord.id,
      config: {
        filterByPresentationPreview: true,
      },
    })
    faberProofRecordPromise = waitForProofExchangeRecord(faberAgent, {
      threadId: aliceProofRecord.threadId,
      state: ProofState.PresentationReceived,
      timeoutMs: 200000, // Temporary I have increased timeout as, verify presentation takes time to fetch the data from documentLoader
    })

    aliceProofRecord = await aliceAgent.proofs.acceptRequest({
      proofRecordId: aliceProofRecord.id,
      proofFormats: { presentationExchange: requestedCredentials.proofFormats.presentationExchange },
    })

    // Faber waits for the presentation from Alice
    testLogger.test('Faber waits for presentation from Alice')
    faberProofRecord = await faberProofRecordPromise

    const presentation = await didCommMessageRepository.findAgentMessage(faberAgent.context, {
      associatedRecordId: faberProofRecord.id,
      messageClass: V2PresentationMessage,
    })

    expect(presentation).toMatchObject({
      type: 'https://didcomm.org/present-proof/2.0/presentation',
      formats: [
        {
          attachmentId: expect.any(String),
          format: V2_PRESENTATION_EXCHANGE_PRESENTATION,
        },
      ],
      presentationsAttach: [
        {
          id: expect.any(String),
          mimeType: 'application/json',
          data: {
            json: {
              '@context': expect.any(Array),
              type: expect.any(Array),
              verifiableCredential: expect.any(Array),
            },
          },
        },
      ],
      id: expect.any(String),
      thread: {
        threadId: faberProofRecord.threadId,
      },
    })
    expect(faberProofRecord.id).not.toBeNull()
    expect(faberProofRecord).toMatchObject({
      threadId: faberProofRecord.threadId,
      state: ProofState.PresentationReceived,
      protocolVersion: 'v2',
    })

    aliceProofRecordPromise = waitForProofExchangeRecord(aliceAgent, {
      threadId: aliceProofRecord.threadId,
      state: ProofState.Done,
    })

    // Faber accepts the presentation provided by Alice
    testLogger.test('Faber accepts the presentation provided by Alice')
    await faberAgent.proofs.acceptPresentation(faberProofRecord.id)

    // Alice waits until she received a presentation acknowledgement
    testLogger.test('Alice waits until she receives a presentation acknowledgement')
    aliceProofRecord = await aliceProofRecordPromise

    expect(faberProofRecord).toMatchObject({
      id: expect.any(String),
      createdAt: expect.any(Date),
      threadId: aliceProofRecord.threadId,
      connectionId: expect.any(String),
      isVerified: true,
      state: ProofState.PresentationReceived,
    })
    expect(aliceProofRecord).toMatchObject({
      id: expect.any(String),
      createdAt: expect.any(Date),
      threadId: faberProofRecord.threadId,
      connectionId: expect.any(String),
      state: ProofState.Done,
    })
  })

  test('Faber starts with proof request to Alice', async () => {
    let aliceProofRecordPromise = waitForProofExchangeRecord(aliceAgent, {
      state: ProofState.RequestReceived,
    })

    // Faber sends a presentation request to Alice
    testLogger.test('Faber sends a presentation request to Alice')
    faberProofRecord = await faberAgent.proofs.requestProof({
      protocolVersion: 'v2',
      connectionId: faberConnection.id,
      proofFormats: {
        presentationExchange: {
          options: {
            challenge: 'e950bfe5-d7ec-4303-ad61-6983fb976ac9',
            domain: '',
          },
          presentationDefinition: {
            id: 'e950bfe5-d7ec-4303-ad61-6983fb976ac9',
            input_descriptors: [TEST_INPUT_DESCRIPTORS_CITIZENSHIP],
          },
        },
      },
    })

    // Alice waits for presentation request from Faber
    testLogger.test('Alice waits for presentation request from Faber')
    aliceProofRecord = await aliceProofRecordPromise

    const request = await didCommMessageRepository.findAgentMessage(faberAgent.context, {
      associatedRecordId: faberProofRecord.id,
      messageClass: V2RequestPresentationMessage,
    })

    expect(request).toMatchObject({
      type: 'https://didcomm.org/present-proof/2.0/request-presentation',
      id: expect.any(String),
      formats: [
        {
          attachmentId: expect.any(String),
          format: V2_PRESENTATION_EXCHANGE_PRESENTATION_REQUEST,
        },
      ],
      requestPresentationsAttach: [
        {
          id: expect.any(String),
          mimeType: 'application/json',
          data: {
            json: {
              options: {
                challenge: expect.any(String),
                domain: expect.any(String),
              },
              presentationDefinition: {
                id: expect.any(String),
                input_descriptors: [
                  {
                    id: expect.any(String),
                    name: expect.any(String),
                    group: expect.any(Array),
                    schema: expect.any(Array),
                    constraints: {
                      fields: expect.any(Array),
                    },
                  },
                ],
                // format: {
                //   ldpVc: {
                //     proofType: ['Ed25519Signature2018'],
                //   },
                // },
              },
            },
          },
        },
      ],
    })
    expect(aliceProofRecord).toMatchObject({
      id: expect.any(String),
      threadId: faberProofRecord.threadId,
      state: ProofState.RequestReceived,
      protocolVersion: 'v2',
    })

    // Alice retrieves the requested credentials and accepts the presentation request
    testLogger.test('Alice accepts presentation request from Faber')

    const requestedCredentials = await aliceAgent.proofs.autoSelectCredentialsForProofRequest({
      proofRecordId: aliceProofRecord.id,
      config: {
        filterByPresentationPreview: true,
      },
    })

    const acceptPresentationOptions = {
      proofRecordId: aliceProofRecord.id,
      proofFormats: { presentationExchange: requestedCredentials.proofFormats.presentationExchange },
    }

    const faberProofRecordPromise = waitForProofExchangeRecord(faberAgent, {
      threadId: aliceProofRecord.threadId,
      state: ProofState.PresentationReceived,
      timeoutMs: 200000, // Temporary I have increased timeout as, verify presentation takes time to fetch the data from documentLoader
    })

    aliceProofRecord = await aliceAgent.proofs.acceptRequest(acceptPresentationOptions)

    // Faber waits for the presentation from Alice
    testLogger.test('Faber waits for presentation from Alice')
    faberProofRecord = await faberProofRecordPromise

    const presentation = await didCommMessageRepository.findAgentMessage(faberAgent.context, {
      associatedRecordId: faberProofRecord.id,
      messageClass: V2PresentationMessage,
    })

    expect(presentation).toMatchObject({
      type: 'https://didcomm.org/present-proof/2.0/presentation',
      formats: [
        {
          attachmentId: expect.any(String),
          format: V2_PRESENTATION_EXCHANGE_PRESENTATION,
        },
      ],
      presentationsAttach: [
        {
          id: expect.any(String),
          mimeType: 'application/json',
          data: {
            json: {
              '@context': expect.any(Array),
              type: expect.any(Array),
              verifiableCredential: expect.any(Array),
            },
          },
        },
      ],
      id: expect.any(String),
      thread: {
        threadId: faberProofRecord.threadId,
      },
    })
    expect(faberProofRecord.id).not.toBeNull()
    expect(faberProofRecord).toMatchObject({
      threadId: faberProofRecord.threadId,
      state: ProofState.PresentationReceived,
      protocolVersion: 'v2',
    })

    aliceProofRecordPromise = waitForProofExchangeRecord(aliceAgent, {
      threadId: aliceProofRecord.threadId,
      state: ProofState.Done,
    })

    // Faber accepts the presentation provided by Alice
    testLogger.test('Faber accepts the presentation provided by Alice')
    await faberAgent.proofs.acceptPresentation(faberProofRecord.id)

    // Alice waits until she received a presentation acknowledgement
    testLogger.test('Alice waits until she receives a presentation acknowledgement')
    aliceProofRecord = await aliceProofRecordPromise

    expect(faberProofRecord).toMatchObject({
      id: expect.any(String),
      createdAt: expect.any(Date),
      threadId: aliceProofRecord.threadId,
      connectionId: expect.any(String),
      isVerified: true,
      state: ProofState.PresentationReceived,
    })

    expect(aliceProofRecord).toMatchObject({
      id: expect.any(String),
      createdAt: expect.any(Date),
      threadId: faberProofRecord.threadId,
      connectionId: expect.any(String),
      state: ProofState.Done,
    })
  })
})
