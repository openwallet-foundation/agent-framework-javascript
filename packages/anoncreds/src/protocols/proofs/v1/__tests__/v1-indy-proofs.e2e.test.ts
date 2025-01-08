import type { EventReplaySubject } from '../../../../../../core/tests'
import type { AnonCredsTestsAgent } from '../../../../../tests/legacyAnonCredsSetup'

import { testLogger, waitForProofExchangeRecord } from '../../../../../../core/tests'
import { ProofState, ProofExchangeRecord } from '../../../../../../didcomm/src'
import { issueLegacyAnonCredsCredential, setupAnonCredsTests } from '../../../../../tests/legacyAnonCredsSetup'
import { V1ProposePresentationMessage, V1RequestPresentationMessage, V1PresentationMessage } from '../messages'

describe('Present Proof', () => {
  let faberAgent: AnonCredsTestsAgent
  let faberReplay: EventReplaySubject
  let aliceAgent: AnonCredsTestsAgent
  let aliceReplay: EventReplaySubject
  let faberConnectionId: string
  let aliceConnectionId: string
  let credentialDefinitionId: string

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
      issuerName: 'Faber Proofs V1 - Full',
      holderName: 'Alice Proofs V1 - Full',
      attributeNames: ['name', 'age'],
    }))

    await issueLegacyAnonCredsCredential({
      issuerAgent: faberAgent,
      issuerReplay: faberReplay,
      holderAgent: aliceAgent,
      holderReplay: aliceReplay,
      issuerHolderConnectionId: faberConnectionId,
      offer: {
        credentialDefinitionId,
        attributes: [
          { name: 'name', value: 'John' },
          { name: 'age', value: '99' },
        ],
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

  test('Alice starts with proof proposal to Faber', async () => {
    // Alice sends a presentation proposal to Faber
    testLogger.test('Alice sends a presentation proposal to Faber')

    let faberProofExchangeRecordPromise = waitForProofExchangeRecord(faberAgent, {
      state: ProofState.ProposalReceived,
    })

    let aliceProofExchangeRecord = await aliceAgent.modules.proofs.proposeProof({
      connectionId: aliceConnectionId,
      protocolVersion: 'v1',
      proofFormats: {
        indy: {
          attributes: [
            {
              name: 'name',
              value: 'John',
              credentialDefinitionId,
              referent: '0',
            },
          ],
          predicates: [
            {
              name: 'age',
              predicate: '>=',
              threshold: 50,
              credentialDefinitionId,
            },
          ],
        },
      },
    })

    // Faber waits for a presentation proposal from Alice
    testLogger.test('Faber waits for a presentation proposal from Alice')
    let faberProofExchangeRecord = await faberProofExchangeRecordPromise
    const proposal = await faberAgent.modules.proofs.findProposalMessage(faberProofExchangeRecord.id)
    expect(proposal).toMatchObject({
      type: 'https://didcomm.org/present-proof/1.0/propose-presentation',
      id: expect.any(String),
      presentationProposal: {
        type: 'https://didcomm.org/present-proof/1.0/presentation-preview',
        attributes: [
          {
            name: 'name',
            credentialDefinitionId,
            value: 'John',
            referent: '0',
          },
        ],
        predicates: [
          {
            name: 'age',
            credentialDefinitionId,
            predicate: '>=',
            threshold: 50,
          },
        ],
      },
    })
    expect(faberProofExchangeRecord.id).not.toBeNull()
    expect(faberProofExchangeRecord).toMatchObject({
      threadId: faberProofExchangeRecord.threadId,
      state: ProofState.ProposalReceived,
      protocolVersion: 'v1',
    })

    let aliceProofExchangeRecordPromise = waitForProofExchangeRecord(aliceAgent, {
      threadId: aliceProofExchangeRecord.threadId,
      state: ProofState.RequestReceived,
    })

    // Faber accepts the presentation proposal from Alice
    testLogger.test('Faber accepts presentation proposal from Alice')
    faberProofExchangeRecord = await faberAgent.modules.proofs.acceptProposal({
      proofRecordId: faberProofExchangeRecord.id,
    })

    // Alice waits for presentation request from Faber
    testLogger.test('Alice waits for presentation request from Faber')
    aliceProofExchangeRecord = await aliceProofExchangeRecordPromise

    const request = await faberAgent.modules.proofs.findRequestMessage(faberProofExchangeRecord.id)
    expect(request).toMatchObject({
      type: 'https://didcomm.org/present-proof/1.0/request-presentation',
      id: expect.any(String),
      requestAttachments: [
        {
          id: 'libindy-request-presentation-0',
          mimeType: 'application/json',
          data: {
            base64: expect.any(String),
          },
        },
      ],
      thread: {
        threadId: faberProofExchangeRecord.threadId,
      },
    })

    // Alice retrieves the requested credentials and accepts the presentation request
    testLogger.test('Alice accepts presentation request from Faber')

    const requestedCredentials = await aliceAgent.modules.proofs.selectCredentialsForRequest({
      proofRecordId: aliceProofExchangeRecord.id,
    })

    faberProofExchangeRecordPromise = waitForProofExchangeRecord(faberAgent, {
      threadId: aliceProofExchangeRecord.threadId,
      state: ProofState.PresentationReceived,
    })

    await aliceAgent.modules.proofs.acceptRequest({
      proofRecordId: aliceProofExchangeRecord.id,
      proofFormats: { indy: requestedCredentials.proofFormats.indy },
    })

    // Faber waits for the presentation from Alice
    testLogger.test('Faber waits for presentation from Alice')
    faberProofExchangeRecord = await faberProofExchangeRecordPromise

    const presentation = await faberAgent.modules.proofs.findPresentationMessage(faberProofExchangeRecord.id)
    expect(presentation).toMatchObject({
      type: 'https://didcomm.org/present-proof/1.0/presentation',
      id: expect.any(String),
      presentationAttachments: [
        {
          id: 'libindy-presentation-0',
          mimeType: 'application/json',
          data: {
            base64: expect.any(String),
          },
        },
      ],
      thread: {
        threadId: expect.any(String),
      },
    })

    expect(faberProofExchangeRecord.id).not.toBeNull()
    expect(faberProofExchangeRecord).toMatchObject({
      threadId: faberProofExchangeRecord.threadId,
      state: ProofState.PresentationReceived,
      protocolVersion: 'v1',
    })

    aliceProofExchangeRecordPromise = waitForProofExchangeRecord(aliceAgent, {
      threadId: aliceProofExchangeRecord.threadId,
      state: ProofState.Done,
    })

    // Faber accepts the presentation provided by Alice
    testLogger.test('Faber accepts the presentation provided by Alice')
    await faberAgent.modules.proofs.acceptPresentation({ proofRecordId: faberProofExchangeRecord.id })

    // Alice waits until she received a presentation acknowledgement
    testLogger.test('Alice waits until she receives a presentation acknowledgement')
    aliceProofExchangeRecord = await aliceProofExchangeRecordPromise

    expect(faberProofExchangeRecord).toMatchObject({
      type: ProofExchangeRecord.type,
      id: expect.any(String),
      createdAt: expect.any(Date),
      threadId: aliceProofExchangeRecord.threadId,
      connectionId: expect.any(String),
      isVerified: true,
      state: ProofState.PresentationReceived,
    })

    expect(aliceProofExchangeRecord).toMatchObject({
      type: ProofExchangeRecord.type,
      id: expect.any(String),
      createdAt: expect.any(Date),
      threadId: faberProofExchangeRecord.threadId,
      connectionId: expect.any(String),
      state: ProofState.Done,
    })

    const proposalMessage = await aliceAgent.modules.proofs.findProposalMessage(aliceProofExchangeRecord.id)
    const requestMessage = await aliceAgent.modules.proofs.findRequestMessage(aliceProofExchangeRecord.id)
    const presentationMessage = await aliceAgent.modules.proofs.findPresentationMessage(aliceProofExchangeRecord.id)

    expect(proposalMessage).toBeInstanceOf(V1ProposePresentationMessage)
    expect(requestMessage).toBeInstanceOf(V1RequestPresentationMessage)
    expect(presentationMessage).toBeInstanceOf(V1PresentationMessage)

    const formatData = await aliceAgent.modules.proofs.getFormatData(aliceProofExchangeRecord.id)

    const proposalPredicateKey = Object.keys(formatData.proposal?.indy?.requested_predicates || {})[0]
    const requestPredicateKey = Object.keys(formatData.request?.indy?.requested_predicates || {})[0]

    expect(formatData).toMatchObject({
      proposal: {
        indy: {
          name: 'Proof Request',
          version: '1.0',
          nonce: expect.any(String),
          requested_attributes: {
            0: {
              name: 'name',
            },
          },
          requested_predicates: {
            [proposalPredicateKey]: {
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
      request: {
        indy: {
          name: 'Proof Request',
          version: '1.0',
          nonce: expect.any(String),
          requested_attributes: {
            0: {
              name: 'name',
            },
          },
          requested_predicates: {
            [requestPredicateKey]: {
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
      presentation: {
        indy: {
          proof: expect.any(Object),
          requested_proof: expect.any(Object),
          identifiers: expect.any(Array),
        },
      },
    })
  })

  test('Faber starts with proof request to Alice', async () => {
    let aliceProofExchangeRecordPromise = waitForProofExchangeRecord(aliceAgent, {
      state: ProofState.RequestReceived,
    })

    // Faber sends a presentation request to Alice
    testLogger.test('Faber sends a presentation request to Alice')
    let faberProofExchangeRecord = await faberAgent.modules.proofs.requestProof({
      protocolVersion: 'v1',
      connectionId: faberConnectionId,
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

    // Alice waits for presentation request from Faber
    testLogger.test('Alice waits for presentation request from Faber')
    let aliceProofExchangeRecord = await aliceProofExchangeRecordPromise

    const request = await faberAgent.modules.proofs.findRequestMessage(faberProofExchangeRecord.id)
    expect(request).toMatchObject({
      type: 'https://didcomm.org/present-proof/1.0/request-presentation',
      id: expect.any(String),
      requestAttachments: [
        {
          id: 'libindy-request-presentation-0',
          mimeType: 'application/json',
          data: {
            base64: expect.any(String),
          },
        },
      ],
    })

    expect(aliceProofExchangeRecord.id).not.toBeNull()
    expect(aliceProofExchangeRecord).toMatchObject({
      threadId: aliceProofExchangeRecord.threadId,
      state: ProofState.RequestReceived,
      protocolVersion: 'v1',
    })

    // Alice retrieves the requested credentials and accepts the presentation request
    testLogger.test('Alice accepts presentation request from Faber')

    const requestedCredentials = await aliceAgent.modules.proofs.selectCredentialsForRequest({
      proofRecordId: aliceProofExchangeRecord.id,
    })

    const faberProofExchangeRecordPromise = waitForProofExchangeRecord(faberAgent, {
      threadId: aliceProofExchangeRecord.threadId,
      state: ProofState.PresentationReceived,
    })

    await aliceAgent.modules.proofs.acceptRequest({
      proofRecordId: aliceProofExchangeRecord.id,
      proofFormats: { indy: requestedCredentials.proofFormats.indy },
    })

    // Faber waits until it receives a presentation from Alice
    testLogger.test('Faber waits for presentation from Alice')
    faberProofExchangeRecord = await faberProofExchangeRecordPromise

    const presentation = await faberAgent.modules.proofs.findPresentationMessage(faberProofExchangeRecord.id)
    expect(presentation).toMatchObject({
      type: 'https://didcomm.org/present-proof/1.0/presentation',
      id: expect.any(String),
      presentationAttachments: [
        {
          id: 'libindy-presentation-0',
          mimeType: 'application/json',
          data: {
            base64: expect.any(String),
          },
        },
      ],
      thread: {
        threadId: expect.any(String),
      },
    })

    expect(faberProofExchangeRecord.id).not.toBeNull()
    expect(faberProofExchangeRecord).toMatchObject({
      threadId: faberProofExchangeRecord.threadId,
      state: ProofState.PresentationReceived,
      protocolVersion: 'v1',
    })

    aliceProofExchangeRecordPromise = waitForProofExchangeRecord(aliceAgent, {
      threadId: aliceProofExchangeRecord.threadId,
      state: ProofState.Done,
    })

    // Faber accepts the presentation
    testLogger.test('Faber accept the presentation from Alice')
    await faberAgent.modules.proofs.acceptPresentation({ proofRecordId: faberProofExchangeRecord.id })

    // Alice waits until she receives a presentation acknowledgement
    testLogger.test('Alice waits for acceptance by Faber')
    aliceProofExchangeRecord = await aliceProofExchangeRecordPromise

    expect(faberProofExchangeRecord).toMatchObject({
      type: ProofExchangeRecord.type,
      id: expect.any(String),
      createdAt: expect.any(Date),
      threadId: aliceProofExchangeRecord.threadId,
      connectionId: expect.any(String),
      isVerified: true,
      state: ProofState.PresentationReceived,
    })

    expect(aliceProofExchangeRecord).toMatchObject({
      type: ProofExchangeRecord.type,
      id: expect.any(String),
      createdAt: expect.any(Date),
      threadId: faberProofExchangeRecord.threadId,
      connectionId: expect.any(String),
      state: ProofState.Done,
    })
  })

  test('an attribute group name matches with a predicate group name so an error is thrown', async () => {
    await expect(
      faberAgent.modules.proofs.requestProof({
        protocolVersion: 'v1',
        connectionId: faberConnectionId,
        proofFormats: {
          indy: {
            name: 'proof-request',
            version: '1.0',
            requested_attributes: {
              age: {
                name: 'age',
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
    ).rejects.toThrowError(`The proof request contains duplicate predicates and attributes: age`)
  })

  test('Faber starts with proof request to Alice but gets Problem Reported', async () => {
    const aliceProofExchangeRecordPromise = waitForProofExchangeRecord(aliceAgent, {
      state: ProofState.RequestReceived,
    })

    // Faber sends a presentation request to Alice
    testLogger.test('Faber sends a presentation request to Alice')
    let faberProofExchangeRecord = await faberAgent.modules.proofs.requestProof({
      protocolVersion: 'v1',
      connectionId: faberConnectionId,
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

    // Alice waits for presentation request from Faber
    testLogger.test('Alice waits for presentation request from Faber')
    let aliceProofExchangeRecord = await aliceProofExchangeRecordPromise

    const request = await faberAgent.modules.proofs.findRequestMessage(faberProofExchangeRecord.id)
    expect(request).toMatchObject({
      type: 'https://didcomm.org/present-proof/1.0/request-presentation',
      id: expect.any(String),
      requestAttachments: [
        {
          id: 'libindy-request-presentation-0',
          mimeType: 'application/json',
          data: {
            base64: expect.any(String),
          },
        },
      ],
    })

    expect(aliceProofExchangeRecord.id).not.toBeNull()
    expect(aliceProofExchangeRecord).toMatchObject({
      threadId: aliceProofExchangeRecord.threadId,
      state: ProofState.RequestReceived,
      protocolVersion: 'v1',
    })

    const faberProofExchangeRecordPromise = waitForProofExchangeRecord(faberAgent, {
      threadId: aliceProofExchangeRecord.threadId,
      state: ProofState.Abandoned,
    })

    aliceProofExchangeRecord = await aliceAgent.modules.proofs.sendProblemReport({
      proofRecordId: aliceProofExchangeRecord.id,
      description: 'Problem inside proof request',
    })

    faberProofExchangeRecord = await faberProofExchangeRecordPromise

    expect(faberProofExchangeRecord).toMatchObject({
      threadId: aliceProofExchangeRecord.threadId,
      state: ProofState.Abandoned,
      protocolVersion: 'v1',
    })
  })
})
