import type { AnonCredsProofRequest } from '../../../../../../../anoncreds/src/models/exchange'
import type { AnonCredsTestsAgent } from '../../../../../../../anoncreds/tests/legacyAnonCredsSetup'
import type { EventReplaySubject } from '../../../../../../tests'
import type { V2ProposePresentationMessage, V2RequestPresentationMessage } from '../messages'

import { AnonCredsProofRequest as AnonCredsProofRequestClass } from '../../../../../../../anoncreds/src/models/AnonCredsProofRequest'
import {
  issueLegacyAnonCredsCredential,
  setupAnonCredsTests,
} from '../../../../../../../anoncreds/tests/legacyAnonCredsSetup'
import { waitForProofExchangeRecordSubject, testLogger } from '../../../../../../tests'
import { JsonTransformer } from '../../../../../utils/JsonTransformer'
import { ProofState } from '../../../models/ProofState'

describe('V2 Proofs Negotiation - Indy', () => {
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
      issuerHolderConnectionId: faberConnectionId,
      holderIssuerConnectionId: aliceConnectionId,

      credentialDefinitionId,
    } = await setupAnonCredsTests({
      issuerName: 'Faber agent v2',
      holderName: 'Alice agent v2',
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
          {
            name: 'name',
            value: 'Alice',
          },
          {
            name: 'age',
            value: '99',
          },
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

  test(`Proof negotiation between Alice and Faber`, async () => {
    testLogger.test('Alice sends proof proposal to Faber')

    let aliceProofExchangeRecord = await aliceAgent.proofs.proposeProof({
      connectionId: aliceConnectionId,
      protocolVersion: 'v2',
      proofFormats: {
        indy: {
          name: 'proof-request',
          version: '1.0',
          attributes: [],
          predicates: [
            {
              credentialDefinitionId,
              name: 'age',
              predicate: '>=',
              threshold: 50,
            },
          ],
        },
      },
      comment: 'V2 propose proof test 1',
    })

    testLogger.test('Faber waits for presentation from Alice')
    let faberProofExchangeRecord = await waitForProofExchangeRecordSubject(faberReplay, {
      state: ProofState.ProposalReceived,
      threadId: aliceProofExchangeRecord.threadId,
    })

    const proposal = await faberAgent.proofs.findProposalMessage(faberProofExchangeRecord.id)
    expect(proposal).toMatchObject({
      type: 'https://didcomm.org/present-proof/2.0/propose-presentation',
      formats: [
        {
          attachmentId: expect.any(String),
          format: 'hlindy/proof-req@v2.0',
        },
      ],
      proposalAttachments: [
        {
          id: expect.any(String),
          mimeType: 'application/json',
          data: {
            base64: expect.any(String),
          },
        },
      ],
      id: expect.any(String),
      comment: 'V2 propose proof test 1',
    })

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const proposalAttach = (
      proposal as V2ProposePresentationMessage
    )?.proposalAttachments?.[0].getDataAsJson<AnonCredsProofRequest>()

    expect(proposalAttach).toMatchObject({
      requested_attributes: {},
      requested_predicates: {
        [Object.keys(proposalAttach.requested_predicates)[0]]: {
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
    })
    expect(faberProofExchangeRecord).toMatchObject({
      id: expect.anything(),
      threadId: faberProofExchangeRecord.threadId,
      state: ProofState.ProposalReceived,
      protocolVersion: 'v2',
    })

    testLogger.test('Faber sends new proof request to Alice')
    faberProofExchangeRecord = await faberAgent.proofs.negotiateProposal({
      proofRecordId: faberProofExchangeRecord.id,
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

    testLogger.test('Alice waits for proof request from Faber')
    aliceProofExchangeRecord = await waitForProofExchangeRecordSubject(aliceReplay, {
      threadId: faberProofExchangeRecord.threadId,
      state: ProofState.RequestReceived,
    })

    const request = await faberAgent.proofs.findRequestMessage(faberProofExchangeRecord.id)
    expect(request).toMatchObject({
      type: 'https://didcomm.org/present-proof/2.0/request-presentation',
      id: expect.any(String),
      requestAttachments: [
        {
          id: expect.any(String),
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
    expect(aliceProofExchangeRecord).toMatchObject({
      id: expect.anything(),
      threadId: faberProofExchangeRecord.threadId,
      state: ProofState.RequestReceived,
      protocolVersion: 'v2',
    })

    testLogger.test('Alice sends proof proposal to Faber')

    aliceProofExchangeRecord = await aliceAgent.proofs.negotiateRequest({
      proofRecordId: aliceProofExchangeRecord.id,
      proofFormats: {
        indy: {
          name: 'proof-request',
          version: '1.0',
          attributes: [],
          predicates: [
            {
              credentialDefinitionId,
              name: 'age',
              predicate: '>=',
              threshold: 50,
            },
          ],
        },
      },
      comment: 'V2 propose proof test 2',
    })

    testLogger.test('Faber waits for presentation from Alice')
    faberProofExchangeRecord = await waitForProofExchangeRecordSubject(faberReplay, {
      state: ProofState.ProposalReceived,
      threadId: aliceProofExchangeRecord.threadId,
      // Negotiation so this will be the second proposal
      count: 2,
    })

    const proposal2 = await faberAgent.proofs.findProposalMessage(faberProofExchangeRecord.id)
    expect(proposal2).toMatchObject({
      type: 'https://didcomm.org/present-proof/2.0/propose-presentation',
      formats: [
        {
          attachmentId: expect.any(String),
          format: 'hlindy/proof-req@v2.0',
        },
      ],
      proposalAttachments: [
        {
          id: expect.any(String),
          mimeType: 'application/json',
          data: {
            base64: expect.any(String),
          },
        },
      ],
      id: expect.any(String),
      comment: 'V2 propose proof test 2',
    })

    const proposalAttach2 = (
      proposal as V2ProposePresentationMessage
    )?.proposalAttachments[0].getDataAsJson<AnonCredsProofRequest>()
    expect(proposalAttach2).toMatchObject({
      requested_attributes: {},
      requested_predicates: {
        [Object.keys(proposalAttach2.requested_predicates)[0]]: {
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
    })
    expect(faberProofExchangeRecord).toMatchObject({
      id: expect.anything(),
      threadId: faberProofExchangeRecord.threadId,
      state: ProofState.ProposalReceived,
      protocolVersion: 'v2',
    })

    // Accept Proposal
    testLogger.test('Faber accepts presentation proposal from Alice')
    faberProofExchangeRecord = await faberAgent.proofs.acceptProposal({
      proofRecordId: faberProofExchangeRecord.id,
    })

    testLogger.test('Alice waits for proof request from Faber')
    aliceProofExchangeRecord = await waitForProofExchangeRecordSubject(aliceReplay, {
      threadId: faberProofExchangeRecord.threadId,
      state: ProofState.RequestReceived,
      // Negotiation so this will be the second request
      count: 2,
    })

    const request2 = await faberAgent.proofs.findRequestMessage(faberProofExchangeRecord.id)
    expect(request2).toMatchObject({
      type: 'https://didcomm.org/present-proof/2.0/request-presentation',
      formats: [
        {
          attachmentId: expect.any(String),
          format: 'hlindy/proof-req@v2.0',
        },
      ],
      requestAttachments: [
        {
          id: expect.any(String),
          mimeType: 'application/json',
          data: {
            base64: expect.any(String),
          },
        },
      ],
      id: expect.any(String),
      thread: {
        threadId: faberProofExchangeRecord.threadId,
      },
    })
    expect(aliceProofExchangeRecord).toMatchObject({
      id: expect.anything(),
      threadId: faberProofExchangeRecord.threadId,
      state: ProofState.RequestReceived,
      protocolVersion: 'v2',
    })

    const proposalMessage = await aliceAgent.proofs.findProposalMessage(aliceProofExchangeRecord.id)
    expect(proposalMessage).toMatchObject({
      type: 'https://didcomm.org/present-proof/2.0/propose-presentation',
      formats: [
        {
          attachmentId: expect.any(String),
          format: 'hlindy/proof-req@v2.0',
        },
      ],
      proposalAttachments: [
        {
          id: expect.any(String),
          mimeType: 'application/json',
          data: {
            base64: expect.any(String),
          },
        },
      ],
      id: expect.any(String),
      comment: 'V2 propose proof test 2',
    })

    const proposalAttach3 = (
      proposal as V2ProposePresentationMessage
    )?.proposalAttachments[0].getDataAsJson<AnonCredsProofRequest>()
    expect(proposalAttach3).toMatchObject({
      requested_attributes: {},
      requested_predicates: {
        [Object.keys(proposalAttach3.requested_predicates ?? {})[0]]: {
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
    })

    const proofRequestMessage = (await aliceAgent.proofs.findRequestMessage(
      aliceProofExchangeRecord.id
    )) as V2RequestPresentationMessage

    const proofRequest = JsonTransformer.fromJSON(
      proofRequestMessage.requestAttachments[0].getDataAsJson(),
      AnonCredsProofRequestClass
    )
    const predicateKey = proofRequest.requestedPredicates?.keys().next().value

    expect(JsonTransformer.toJSON(proofRequest)).toMatchObject({
      name: 'proof-request',
      nonce: expect.any(String),
      version: '1.0',
      requested_attributes: {},
      requested_predicates: {
        [predicateKey]: {
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
    })
  })
})
