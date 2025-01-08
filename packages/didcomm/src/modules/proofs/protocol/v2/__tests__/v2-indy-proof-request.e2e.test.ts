import type { AnonCredsTestsAgent } from '../../../../../../../anoncreds/tests/legacyAnonCredsSetup'
import type { EventReplaySubject } from '../../../../../../tests'

import {
  issueLegacyAnonCredsCredential,
  setupAnonCredsTests,
} from '../../../../../../../anoncreds/tests/legacyAnonCredsSetup'
import { waitForProofExchangeRecordSubject } from '../../../../../../tests'
import testLogger from '../../../../../../tests/logger'
import { ProofState } from '../../../models/ProofState'

describe('V2 Proofs - Indy', () => {
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

  test(`Alice Creates and sends Proof Proposal to Faber`, async () => {
    testLogger.test('Alice sends proof proposal to Faber')

    let aliceProofExchangeRecord = await aliceAgent.proofs.proposeProof({
      connectionId: aliceConnectionId,
      protocolVersion: 'v2',
      proofFormats: {
        indy: {
          name: 'ProofRequest',
          version: '1.0',
          attributes: [
            {
              name: 'name',
              value: 'Alice',
              credentialDefinitionId,
            },
          ],
          predicates: [
            {
              credentialDefinitionId,
              name: 'age',
              predicate: '>=',
              threshold: 18,
            },
          ],
        },
      },
      comment: 'V2 propose proof test',
    })

    testLogger.test('Faber waits for presentation from Alice')
    let faberProofExchangeRecord = await waitForProofExchangeRecordSubject(faberReplay, {
      state: ProofState.ProposalReceived,
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
      comment: 'V2 propose proof test',
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
    })

    const request = await faberAgent.proofs.findRequestMessage(faberProofExchangeRecord.id)
    expect(request).toMatchObject({
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
  })
})
