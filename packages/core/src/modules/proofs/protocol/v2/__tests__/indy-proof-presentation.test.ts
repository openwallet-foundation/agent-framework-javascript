import type { Agent } from '../../../../../agent/Agent'
import type { ConnectionRecord } from '../../../../connections/repository/ConnectionRecord'
import type { ProposeProofOptions, AcceptProposalOptions } from '../../../ProofsApiOptions'
import type { IndyProofFormat } from '../../../formats/indy/IndyProofFormat'
import type { ProofRecord } from '../../../repository/ProofRecord'
import type { PresentationPreview } from '../../v1/models/V1PresentationPreview'
import type { V2ProofService } from '../V2ProofService'

import { setupProofsTest, waitForProofRecord } from '../../../../../../tests/helpers'
import testLogger from '../../../../../../tests/logger'
import { DidCommMessageRepository } from '../../../../../storage'
import {
  V2_INDY_PRESENTATION_PROPOSAL,
  V2_INDY_PRESENTATION_REQUEST,
  V2_INDY_PRESENTATION,
} from '../../../formats/ProofFormatConstants'
import { ProofState } from '../../../models/ProofState'
import { V2PresentationMessage, V2RequestPresentationMessage } from '../messages'
import { V2ProposalPresentationMessage } from '../messages/V2ProposalPresentationMessage'

describe('Present Proof', () => {
  let faberAgent: Agent
  let aliceAgent: Agent
  let aliceConnection: ConnectionRecord
  let presentationPreview: PresentationPreview
  let faberProofRecord: ProofRecord
  let aliceProofRecord: ProofRecord
  let didCommMessageRepository: DidCommMessageRepository

  beforeAll(async () => {
    testLogger.test('Initializing the agents')
    ;({ faberAgent, aliceAgent, aliceConnection, presentationPreview } = await setupProofsTest(
      'Faber agent',
      'Alice agent'
    ))
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

    const proposeOptions: ProposeProofOptions<[IndyProofFormat], [V2ProofService]> = {
      connectionId: aliceConnection.id,
      protocolVersion: 'v2',
      proofFormats: {
        indy: {
          name: 'ProofRequest',
          nonce: '947121108704767252195126',
          version: '1.0',
          attributes: presentationPreview.attributes,
          predicates: presentationPreview.predicates,
        },
      },
      comment: 'V2 propose proof test',
    }

    const faberPresentationRecordPromise = waitForProofRecord(faberAgent, {
      state: ProofState.ProposalReceived,
    })

    aliceProofRecord = await aliceAgent.proofs.proposeProof(proposeOptions)

    testLogger.test('Faber waits for presentation from Alice')
    faberProofRecord = await faberPresentationRecordPromise

    didCommMessageRepository = faberAgent.injectionContainer.resolve<DidCommMessageRepository>(DidCommMessageRepository)

    const proposal = await didCommMessageRepository.findAgentMessage(faberAgent.context, {
      associatedRecordId: faberProofRecord.id,
      messageClass: V2ProposalPresentationMessage,
    })

    expect(proposal).toMatchObject({
      type: 'https://didcomm.org/present-proof/2.0/propose-presentation',
      formats: [
        {
          attachmentId: expect.any(String),
          format: V2_INDY_PRESENTATION_PROPOSAL,
        },
      ],
      proposalsAttach: [
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
    expect(faberProofRecord).toMatchObject({
      id: expect.anything(),
      threadId: faberProofRecord.threadId,
      state: ProofState.ProposalReceived,
      protocolVersion: 'v2',
    })
  })

  test(`Faber accepts the Proposal send by Alice`, async () => {
    // Accept Proposal
    const acceptProposalOptions: AcceptProposalOptions = {
      proofRecordId: faberProofRecord.id,
    }

    const alicePresentationRecordPromise = waitForProofRecord(aliceAgent, {
      threadId: faberProofRecord.threadId,
      state: ProofState.RequestReceived,
    })

    testLogger.test('Faber accepts presentation proposal from Alice')
    faberProofRecord = await faberAgent.proofs.acceptProposal(acceptProposalOptions)

    testLogger.test('Alice waits for proof request from Faber')
    aliceProofRecord = await alicePresentationRecordPromise

    didCommMessageRepository = faberAgent.injectionContainer.resolve<DidCommMessageRepository>(DidCommMessageRepository)

    const request = await didCommMessageRepository.findAgentMessage(faberAgent.context, {
      associatedRecordId: faberProofRecord.id,
      messageClass: V2RequestPresentationMessage,
    })

    expect(request).toMatchObject({
      type: 'https://didcomm.org/present-proof/2.0/request-presentation',
      formats: [
        {
          attachmentId: expect.any(String),
          format: V2_INDY_PRESENTATION_REQUEST,
        },
      ],
      requestPresentationsAttach: [
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
        threadId: faberProofRecord.threadId,
      },
    })
    expect(aliceProofRecord).toMatchObject({
      id: expect.anything(),
      threadId: faberProofRecord.threadId,
      state: ProofState.RequestReceived,
      protocolVersion: 'v2',
    })
  })

  test(`Alice accepts presentation request from Faber`, async () => {
    // Alice retrieves the requested credentials and accepts the presentation request
    testLogger.test('Alice accepts presentation request from Faber')

    const requestedCredentials = await aliceAgent.proofs.autoSelectCredentialsForProofRequest({
      proofRecordId: aliceProofRecord.id,
      config: {
        filterByPresentationPreview: true,
      },
    })

    const faberPresentationRecordPromise = waitForProofRecord(faberAgent, {
      threadId: aliceProofRecord.threadId,
      state: ProofState.PresentationReceived,
    })

    await aliceAgent.proofs.acceptRequest({
      proofRecordId: aliceProofRecord.id,
      proofFormats: { indy: requestedCredentials.proofFormats.indy },
    })

    // Faber waits for the presentation from Alice
    testLogger.test('Faber waits for presentation from Alice')
    faberProofRecord = await faberPresentationRecordPromise

    const presentation = await didCommMessageRepository.findAgentMessage(faberAgent.context, {
      associatedRecordId: faberProofRecord.id,
      messageClass: V2PresentationMessage,
    })

    expect(presentation).toMatchObject({
      type: 'https://didcomm.org/present-proof/2.0/presentation',
      formats: [
        {
          attachmentId: expect.any(String),
          format: V2_INDY_PRESENTATION,
        },
      ],
      presentationsAttach: [
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
        threadId: faberProofRecord.threadId,
      },
    })
    expect(faberProofRecord.id).not.toBeNull()
    expect(faberProofRecord).toMatchObject({
      threadId: faberProofRecord.threadId,
      state: ProofState.PresentationReceived,
      protocolVersion: 'v2',
    })
  })

  test(`Faber accepts the presentation provided by Alice`, async () => {
    const aliceProofRecordPromise = waitForProofRecord(aliceAgent, {
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
      // type: ProofRecord.name,
      id: expect.any(String),
      createdAt: expect.any(Date),
      threadId: aliceProofRecord.threadId,
      connectionId: expect.any(String),
      isVerified: true,
      state: ProofState.PresentationReceived,
    })

    expect(aliceProofRecord).toMatchObject({
      // type: ProofRecord.name,
      id: expect.any(String),
      createdAt: expect.any(Date),
      threadId: faberProofRecord.threadId,
      connectionId: expect.any(String),
      state: ProofState.Done,
    })
  })
})
