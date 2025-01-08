import type { Agent } from '../../../../../agent/Agent'

import {
  setupAnonCredsTests,
  issueLegacyAnonCredsCredential,
} from '../../../../../../../anoncreds/tests/legacyAnonCredsSetup'
import { testLogger, waitForProofExchangeRecordSubject } from '../../../../../../tests'
import { AutoAcceptProof, ProofState } from '../../../models'
import { V2PresentationMessage, V2ProposePresentationMessage, V2RequestPresentationMessage } from '../messages'

describe('V2 OOB Proposal Proposal - Indy', () => {
  let agents: Agent[]

  afterEach(async () => {
    for (const agent of agents) {
      await agent.shutdown()
      await agent.wallet.delete()
    }
  })

  test('Alice start with oob proof proposal for Faber with aut-accept enabled', async () => {
    const {
      issuerAgent: faberAgent,
      issuerReplay: faberReplay,
      holderAgent: aliceAgent,
      holderReplay: aliceReplay,
      credentialDefinitionId,
      issuerHolderConnectionId: faberConnectionId,
    } = await setupAnonCredsTests({
      issuerName: 'Faber oob Proofs proposal v2 - Auto Accept',
      holderName: 'Alice oob Proofs proposal v2 - Auto Accept',
      autoAcceptProofs: AutoAcceptProof.Always,
      attributeNames: ['name', 'age'],
    })
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
    agents = [aliceAgent, faberAgent]
    testLogger.test('Alice creates oob proof proposal for faber')
    const { message } = await aliceAgent.proofs.createProofProposal({
      protocolVersion: 'v2',
      proofFormats: {
        indy: {
          name: 'abc',
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
              name: 'age',
              predicate: '>=',
              threshold: 50,
              credentialDefinitionId,
            },
          ],
        },
      },
      autoAcceptProof: AutoAcceptProof.ContentApproved,
    })
    const { outOfBandInvitation } = await aliceAgent.oob.createInvitation({
      messages: [message],
      autoAcceptConnection: true,
    })
    await faberAgent.oob.receiveInvitation(outOfBandInvitation)

    const aliceProofExchangeRecord = await waitForProofExchangeRecordSubject(aliceReplay, {
      state: ProofState.Done,
    })
    await waitForProofExchangeRecordSubject(faberReplay, {
      state: ProofState.Done,
    })
    expect(aliceProofExchangeRecord.connectionId).not.toBeNull()
    const proposalMessage = await aliceAgent.proofs.findProposalMessage(aliceProofExchangeRecord.id)
    const requestMessage = await aliceAgent.proofs.findRequestMessage(aliceProofExchangeRecord.id)
    const presentationMessage = await aliceAgent.proofs.findPresentationMessage(aliceProofExchangeRecord.id)
    expect(proposalMessage).toBeInstanceOf(V2ProposePresentationMessage)
    expect(requestMessage).toBeInstanceOf(V2RequestPresentationMessage)
    expect(presentationMessage).toBeInstanceOf(V2PresentationMessage)
  })
})
