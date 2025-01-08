import type { AnonCredsTestsAgent } from '../../../../../../../anoncreds/tests/legacyAnonCredsSetup'
import type { EventReplaySubject } from '../../../../../../tests'

import {
  issueLegacyAnonCredsCredential,
  setupAnonCredsTests,
} from '../../../../../../../anoncreds/tests/legacyAnonCredsSetup'
import { waitForProofExchangeRecord, testLogger } from '../../../../../../tests'
import { AutoAcceptProof, ProofState } from '../../../models'

describe('Auto accept present proof', () => {
  let faberAgent: AnonCredsTestsAgent
  let faberReplay: EventReplaySubject
  let aliceAgent: AnonCredsTestsAgent
  let aliceReplay: EventReplaySubject
  let credentialDefinitionId: string
  let faberConnectionId: string
  let aliceConnectionId: string

  describe("Auto accept on 'always'", () => {
    beforeAll(async () => {
      ;({
        issuerAgent: faberAgent,
        issuerReplay: faberReplay,
        holderAgent: aliceAgent,
        holderReplay: aliceReplay,
        credentialDefinitionId,
        issuerHolderConnectionId: faberConnectionId,
        holderIssuerConnectionId: aliceConnectionId,
      } = await setupAnonCredsTests({
        issuerName: 'Faber Auto Accept Always Proofs',
        holderName: 'Alice Auto Accept Always Proofs',
        attributeNames: ['name', 'age'],
        autoAcceptProofs: AutoAcceptProof.Always,
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
      await faberAgent.shutdown()
      await faberAgent.wallet.delete()
      await aliceAgent.shutdown()
      await aliceAgent.wallet.delete()
    })

    test("Alice starts with proof proposal to Faber, both with autoAcceptProof on 'always'", async () => {
      testLogger.test('Alice sends presentation proposal to Faber')

      await aliceAgent.proofs.proposeProof({
        connectionId: aliceConnectionId,
        protocolVersion: 'v2',
        proofFormats: {
          indy: {
            name: 'abc',
            version: '1.0',
            attributes: [
              {
                credentialDefinitionId,
                name: 'name',
                value: 'Alice',
              },
            ],
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
      })

      testLogger.test('Faber waits for presentation from Alice')
      testLogger.test('Alice waits till it receives presentation ack')
      await Promise.all([
        waitForProofExchangeRecord(faberAgent, { state: ProofState.Done }),
        waitForProofExchangeRecord(aliceAgent, { state: ProofState.Done }),
      ])
    })

    test("Faber starts with proof requests to Alice, both with autoAcceptProof on 'always'", async () => {
      testLogger.test('Faber sends presentation request to Alice')

      await faberAgent.proofs.requestProof({
        protocolVersion: 'v2',
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

      testLogger.test('Alice waits for presentation from Faber')
      testLogger.test('Faber waits till it receives presentation ack')
      await Promise.all([
        waitForProofExchangeRecord(faberAgent, { state: ProofState.Done }),
        waitForProofExchangeRecord(aliceAgent, { state: ProofState.Done }),
      ])
    })
  })

  describe("Auto accept on 'contentApproved'", () => {
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
        issuerName: 'Faber Auto Accept ContentApproved Proofs',
        holderName: 'Alice Auto Accept ContentApproved Proofs',
        attributeNames: ['name', 'age'],
        autoAcceptProofs: AutoAcceptProof.ContentApproved,
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

    test("Alice starts with proof proposal to Faber, both with autoAcceptProof on 'contentApproved'", async () => {
      testLogger.test('Alice sends presentation proposal to Faber')

      const faberProofExchangeRecordPromise = waitForProofExchangeRecord(faberAgent, {
        state: ProofState.ProposalReceived,
      })

      await aliceAgent.proofs.proposeProof({
        connectionId: aliceConnectionId,
        protocolVersion: 'v2',
        proofFormats: {
          indy: {
            name: 'abc',
            version: '1.0',
            attributes: [
              {
                credentialDefinitionId,
                name: 'name',
                value: 'Alice',
              },
            ],
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
      })

      const faberProofExchangeRecord = await faberProofExchangeRecordPromise
      await faberAgent.proofs.acceptProposal({
        proofRecordId: faberProofExchangeRecord.id,
      })

      await Promise.all([
        waitForProofExchangeRecord(aliceAgent, { state: ProofState.Done }),
        waitForProofExchangeRecord(faberAgent, { state: ProofState.Done }),
      ])
    })

    test("Faber starts with proof requests to Alice, both with autoAcceptProof on 'contentApproved'", async () => {
      testLogger.test('Faber sends presentation request to Alice')

      const aliceProofExchangeRecordPromise = waitForProofExchangeRecord(aliceAgent, {
        state: ProofState.RequestReceived,
      })

      await faberAgent.proofs.requestProof({
        protocolVersion: 'v2',
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

      const aliceProofExchangeRecord = await aliceProofExchangeRecordPromise
      await aliceAgent.proofs.acceptRequest({
        proofRecordId: aliceProofExchangeRecord.id,
      })

      await Promise.all([
        waitForProofExchangeRecord(faberAgent, { state: ProofState.Done }),
        waitForProofExchangeRecord(aliceAgent, { state: ProofState.Done }),
      ])
    })
  })
})
