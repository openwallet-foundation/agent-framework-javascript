import type { Agent, ConnectionRecord } from '../src'
import type { ProposeProofOptions, RequestProofOptions } from '../src/modules/proofs/ProofsApiOptions'
import type { IndyProofFormat } from '../src/modules/proofs/formats/indy/IndyProofFormat'
import type { V1ProofService } from '../src/modules/proofs/protocol/v1/V1ProofService'
import type { PresentationPreview } from '../src/modules/proofs/protocol/v1/models/V1PresentationPreview'

import {
  AutoAcceptProof,
  ProofState,
  ProofAttributeInfo,
  AttributeFilter,
  ProofPredicateInfo,
  PredicateType,
} from '../src'
import { ProofProtocolVersion } from '../src/modules/proofs/models/ProofProtocolVersion'

import { setupProofsTest, waitForProofRecord } from './helpers'
import testLogger from './logger'

describe('Auto accept present proof', () => {
  let faberAgent: Agent
  let aliceAgent: Agent
  let credDefId: string
  let faberConnection: ConnectionRecord
  let aliceConnection: ConnectionRecord
  let presentationPreview: PresentationPreview

  describe('Auto accept on `always`', () => {
    beforeAll(async () => {
      ;({ faberAgent, aliceAgent, credDefId, faberConnection, aliceConnection, presentationPreview } =
        await setupProofsTest(
          'Faber Auto Accept Always Proofs',
          'Alice Auto Accept Always Proofs',
          AutoAcceptProof.Always
        ))
    })
    afterAll(async () => {
      await faberAgent.shutdown()
      await faberAgent.wallet.delete()
      await aliceAgent.shutdown()
      await aliceAgent.wallet.delete()
    })

    test('Alice starts with proof proposal to Faber, both with autoAcceptProof on `always`', async () => {
      testLogger.test('Alice sends presentation proposal to Faber')

      const proposeProofOptions: ProposeProofOptions<[IndyProofFormat], [V1ProofService]> = {
        connectionId: aliceConnection.id,
        protocolVersion: 'v1',
        proofFormats: {
          indy: {
            nonce: '58d223e5-fc4d-4448-b74c-5eb11c6b558f',
            name: 'abc',
            version: '1.0',
            attributes: presentationPreview.attributes,
            predicates: presentationPreview.predicates,
          },
        },
      }

      const faberProofRecordPromise = waitForProofRecord(faberAgent, {
        state: ProofState.Done,
      })

      const aliceProofRecordPromise = waitForProofRecord(aliceAgent, {
        state: ProofState.Done,
      })

      await aliceAgent.proofs.proposeProof(proposeProofOptions)

      testLogger.test('Faber waits for presentation from Alice')
      await faberProofRecordPromise

      testLogger.test('Alice waits till it receives presentation ack')
      await aliceProofRecordPromise
    })

    test('Faber starts with proof requests to Alice, both with autoAcceptProof on `always`', async () => {
      testLogger.test('Faber sends presentation request to Alice')
      const attributes = {
        name: new ProofAttributeInfo({
          name: 'name',
          restrictions: [
            new AttributeFilter({
              credentialDefinitionId: credDefId,
            }),
          ],
        }),
      }
      const predicates = {
        age: new ProofPredicateInfo({
          name: 'age',
          predicateType: PredicateType.GreaterThanOrEqualTo,
          predicateValue: 50,
          restrictions: [
            new AttributeFilter({
              credentialDefinitionId: credDefId,
            }),
          ],
        }),
      }

      const requestProofsOptions = {
        protocolVersion: ProofProtocolVersion.V1,
        connectionId: faberConnection.id,
        proofFormats: {
          indy: {
            name: 'proof-request',
            version: '1.0',
            nonce: '1298236324864',
            requestedAttributes: attributes,
            requestedPredicates: predicates,
          },
        },
      }
      const faberProofRecordPromise = waitForProofRecord(faberAgent, {
        state: ProofState.Done,
      })

      const aliceProofRecordPromise = waitForProofRecord(aliceAgent, {
        state: ProofState.Done,
      })

      await faberAgent.proofs.requestProof(requestProofsOptions)

      testLogger.test('Faber waits for presentation from Alice')

      await faberProofRecordPromise

      // Alice waits till it receives presentation ack
      await aliceProofRecordPromise
    })
  })

  describe('Auto accept on `contentApproved`', () => {
    beforeAll(async () => {
      testLogger.test('Initializing the agents')
      ;({ faberAgent, aliceAgent, credDefId, faberConnection, aliceConnection, presentationPreview } =
        await setupProofsTest(
          'Faber Auto Accept Content Approved Proofs',
          'Alice Auto Accept Content Approved Proofs',
          AutoAcceptProof.ContentApproved
        ))
    })
    afterAll(async () => {
      testLogger.test('Shutting down both agents')
      await faberAgent.shutdown()
      await faberAgent.wallet.delete()
      await aliceAgent.shutdown()
      await aliceAgent.wallet.delete()
    })

    test('Alice starts with proof proposal to Faber, both with autoacceptproof on `contentApproved`', async () => {
      testLogger.test('Alice sends presentation proposal to Faber')

      const proposal: ProposeProofOptions<[IndyProofFormat], [V1ProofService]> = {
        connectionId: aliceConnection.id,
        protocolVersion: ProofProtocolVersion.V1,
        proofFormats: {
          indy: {
            nonce: '1298236324864',
            name: 'abc',
            version: '1.0',
            attributes: presentationPreview.attributes,
            predicates: presentationPreview.predicates,
          },
        },
      }

      let faberProofRecordPromise = waitForProofRecord(faberAgent, {
        state: ProofState.ProposalReceived,
      })

      const aliceProofRecord = await aliceAgent.proofs.proposeProof(proposal)

      testLogger.test('Faber waits for presentation proposal from Alice')

      await faberProofRecordPromise

      testLogger.test('Faber accepts presentation proposal from Alice')

      faberProofRecordPromise = waitForProofRecord(faberAgent, {
        threadId: aliceProofRecord.threadId,
        state: ProofState.Done,
      })

      const aliceProofRecordPromise = waitForProofRecord(aliceAgent, {
        threadId: aliceProofRecord.threadId,
        state: ProofState.Done,
      })

      testLogger.test('Faber waits for presentation from Alice')

      await faberProofRecordPromise
      // Alice waits till it receives presentation ack
      await aliceProofRecordPromise
    })

    test('Faber starts with proof requests to Alice, both with autoacceptproof on `contentApproved`', async () => {
      testLogger.test('Faber sends presentation request to Alice')
      const attributes = {
        name: new ProofAttributeInfo({
          name: 'name',
          restrictions: [
            new AttributeFilter({
              credentialDefinitionId: credDefId,
            }),
          ],
        }),
      }
      const predicates = {
        age: new ProofPredicateInfo({
          name: 'age',
          predicateType: PredicateType.GreaterThanOrEqualTo,
          predicateValue: 50,
          restrictions: [
            new AttributeFilter({
              credentialDefinitionId: credDefId,
            }),
          ],
        }),
      }

      const requestProofsOptions: RequestProofOptions<[IndyProofFormat], [V1ProofService]> = {
        protocolVersion: ProofProtocolVersion.V1,
        connectionId: faberConnection.id,
        proofFormats: {
          indy: {
            name: 'proof-request',
            version: '1.0',
            nonce: '1298236324866',
            requestedAttributes: attributes,
            requestedPredicates: predicates,
          },
        },
      }

      const faberProofRecordPromise = waitForProofRecord(faberAgent, {
        state: ProofState.Done,
      })

      const aliceProofRecordPromise = waitForProofRecord(aliceAgent, {
        state: ProofState.Done,
      })

      await faberAgent.proofs.requestProof(requestProofsOptions)

      testLogger.test('Faber waits for presentation from Alice')
      await faberProofRecordPromise

      // Alice waits till it receives presentation ack
      await aliceProofRecordPromise
    })
  })
})
