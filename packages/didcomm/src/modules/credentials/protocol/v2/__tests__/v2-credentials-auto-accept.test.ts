import type { AnonCredsTestsAgent } from '../../../../../../../anoncreds/tests/legacyAnonCredsSetup'
import type { EventReplaySubject } from '@credo-ts/core/tests'

import { setupAnonCredsTests } from '../../../../../../../anoncreds/tests/legacyAnonCredsSetup'
import { anoncredsDefinitionFourAttributesNoRevocation } from '../../../../../../../anoncreds/tests/preCreatedAnonCredsDefinition'
import {
  waitForCredentialRecord,
  waitForCredentialRecordSubject,
  waitForAgentMessageProcessedEventSubject,
} from '@credo-ts/core/tests/helpers'
import testLogger from '@credo-ts/core/tests/logger'
import { CredentialRole } from '../../../models'
import { AutoAcceptCredential } from '../../../models/CredentialAutoAcceptType'
import { CredentialState } from '../../../models/CredentialState'
import { CredentialExchangeRecord } from '../../../repository/CredentialExchangeRecord'
import { V2ProposeCredentialMessage } from '../messages'
import { V2CredentialPreview } from '../messages/V2CredentialPreview'

describe('V2 Credentials Auto Accept', () => {
  let faberAgent: AnonCredsTestsAgent
  let faberReplay: EventReplaySubject
  let aliceAgent: AnonCredsTestsAgent
  let aliceReplay: EventReplaySubject
  let credentialDefinitionId: string
  let schemaId: string
  let faberConnectionId: string
  let aliceConnectionId: string

  const credentialPreview = V2CredentialPreview.fromRecord({
    name: 'John',
    age: '99',
    'x-ray': 'some x-ray',
    profile_picture: 'profile picture',
  })
  const newCredentialPreview = V2CredentialPreview.fromRecord({
    name: 'John',
    age: '99',
    'x-ray': 'another x-ray value',
    profile_picture: 'another profile picture',
  })

  describe("Auto accept on 'always'", () => {
    beforeAll(async () => {
      ;({
        issuerAgent: faberAgent,
        issuerReplay: faberReplay,
        holderAgent: aliceAgent,
        holderReplay: aliceReplay,
        credentialDefinitionId,
        schemaId,
        issuerHolderConnectionId: faberConnectionId,
        holderIssuerConnectionId: aliceConnectionId,
      } = await setupAnonCredsTests({
        issuerName: 'faber agent: always v2',
        holderName: 'alice agent: always v2',
        autoAcceptCredentials: AutoAcceptCredential.Always,
        preCreatedDefinition: anoncredsDefinitionFourAttributesNoRevocation,
      }))
    })

    afterAll(async () => {
      await faberAgent.shutdown()
      await faberAgent.wallet.delete()
      await aliceAgent.shutdown()
      await aliceAgent.wallet.delete()
    })

    test("Alice starts with V2 credential proposal to Faber, both with autoAcceptCredential on 'always'", async () => {
      testLogger.test('Alice sends credential proposal to Faber')
      let aliceCredentialRecord = await aliceAgent.credentials.proposeCredential({
        connectionId: aliceConnectionId,
        protocolVersion: 'v2',
        credentialFormats: {
          anoncreds: {
            attributes: credentialPreview.attributes,
            credentialDefinitionId: credentialDefinitionId,
          },
        },
        comment: 'v2 propose credential test',
      })

      testLogger.test('Alice waits for credential from Faber')
      aliceCredentialRecord = await waitForCredentialRecordSubject(aliceReplay, {
        state: CredentialState.Done,
        threadId: aliceCredentialRecord.threadId,
      })

      testLogger.test('Faber waits for credential ack from Alice')
      await waitForCredentialRecordSubject(faberReplay, {
        state: CredentialState.Done,
        threadId: aliceCredentialRecord.threadId,
      })

      expect(aliceCredentialRecord).toMatchObject({
        type: CredentialExchangeRecord.type,
        id: expect.any(String),
        createdAt: expect.any(Date),
        metadata: {
          data: {
            '_anoncreds/credential': {
              schemaId,
              credentialDefinitionId: credentialDefinitionId,
            },
          },
        },
        state: CredentialState.Done,
      })
    })

    test("Faber starts with V2 credential offer to Alice, both with autoAcceptCredential on 'always'", async () => {
      testLogger.test('Faber sends credential offer to Alice')
      let faberCredentialRecord = await faberAgent.credentials.offerCredential({
        comment: 'some comment about credential',
        connectionId: faberConnectionId,
        credentialFormats: {
          anoncreds: {
            attributes: credentialPreview.attributes,
            credentialDefinitionId: credentialDefinitionId,
          },
        },
        protocolVersion: 'v2',
      })

      testLogger.test('Alice waits for credential from Faber')
      const aliceCredentialRecord = await waitForCredentialRecordSubject(aliceReplay, {
        state: CredentialState.CredentialReceived,
        threadId: faberCredentialRecord.threadId,
      })

      expect(aliceCredentialRecord).toMatchObject({
        type: CredentialExchangeRecord.type,
        id: expect.any(String),
        createdAt: expect.any(Date),
        metadata: {
          data: {
            '_anoncreds/credentialRequest': expect.any(Object),
            '_anoncreds/credential': {
              schemaId,
              credentialDefinitionId: credentialDefinitionId,
            },
          },
        },
        credentials: [
          {
            credentialRecordType: 'w3c',
            credentialRecordId: expect.any(String),
          },
        ],
        state: CredentialState.CredentialReceived,
      })

      testLogger.test('Faber waits for credential ack from Alice')
      faberCredentialRecord = await waitForCredentialRecordSubject(faberReplay, {
        state: CredentialState.Done,
        threadId: faberCredentialRecord.threadId,
      })
      expect(faberCredentialRecord).toMatchObject({
        type: CredentialExchangeRecord.type,
        id: expect.any(String),
        createdAt: expect.any(Date),
        state: CredentialState.Done,
      })
    })
  })

  describe("Auto accept on 'contentApproved'", () => {
    // FIXME: we don't need to set up the agent and create all schemas/credential definitions again, just change the auto accept credential setting
    beforeAll(async () => {
      ;({
        issuerAgent: faberAgent,
        issuerReplay: faberReplay,
        holderAgent: aliceAgent,
        holderReplay: aliceReplay,
        credentialDefinitionId,
        schemaId,
        issuerHolderConnectionId: faberConnectionId,
        holderIssuerConnectionId: aliceConnectionId,
      } = await setupAnonCredsTests({
        issuerName: 'Faber Agent: Always V2',
        holderName: 'Alice Agent: Always V2',
        autoAcceptCredentials: AutoAcceptCredential.ContentApproved,
        preCreatedDefinition: anoncredsDefinitionFourAttributesNoRevocation,
      }))
    })

    afterAll(async () => {
      await faberAgent.shutdown()
      await faberAgent.wallet.delete()
      await aliceAgent.shutdown()
      await aliceAgent.wallet.delete()
    })

    test("Alice starts with V2 credential proposal to Faber, both with autoAcceptCredential on 'contentApproved'", async () => {
      testLogger.test('Alice sends credential proposal to Faber')

      let aliceCredentialRecord = await aliceAgent.credentials.proposeCredential({
        connectionId: aliceConnectionId,
        protocolVersion: 'v2',
        credentialFormats: {
          anoncreds: {
            attributes: credentialPreview.attributes,
            credentialDefinitionId: credentialDefinitionId,
          },
        },
      })

      testLogger.test('Faber waits for credential proposal from Alice')
      let faberCredentialRecord = await waitForCredentialRecordSubject(faberReplay, {
        state: CredentialState.ProposalReceived,
        threadId: aliceCredentialRecord.threadId,
      })

      testLogger.test('Faber sends credential offer to Alice')
      await faberAgent.credentials.acceptProposal({
        credentialRecordId: faberCredentialRecord.id,
        comment: 'V2 Indy Offer',
        credentialFormats: {
          anoncreds: {
            credentialDefinitionId: credentialDefinitionId,
            attributes: credentialPreview.attributes,
          },
        },
      })

      testLogger.test('Alice waits for credential from Faber')
      aliceCredentialRecord = await waitForCredentialRecordSubject(aliceReplay, {
        state: CredentialState.Done,
        threadId: faberCredentialRecord.threadId,
      })

      faberCredentialRecord = await waitForCredentialRecord(faberAgent, {
        threadId: faberCredentialRecord.threadId,
        state: CredentialState.Done,
      })

      expect(aliceCredentialRecord).toMatchObject({
        type: CredentialExchangeRecord.type,
        id: expect.any(String),
        createdAt: expect.any(Date),
        metadata: {
          data: {
            '_anoncreds/credentialRequest': expect.any(Object),
            '_anoncreds/credential': {
              schemaId,
              credentialDefinitionId: credentialDefinitionId,
            },
          },
        },
        credentials: [
          {
            credentialRecordType: 'w3c',
            credentialRecordId: expect.any(String),
          },
        ],
        state: CredentialState.Done,
      })

      expect(faberCredentialRecord).toMatchObject({
        type: CredentialExchangeRecord.type,
        id: expect.any(String),
        createdAt: expect.any(Date),
        metadata: {
          data: {
            '_anoncreds/credential': {
              schemaId,
              credentialDefinitionId: credentialDefinitionId,
            },
          },
        },
        state: CredentialState.Done,
      })
    })

    test("Faber starts with V2 credential offer to Alice, both with autoAcceptCredential on 'contentApproved'", async () => {
      testLogger.test('Faber sends credential offer to Alice')
      let faberCredentialRecord = await faberAgent.credentials.offerCredential({
        comment: 'some comment about credential',
        connectionId: faberConnectionId,
        credentialFormats: {
          anoncreds: {
            attributes: credentialPreview.attributes,
            credentialDefinitionId: credentialDefinitionId,
          },
        },
        protocolVersion: 'v2',
      })

      testLogger.test('Alice waits for credential offer from Faber')
      let aliceCredentialRecord = await waitForCredentialRecordSubject(aliceReplay, {
        state: CredentialState.OfferReceived,
        threadId: faberCredentialRecord.threadId,
      })

      // below values are not in json object
      expect(aliceCredentialRecord.id).not.toBeNull()
      expect(aliceCredentialRecord.getTags()).toEqual({
        threadId: aliceCredentialRecord.threadId,
        state: aliceCredentialRecord.state,
        connectionId: aliceConnectionId,
        role: CredentialRole.Holder,
        credentialIds: [],
      })
      testLogger.test('Alice received credential offer from Faber')

      testLogger.test('alice sends credential request to faber')
      await aliceAgent.credentials.acceptOffer({
        credentialRecordId: aliceCredentialRecord.id,
      })

      testLogger.test('Alice waits for credential from Faber')
      aliceCredentialRecord = await waitForCredentialRecordSubject(aliceReplay, {
        state: CredentialState.Done,
        threadId: faberCredentialRecord.threadId,
      })

      expect(aliceCredentialRecord).toMatchObject({
        type: CredentialExchangeRecord.type,
        id: expect.any(String),
        createdAt: expect.any(Date),
        metadata: {
          data: {
            '_anoncreds/credentialRequest': expect.any(Object),
            '_anoncreds/credential': {
              schemaId,
              credentialDefinitionId: credentialDefinitionId,
            },
          },
        },
        credentials: [
          {
            credentialRecordType: 'w3c',
            credentialRecordId: expect.any(String),
          },
        ],
        state: CredentialState.Done,
      })

      testLogger.test('Faber waits for credential ack from Alice')

      faberCredentialRecord = await waitForCredentialRecordSubject(faberReplay, {
        threadId: faberCredentialRecord.threadId,
        state: CredentialState.Done,
      })

      expect(faberCredentialRecord).toMatchObject({
        type: CredentialExchangeRecord.type,
        id: expect.any(String),
        createdAt: expect.any(Date),
        state: CredentialState.Done,
      })
    })

    test("Alice starts with V2 credential proposal to Faber, both have autoAcceptCredential on 'contentApproved' and attributes did change", async () => {
      testLogger.test('Alice sends credential proposal to Faber')
      let aliceCredentialRecord = await aliceAgent.credentials.proposeCredential({
        connectionId: aliceConnectionId,
        protocolVersion: 'v2',
        credentialFormats: {
          anoncreds: {
            attributes: credentialPreview.attributes,
            credentialDefinitionId: credentialDefinitionId,
          },
        },
        comment: 'v2 propose credential test',
      })
      expect(aliceCredentialRecord.state).toBe(CredentialState.ProposalSent)

      testLogger.test('Faber waits for credential proposal from Alice')
      let faberCredentialRecord = await waitForCredentialRecordSubject(faberReplay, {
        state: CredentialState.ProposalReceived,
        threadId: aliceCredentialRecord.threadId,
      })

      testLogger.test('Faber negotiated proposal, sending credential offer to Alice')
      faberCredentialRecord = await faberAgent.credentials.negotiateProposal({
        credentialRecordId: faberCredentialRecord.id,
        credentialFormats: {
          anoncreds: {
            credentialDefinitionId: credentialDefinitionId,
            attributes: newCredentialPreview.attributes,
          },
        },
      })

      testLogger.test('Alice waits for credential offer from Faber')
      aliceCredentialRecord = await waitForCredentialRecordSubject(aliceReplay, {
        state: CredentialState.OfferReceived,
        threadId: faberCredentialRecord.threadId,
      })

      // below values are not in json object
      expect(aliceCredentialRecord.id).not.toBeNull()
      expect(aliceCredentialRecord.getTags()).toEqual({
        threadId: aliceCredentialRecord.threadId,
        state: aliceCredentialRecord.state,
        connectionId: aliceConnectionId,
        role: CredentialRole.Holder,
        credentialIds: [],
      })
    })

    test("Faber starts with V2 credential offer to Alice, both have autoAcceptCredential on 'contentApproved' and attributes did change", async () => {
      testLogger.test('Faber sends credential offer to Alice')
      const faberCredentialRecord = await faberAgent.credentials.offerCredential({
        comment: 'some comment about credential',
        connectionId: faberConnectionId,
        credentialFormats: {
          anoncreds: {
            attributes: credentialPreview.attributes,
            credentialDefinitionId: credentialDefinitionId,
          },
        },
        protocolVersion: 'v2',
      })

      testLogger.test('Alice waits for credential offer from Faber')
      const aliceCredentialRecord = await waitForCredentialRecordSubject(aliceReplay, {
        state: CredentialState.OfferReceived,
        threadId: faberCredentialRecord.threadId,
      })

      // below values are not in json object
      expect(aliceCredentialRecord.id).not.toBeNull()
      expect(aliceCredentialRecord.getTags()).toEqual({
        threadId: aliceCredentialRecord.threadId,
        state: aliceCredentialRecord.state,
        connectionId: aliceConnectionId,
        role: CredentialRole.Holder,
        credentialIds: [],
      })

      testLogger.test('Alice sends credential request to Faber')
      await aliceAgent.credentials.negotiateOffer({
        credentialRecordId: aliceCredentialRecord.id,
        credentialFormats: {
          anoncreds: {
            attributes: newCredentialPreview.attributes,
            credentialDefinitionId: credentialDefinitionId,
          },
        },
        comment: 'v2 propose credential test',
      })

      await waitForCredentialRecordSubject(faberReplay, {
        state: CredentialState.ProposalReceived,
        threadId: aliceCredentialRecord.threadId,
      })

      // ProposalReceived is emitted before the whole message is finished processing
      // So to not get errors when shutting down the agent, we wait for the message to be processed
      await waitForAgentMessageProcessedEventSubject(faberReplay, {
        threadId: aliceCredentialRecord.threadId,
        messageType: V2ProposeCredentialMessage.type.messageTypeUri,
      })
    })
  })
})
