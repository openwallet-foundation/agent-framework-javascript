import type { AnonCredsTestsAgent } from '../../../../../tests/legacyAnonCredsSetup'
import type { AcceptCredentialOfferOptions } from '@aries-framework/core'

import {
  AutoAcceptCredential,
  CredentialState,
  CredentialExchangeRecord,
  JsonTransformer,
  AriesFrameworkError,
} from '@aries-framework/core'

import { waitForCredentialRecord } from '../../../../../../core/tests/helpers'
import testLogger from '../../../../../../core/tests/logger'
import { setupAnonCredsTests } from '../../../../../tests/legacyAnonCredsSetup'
import { V1CredentialPreview } from '../messages'

const credentialPreview = V1CredentialPreview.fromRecord({
  name: 'John',
  age: '99',
  'x-ray': 'some x-ray',
  profile_picture: 'profile picture',
})
const newCredentialPreview = V1CredentialPreview.fromRecord({
  name: 'John',
  age: '99',
  'x-ray': 'another x-ray value',
  profile_picture: 'another profile picture',
})

describe('V1 Credentials Auto Accept', () => {
  let faberAgent: AnonCredsTestsAgent
  let aliceAgent: AnonCredsTestsAgent
  let credentialDefinitionId: string
  let schemaId: string
  let faberConnectionId: string
  let aliceConnectionId: string

  describe('Auto accept on `always`', () => {
    beforeAll(async () => {
      ;({
        issuerAgent: faberAgent,
        holderAgent: aliceAgent,
        credentialDefinitionId,
        issuerHolderConnectionId: faberConnectionId,
        holderIssuerConnectionId: aliceConnectionId,
      } = await setupAnonCredsTests({
        issuerName: 'faber agent: always v1',
        holderName: 'alice agent: always v1',
        // Not needed for this test
        verifierName: 'verifier agent: always v1',
        autoAcceptCredentials: AutoAcceptCredential.Always,
      }))
    })

    afterAll(async () => {
      await faberAgent.shutdown()
      await faberAgent.wallet.delete()
      await aliceAgent.shutdown()
      await aliceAgent.wallet.delete()
    })

    test('Alice starts with V1 credential proposal to Faber, both with autoAcceptCredential on `always`', async () => {
      testLogger.test('Alice sends credential proposal to Faber')

      const aliceCredentialExchangeRecord = await aliceAgent.credentials.proposeCredential({
        connectionId: aliceConnectionId,
        protocolVersion: 'v1',
        credentialFormats: {
          indy: {
            attributes: credentialPreview.attributes,
            credentialDefinitionId: credentialDefinitionId,
          },
        },
        comment: 'v1 propose credential test',
      })

      testLogger.test('Alice waits for credential from Faber')
      let aliceCredentialRecord = await waitForCredentialRecord(aliceAgent, {
        threadId: aliceCredentialExchangeRecord.threadId,
        state: CredentialState.CredentialReceived,
      })

      testLogger.test('Faber waits for credential ack from Alice')
      aliceCredentialRecord = await waitForCredentialRecord(faberAgent, {
        threadId: aliceCredentialRecord.threadId,
        state: CredentialState.Done,
      })

      expect(aliceCredentialRecord).toMatchObject({
        type: CredentialExchangeRecord.type,
        id: expect.any(String),
        createdAt: expect.any(Date),
        metadata: {
          data: {
            '_internal/indyCredential': {
              schemaId: schemaId,
              credentialDefinitionId: credentialDefinitionId,
            },
          },
        },
        state: CredentialState.Done,
      })
    })

    test('Faber starts with V1 credential offer to Alice, both with autoAcceptCredential on `always`', async () => {
      testLogger.test('Faber sends credential offer to Alice')
      const faberCredentialExchangeRecord = await faberAgent.credentials.offerCredential({
        comment: 'some comment about credential',
        connectionId: faberConnectionId,
        credentialFormats: {
          indy: {
            attributes: credentialPreview.attributes,
            credentialDefinitionId: credentialDefinitionId,
          },
        },
        protocolVersion: 'v1',
      })
      testLogger.test('Alice waits for credential from Faber')
      const aliceCredentialRecord = await waitForCredentialRecord(aliceAgent, {
        threadId: faberCredentialExchangeRecord.threadId,
        state: CredentialState.CredentialReceived,
      })
      testLogger.test('Faber waits for credential ack from Alice')
      const faberCredentialRecord: CredentialExchangeRecord = await waitForCredentialRecord(faberAgent, {
        threadId: faberCredentialExchangeRecord.threadId,
        state: CredentialState.Done,
      })
      expect(aliceCredentialRecord).toMatchObject({
        type: CredentialExchangeRecord.type,
        id: expect.any(String),
        createdAt: expect.any(Date),
        metadata: {
          data: {
            '_internal/indyRequest': expect.any(Object),
            '_internal/indyCredential': {
              schemaId,
              credentialDefinitionId,
            },
          },
        },
        credentials: [
          {
            credentialRecordType: 'indy',
            credentialRecordId: expect.any(String),
          },
        ],
        state: CredentialState.CredentialReceived,
      })
      expect(faberCredentialRecord).toMatchObject({
        type: CredentialExchangeRecord.type,
        id: expect.any(String),
        createdAt: expect.any(Date),
        state: CredentialState.Done,
      })
    })
  })

  describe('Auto accept on `contentApproved`', () => {
    beforeAll(async () => {
      ;({
        issuerAgent: faberAgent,
        holderAgent: aliceAgent,
        credentialDefinitionId,
        issuerHolderConnectionId: faberConnectionId,
        holderIssuerConnectionId: aliceConnectionId,
      } = await setupAnonCredsTests({
        issuerName: 'faber agent: contentApproved v1',
        holderName: 'alice agent: contentApproved v1',
        // Not needed for this test
        verifierName: 'verifier agent: always v1',
        autoAcceptCredentials: AutoAcceptCredential.ContentApproved,
      }))
    })

    afterAll(async () => {
      await faberAgent.shutdown()
      await faberAgent.wallet.delete()
      await aliceAgent.shutdown()
      await aliceAgent.wallet.delete()
    })

    // ==============================
    // TESTS v1 BEGIN
    // ==========================
    test('Alice starts with V1 credential proposal to Faber, both with autoAcceptCredential on `contentApproved`', async () => {
      testLogger.test('Alice sends credential proposal to Faber')
      let aliceCredentialExchangeRecord = await aliceAgent.credentials.proposeCredential({
        connectionId: aliceConnectionId,
        protocolVersion: 'v1',
        credentialFormats: {
          indy: {
            attributes: credentialPreview.attributes,
            credentialDefinitionId: credentialDefinitionId,
          },
        },
      })

      testLogger.test('Faber waits for credential proposal from Alice')
      let faberCredentialExchangeRecord = await waitForCredentialRecord(faberAgent, {
        threadId: aliceCredentialExchangeRecord.threadId,
        state: CredentialState.ProposalReceived,
      })

      testLogger.test('Faber sends credential offer to Alice')
      faberCredentialExchangeRecord = await faberAgent.credentials.acceptProposal({
        credentialRecordId: faberCredentialExchangeRecord.id,
        comment: 'V1 Indy Offer',
        credentialFormats: {
          indy: {
            credentialDefinitionId: credentialDefinitionId,
            attributes: credentialPreview.attributes,
          },
        },
      })

      testLogger.test('Alice waits for credential from Faber')
      aliceCredentialExchangeRecord = await waitForCredentialRecord(aliceAgent, {
        threadId: faberCredentialExchangeRecord.threadId,
        state: CredentialState.CredentialReceived,
      })

      testLogger.test('Faber waits for credential ack from Alice')
      faberCredentialExchangeRecord = await waitForCredentialRecord(faberAgent, {
        threadId: faberCredentialExchangeRecord.threadId,
        state: CredentialState.Done,
      })

      expect(aliceCredentialExchangeRecord).toMatchObject({
        type: CredentialExchangeRecord.type,
        id: expect.any(String),
        createdAt: expect.any(Date),
        metadata: {
          data: {
            '_internal/indyRequest': expect.any(Object),
            '_internal/indyCredential': {
              schemaId,
              credentialDefinitionId: credentialDefinitionId,
            },
          },
        },
        credentials: [
          {
            credentialRecordType: 'indy',
            credentialRecordId: expect.any(String),
          },
        ],
        state: CredentialState.CredentialReceived,
      })

      expect(faberCredentialExchangeRecord).toMatchObject({
        type: CredentialExchangeRecord.type,
        id: expect.any(String),
        createdAt: expect.any(Date),
        metadata: {
          data: {
            '_internal/indyCredential': {
              schemaId,
              credentialDefinitionId: credentialDefinitionId,
            },
          },
        },
        state: CredentialState.Done,
      })
    })

    test('Faber starts with V1 credential offer to Alice, both with autoAcceptCredential on `contentApproved`', async () => {
      testLogger.test('Faber sends credential offer to Alice')
      let faberCredentialExchangeRecord = await faberAgent.credentials.offerCredential({
        comment: 'some comment about credential',
        connectionId: faberConnectionId,
        credentialFormats: {
          indy: {
            attributes: credentialPreview.attributes,
            credentialDefinitionId: credentialDefinitionId,
          },
        },
        protocolVersion: 'v1',
      })

      testLogger.test('Alice waits for credential offer from Faber')
      let aliceCredentialExchangeRecord = await waitForCredentialRecord(aliceAgent, {
        threadId: faberCredentialExchangeRecord.threadId,
        state: CredentialState.OfferReceived,
      })

      expect(JsonTransformer.toJSON(aliceCredentialExchangeRecord)).toMatchObject({
        state: CredentialState.OfferReceived,
      })

      // below values are not in json object
      expect(aliceCredentialExchangeRecord.id).not.toBeNull()
      expect(aliceCredentialExchangeRecord.getTags()).toEqual({
        threadId: aliceCredentialExchangeRecord.threadId,
        state: aliceCredentialExchangeRecord.state,
        connectionId: aliceConnectionId,
        credentialIds: [],
      })

      if (aliceCredentialExchangeRecord.connectionId) {
        const acceptOfferOptions: AcceptCredentialOfferOptions = {
          credentialRecordId: aliceCredentialExchangeRecord.id,
        }
        testLogger.test('alice sends credential request to faber')
        faberCredentialExchangeRecord = await aliceAgent.credentials.acceptOffer(acceptOfferOptions)

        testLogger.test('Alice waits for credential from Faber')
        aliceCredentialExchangeRecord = await waitForCredentialRecord(aliceAgent, {
          threadId: faberCredentialExchangeRecord.threadId,
          state: CredentialState.CredentialReceived,
        })

        testLogger.test('Faber waits for credential ack from Alice')
        faberCredentialExchangeRecord = await waitForCredentialRecord(faberAgent, {
          threadId: faberCredentialExchangeRecord.threadId,
          state: CredentialState.Done,
        })

        expect(aliceCredentialExchangeRecord).toMatchObject({
          type: CredentialExchangeRecord.type,
          id: expect.any(String),
          createdAt: expect.any(Date),
          metadata: {
            data: {
              '_internal/indyRequest': expect.any(Object),
              '_internal/indyCredential': {
                schemaId,
                credentialDefinitionId: credentialDefinitionId,
              },
            },
          },
          credentials: [
            {
              credentialRecordType: 'indy',
              credentialRecordId: expect.any(String),
            },
          ],
          state: CredentialState.CredentialReceived,
        })

        expect(faberCredentialExchangeRecord).toMatchObject({
          type: CredentialExchangeRecord.type,
          id: expect.any(String),
          createdAt: expect.any(Date),
          state: CredentialState.Done,
        })
      } else {
        throw new AriesFrameworkError('missing alice connection id')
      }
    })

    test('Faber starts with V1 credential offer to Alice, both have autoAcceptCredential on `contentApproved` and attributes did change', async () => {
      testLogger.test('Faber sends credential offer to Alice')
      let faberCredentialExchangeRecord = await faberAgent.credentials.offerCredential({
        comment: 'some comment about credential',
        connectionId: faberConnectionId,
        credentialFormats: {
          indy: {
            attributes: credentialPreview.attributes,
            credentialDefinitionId: credentialDefinitionId,
          },
        },
        protocolVersion: 'v1',
      })

      testLogger.test('Alice waits for credential offer from Faber')
      let aliceCredentialExchangeRecord = await waitForCredentialRecord(aliceAgent, {
        threadId: faberCredentialExchangeRecord.threadId,
        state: CredentialState.OfferReceived,
      })

      // below values are not in json object
      expect(aliceCredentialExchangeRecord.id).not.toBeNull()
      expect(aliceCredentialExchangeRecord.getTags()).toEqual({
        threadId: aliceCredentialExchangeRecord.threadId,
        state: aliceCredentialExchangeRecord.state,
        connectionId: aliceConnectionId,
        credentialIds: [],
      })

      testLogger.test('Alice sends credential request to Faber')
      const aliceExchangeCredentialRecord = await aliceAgent.credentials.negotiateOffer({
        credentialRecordId: aliceCredentialExchangeRecord.id,
        credentialFormats: {
          indy: {
            attributes: newCredentialPreview.attributes,
            credentialDefinitionId: credentialDefinitionId,
          },
        },
        comment: 'v1 propose credential test',
      })

      testLogger.test('Faber waits for credential proposal from Alice')
      faberCredentialExchangeRecord = await waitForCredentialRecord(faberAgent, {
        threadId: aliceExchangeCredentialRecord.threadId,
        state: CredentialState.ProposalReceived,
      })

      // Check if the state of fabers credential record did not change
      const faberRecord = await faberAgent.credentials.getById(faberCredentialExchangeRecord.id)
      faberRecord.assertState(CredentialState.ProposalReceived)

      aliceCredentialExchangeRecord = await aliceAgent.credentials.getById(aliceCredentialExchangeRecord.id)
      aliceCredentialExchangeRecord.assertState(CredentialState.ProposalSent)
    })

    test('Alice starts with V1 credential proposal to Faber, both have autoAcceptCredential on `contentApproved` and attributes did change', async () => {
      testLogger.test('Alice sends credential proposal to Faber')
      const aliceCredentialExchangeRecord = await aliceAgent.credentials.proposeCredential({
        connectionId: aliceConnectionId,
        protocolVersion: 'v1',
        credentialFormats: {
          indy: {
            attributes: credentialPreview.attributes,
            credentialDefinitionId: credentialDefinitionId,
          },
        },
        comment: 'v1 propose credential test',
      })

      testLogger.test('Faber waits for credential proposal from Alice')
      let faberCredentialExchangeRecord = await waitForCredentialRecord(faberAgent, {
        threadId: aliceCredentialExchangeRecord.threadId,
        state: CredentialState.ProposalReceived,
      })

      await faberAgent.credentials.negotiateProposal({
        credentialRecordId: faberCredentialExchangeRecord.id,
        credentialFormats: {
          indy: {
            credentialDefinitionId: credentialDefinitionId,
            attributes: newCredentialPreview.attributes,
          },
        },
      })

      testLogger.test('Alice waits for credential offer from Faber')

      const record = await waitForCredentialRecord(aliceAgent, {
        threadId: faberCredentialExchangeRecord.threadId,
        state: CredentialState.OfferReceived,
      })

      // below values are not in json object
      expect(record.id).not.toBeNull()
      expect(record.getTags()).toEqual({
        threadId: record.threadId,
        state: record.state,
        connectionId: aliceConnectionId,
        credentialIds: [],
      })

      // Check if the state of the credential records did not change
      faberCredentialExchangeRecord = await faberAgent.credentials.getById(faberCredentialExchangeRecord.id)
      faberCredentialExchangeRecord.assertState(CredentialState.OfferSent)

      const aliceRecord = await aliceAgent.credentials.getById(record.id)
      aliceRecord.assertState(CredentialState.OfferReceived)
    })
  })
})