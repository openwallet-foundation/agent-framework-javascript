import type { Agent } from '../../../../../agent/Agent'
import type { SignCredentialOptionsRFC0593 } from '../../../../../modules/vc/models/W3cCredentialServiceOptions'
import type { ConnectionRecord } from '../../../../connections'
import type { AcceptOfferOptions, AcceptProposalOptions } from '../../../CredentialsModuleOptions'

import { setupCredentialTests, waitForCredentialRecord } from '../../../../../../tests/helpers'
import testLogger from '../../../../../../tests/logger'
import { KeyType } from '../../../../../crypto'
import { Key } from '../../../../../crypto/Key'
import { AriesFrameworkError } from '../../../../../error/AriesFrameworkError'
import { DidKey } from '../../../../../modules/dids'
import { Ed25519Signature2018Fixtures } from '../../../../../modules/vc/__tests__/fixtures'
import { W3cCredential } from '../../../../../modules/vc/models'
import { JsonTransformer } from '../../../../../utils'
import { sleep } from '../../../../../utils/sleep'
import { IndyWallet } from '../../../../../wallet/IndyWallet'
import { AutoAcceptCredential, CredentialState } from '../../../models'
import { CredentialExchangeRecord } from '../../../repository/CredentialExchangeRecord'
import { V2CredentialPreview } from '../messages'

describe('credentials', () => {
  let faberAgent: Agent
  let aliceAgent: Agent
  let credDefId: string
  let faberConnection: ConnectionRecord
  let aliceConnection: ConnectionRecord
  let aliceCredentialRecord: CredentialExchangeRecord
  let wallet: IndyWallet
  let issuerDidKey: DidKey
  let verificationMethod: string
  let credential: W3cCredential
  let signCredentialOptions: SignCredentialOptionsRFC0593

  describe('Auto accept on `always`', () => {
    const seed = 'testseed000000000000000000000001'
    beforeAll(async () => {
      ;({ faberAgent, aliceAgent, credDefId, faberConnection, aliceConnection } = await setupCredentialTests(
        'faber agent: always v2 jsonld',
        'alice agent: always v2 jsonld',
        AutoAcceptCredential.Always
      ))
      wallet = faberAgent.injectionContainer.resolve(IndyWallet)
      const issuerDidInfo = await wallet.createDid({ seed })
      const issuerKey = Key.fromPublicKeyBase58(issuerDidInfo.verkey, KeyType.Ed25519)
      issuerDidKey = new DidKey(issuerKey)
      verificationMethod = `${issuerDidKey.did}#${issuerDidKey.key.fingerprint}`

      credential = JsonTransformer.fromJSON(Ed25519Signature2018Fixtures.TEST_LD_DOCUMENT, W3cCredential)

      signCredentialOptions = {
        credential,
        options: {
          proofType: 'Ed25519Signature2018',
          proofPurpose: 'assertionMethod',
        },
      }
    })
    afterAll(async () => {
      await faberAgent.shutdown()
      await faberAgent.wallet.delete()
      await aliceAgent.shutdown()
      await aliceAgent.wallet.delete()
    })
    // ==============================
    // TESTS v2 BEGIN
    // ==========================
    test('Alice starts with V2 credential proposal to Faber, both with autoAcceptCredential on `always`', async () => {
      testLogger.test('Alice sends credential proposal to Faber')

      const aliceCredentialExchangeRecord = await aliceAgent.credentials.proposeCredential({
        connectionId: aliceConnection.id,
        protocolVersion: 'v2',
        credentialFormats: {
          jsonld: signCredentialOptions,
        },
        comment: 'v2 propose credential test',
      })
      testLogger.test('Alice waits for credential from Faber')
      aliceCredentialRecord = await waitForCredentialRecord(aliceAgent, {
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
        metadata: {},
        state: CredentialState.Done,
      })
    })
    test('Faber starts with V2 credential offer to Alice, both with autoAcceptCredential on `always`', async () => {
      testLogger.test('Faber sends V2 credential offer to Alice as start of protocol process')
      const credentialPreview = V2CredentialPreview.fromRecord({
        name: 'John',
        age: '99',
        'x-ray': 'some x-ray',
        profile_picture: 'profile picture',
      })

      const faberCredentialExchangeRecord: CredentialExchangeRecord = await faberAgent.credentials.offerCredential({
        comment: 'V2 Offer Credential',
        connectionId: faberConnection.id,
        credentialFormats: {
          indy: {
            attributes: credentialPreview.attributes,
            credentialDefinitionId: credDefId,
          },
        },
        protocolVersion: 'v2',
      })
      testLogger.test('Alice waits for credential from Faber')
      aliceCredentialRecord = await waitForCredentialRecord(aliceAgent, {
        threadId: faberCredentialExchangeRecord.threadId,
        state: CredentialState.OfferReceived,
      })
      testLogger.test('Alice waits for credential from Faber')
      aliceCredentialRecord = await waitForCredentialRecord(aliceAgent, {
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
        metadata: {},
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
    const seed = 'testseed000000000000000000000001'

    beforeAll(async () => {
      ;({ faberAgent, aliceAgent, credDefId, faberConnection, aliceConnection } = await setupCredentialTests(
        'faber agent: content-approved v2 jsonld',
        'alice agent: content-approved v2 jsonld',
        AutoAcceptCredential.ContentApproved
      ))
      wallet = faberAgent.injectionContainer.resolve(IndyWallet)
      const issuerDidInfo = await wallet.createDid({ seed })
      const issuerKey = Key.fromPublicKeyBase58(issuerDidInfo.verkey, KeyType.Ed25519)
      issuerDidKey = new DidKey(issuerKey)
      credential = JsonTransformer.fromJSON(Ed25519Signature2018Fixtures.TEST_LD_DOCUMENT, W3cCredential)
      verificationMethod = `${issuerDidKey.did}#${issuerDidKey.key.fingerprint}`

      signCredentialOptions = {
        credential,
        options: {
          proofType: 'Ed25519Signature2018',
          proofPurpose: 'assertionMethod',
        },
      }
    })

    afterAll(async () => {
      await faberAgent.shutdown()
      await faberAgent.wallet.delete()
      await aliceAgent.shutdown()
      await aliceAgent.wallet.delete()
    })

    test('Alice starts with V2 credential proposal to Faber, both with autoAcceptCredential on `contentApproved`', async () => {
      testLogger.test('Alice sends credential proposal to Faber')
      const aliceCredentialExchangeRecord = await aliceAgent.credentials.proposeCredential({
        connectionId: aliceConnection.id,
        protocolVersion: 'v2',
        credentialFormats: {
          jsonld: signCredentialOptions,
        },
        comment: 'v2 propose credential test',
      })

      testLogger.test('Faber waits for credential proposal from Alice')
      let faberCredentialRecord = await waitForCredentialRecord(faberAgent, {
        threadId: aliceCredentialExchangeRecord.threadId,
        state: CredentialState.ProposalReceived,
      })

      testLogger.test('Faber sends credential offer to Alice')
      const options: AcceptProposalOptions = {
        credentialRecordId: faberCredentialRecord.id,
        comment: 'V2 Indy Offer',
        credentialFormats: {
          jsonld: signCredentialOptions,
        },
      }
      const faberCredentialExchangeRecord = await faberAgent.credentials.acceptProposal(options)

      testLogger.test('Alice waits for credential from Faber')
      aliceCredentialRecord = await waitForCredentialRecord(aliceAgent, {
        threadId: faberCredentialExchangeRecord.threadId,
        state: CredentialState.CredentialReceived,
      })

      testLogger.test('Faber waits for credential ack from Alice')

      faberCredentialRecord = await waitForCredentialRecord(faberAgent, {
        threadId: faberCredentialRecord.threadId,
        state: CredentialState.Done,
      })

      expect(aliceCredentialRecord).toMatchObject({
        type: CredentialExchangeRecord.type,
        id: expect.any(String),
        createdAt: expect.any(Date),
        metadata: {},
        state: CredentialState.CredentialReceived,
      })

      expect(faberCredentialRecord).toMatchObject({
        type: CredentialExchangeRecord.type,
        id: expect.any(String),
        createdAt: expect.any(Date),
        metadata: {},
        state: CredentialState.Done,
      })
    })
    test('Faber starts with V2 credential offer to Alice, both with autoAcceptCredential on `contentApproved`', async () => {
      testLogger.test('Faber sends credential offer to Alice')

      let faberCredentialExchangeRecord = await faberAgent.credentials.offerCredential({
        comment: 'some comment about credential',
        connectionId: faberConnection.id,
        credentialFormats: {
          jsonld: signCredentialOptions,
        },
        protocolVersion: 'v2',
      })

      testLogger.test('Alice waits for credential offer from Faber')
      aliceCredentialRecord = await waitForCredentialRecord(aliceAgent, {
        threadId: faberCredentialExchangeRecord.threadId,
        state: CredentialState.OfferReceived,
      })

      // below values are not in json object
      expect(aliceCredentialRecord.id).not.toBeNull()
      expect(aliceCredentialRecord.getTags()).toEqual({
        threadId: aliceCredentialRecord.threadId,
        state: aliceCredentialRecord.state,
        connectionId: aliceConnection.id,
        credentialIds: [],
      })
      expect(aliceCredentialRecord.type).toBe(CredentialExchangeRecord.type)
      if (!aliceCredentialRecord.connectionId) {
        throw new AriesFrameworkError('missing alice connection id')
      }

      // we do not need to specify connection id in this object
      // it is either connectionless or included in the offer message
      const acceptOfferOptions: AcceptOfferOptions = {
        credentialRecordId: aliceCredentialRecord.id,
      }
      testLogger.test('Alice sends credential request to faber')
      faberCredentialExchangeRecord = await aliceAgent.credentials.acceptOffer(acceptOfferOptions)

      testLogger.test('Alice waits for credential from Faber')
      aliceCredentialRecord = await waitForCredentialRecord(aliceAgent, {
        threadId: faberCredentialExchangeRecord.threadId,
        state: CredentialState.CredentialReceived,
      })

      testLogger.test('Faber waits for credential ack from Alice')

      const faberCredentialRecord = await waitForCredentialRecord(faberAgent, {
        threadId: faberCredentialExchangeRecord.threadId,
        state: CredentialState.Done,
      })

      expect(aliceCredentialRecord).toMatchObject({
        type: CredentialExchangeRecord.type,
        id: expect.any(String),
        createdAt: expect.any(Date),
        metadata: {},
        state: CredentialState.CredentialReceived,
      })

      expect(faberCredentialRecord).toMatchObject({
        type: CredentialExchangeRecord.type,
        id: expect.any(String),
        createdAt: expect.any(Date),
        state: CredentialState.Done,
      })
    })
    test('Alice starts with V2 credential proposal to Faber, both have autoAcceptCredential on `contentApproved` and attributes did change', async () => {
      testLogger.test('Alice sends credential proposal to Faber')
      const aliceCredentialExchangeRecord = await aliceAgent.credentials.proposeCredential({
        connectionId: aliceConnection.id,
        protocolVersion: 'v2',
        credentialFormats: {
          jsonld: signCredentialOptions,
        },
        comment: 'v2 propose credential test',
      })

      testLogger.test('Faber waits for credential proposal from Alice')
      let faberCredentialRecord = await waitForCredentialRecord(faberAgent, {
        threadId: aliceCredentialExchangeRecord.threadId,
        state: CredentialState.ProposalReceived,
      })

      await faberAgent.credentials.negotiateProposal({
        credentialRecordId: faberCredentialRecord.id,
        credentialFormats: {
          jsonld: signCredentialOptions,
        },
      })

      testLogger.test('Alice waits for credential offer from Faber')

      const record = await waitForCredentialRecord(aliceAgent, {
        threadId: faberCredentialRecord.threadId,
        state: CredentialState.OfferReceived,
      })

      // below values are not in json object
      expect(record.id).not.toBeNull()
      expect(record.getTags()).toEqual({
        threadId: record.threadId,
        state: record.state,
        connectionId: aliceConnection.id,
        credentialIds: [],
      })
      expect(record.type).toBe(CredentialExchangeRecord.type)

      // Check if the state of the credential records did not change
      faberCredentialRecord = await faberAgent.credentials.getById(faberCredentialRecord.id)
      faberCredentialRecord.assertState(CredentialState.OfferSent)

      const aliceRecord = await aliceAgent.credentials.getById(record.id)
      aliceRecord.assertState(CredentialState.OfferReceived)
    })
    test('Faber starts with V2 credential offer to Alice, both have autoAcceptCredential on `contentApproved` and attributes did change', async () => {
      testLogger.test('Faber sends credential offer to Alice')

      const faberCredentialExchangeRecord = await faberAgent.credentials.offerCredential({
        comment: 'some comment about credential',
        connectionId: faberConnection.id,
        credentialFormats: {
          jsonld: signCredentialOptions,
        },
        protocolVersion: 'v2',
      })

      testLogger.test('Alice waits for credential offer from Faber')
      aliceCredentialRecord = await waitForCredentialRecord(aliceAgent, {
        threadId: faberCredentialExchangeRecord.threadId,
        state: CredentialState.OfferReceived,
      })

      // below values are not in json object
      expect(aliceCredentialRecord.id).not.toBeNull()
      expect(aliceCredentialRecord.getTags()).toEqual({
        threadId: aliceCredentialRecord.threadId,
        state: aliceCredentialRecord.state,
        connectionId: aliceConnection.id,
        credentialIds: [],
      })
      expect(aliceCredentialRecord.type).toBe(CredentialExchangeRecord.type)

      testLogger.test('Alice sends credential request to Faber')

      const aliceExchangeCredentialRecord = await aliceAgent.credentials.negotiateOffer({
        credentialRecordId: aliceCredentialRecord.id,
        credentialFormats: {
          jsonld: signCredentialOptions,
        },
        comment: 'v2 propose credential test',
      })

      testLogger.test('Faber waits for credential proposal from Alice')
      const faberCredentialRecord = await waitForCredentialRecord(faberAgent, {
        threadId: aliceExchangeCredentialRecord.threadId,
        state: CredentialState.ProposalReceived,
      })

      // Check if the state of faber credential record did not change
      const faberRecord = await faberAgent.credentials.getById(faberCredentialRecord.id)
      faberRecord.assertState(CredentialState.ProposalReceived)

      aliceCredentialRecord = await aliceAgent.credentials.getById(aliceCredentialRecord.id)
      aliceCredentialRecord.assertState(CredentialState.ProposalSent)
      await sleep(5000)
    })
  })
})
