import type { V2IssueCredentialMessage } from '../../core/src/modules/didcomm'
import type { EventReplaySubject, JsonLdTestsAgent } from '../../core/tests'

import { TypedArrayEncoder } from '../../core/src'
import { KeyType } from '../../core/src/crypto'
import { CredentialState, CredentialExchangeRecord } from '../../core/src/modules/didcomm'
import { CREDENTIALS_CONTEXT_V1_URL, SECURITY_CONTEXT_BBS_URL } from '../../core/src/modules/vc'
import { JsonTransformer } from '../../core/src/utils/JsonTransformer'
import { waitForCredentialRecordSubject, setupJsonLdTests, testLogger } from '../../core/tests'

import { describeSkipNode18 } from './util'

let faberAgent: JsonLdTestsAgent
let faberReplay: EventReplaySubject
let aliceAgent: JsonLdTestsAgent
let aliceReplay: EventReplaySubject
let aliceConnectionId: string
let aliceCredentialRecord: CredentialExchangeRecord
let faberCredentialRecord: CredentialExchangeRecord

const signCredentialOptions = {
  credential: {
    '@context': [CREDENTIALS_CONTEXT_V1_URL, 'https://w3id.org/citizenship/v1', SECURITY_CONTEXT_BBS_URL],
    id: 'https://issuer.oidp.uscis.gov/credentials/83627465',
    type: ['VerifiableCredential', 'PermanentResidentCard'],
    issuer:
      'did:key:zUC72Q7XD4PE4CrMiDVXuvZng3sBvMmaGgNeTUJuzavH2BS7ThbHL9FhsZM9QYY5fqAQ4MB8M9oudz3tfuaX36Ajr97QRW7LBt6WWmrtESe6Bs5NYzFtLWEmeVtvRYVAgjFcJSa',
    issuanceDate: '2019-12-03T12:19:52Z',
    expirationDate: '2029-12-03T12:19:52Z',
    identifier: '83627465',
    name: 'Permanent Resident Card',
    credentialSubject: {
      id: 'did:example:b34ca6cd37bbf23',
      type: ['PermanentResident', 'Person'],
      givenName: 'JOHN',
      familyName: 'SMITH',
      gender: 'Male',
      image: 'data:image/png;base64,iVBORw0KGgokJggg==',
      residentSince: '2015-01-01',
      description: 'Government of Example Permanent Resident Card.',
      lprCategory: 'C09',
      lprNumber: '999-999-999',
      commuterClassification: 'C1',
      birthCountry: 'Bahamas',
      birthDate: '1958-07-17',
    },
  },
  options: {
    proofType: 'BbsBlsSignature2020',
    proofPurpose: 'assertionMethod',
  },
}

describeSkipNode18('credentials, BBS+ signature', () => {
  beforeAll(async () => {
    ;({
      issuerAgent: faberAgent,
      issuerReplay: faberReplay,
      holderAgent: aliceAgent,
      holderReplay: aliceReplay,
      holderIssuerConnectionId: aliceConnectionId,
    } = await setupJsonLdTests({
      issuerName: 'Faber Agent Credentials LD BBS+',
      holderName: 'Alice Agent Credentials LD BBS+',
      useBbs: true,
    }))

    await faberAgent.context.wallet.createKey({
      keyType: KeyType.Ed25519,
      privateKey: TypedArrayEncoder.fromString('testseed000000000000000000000001'),
    })
    // FIXME: askar doesn't create the same privateKey based on the same seed as when generated used askar BBS library...
    // See https://github.com/hyperledger/aries-askar/issues/219
    await faberAgent.context.wallet.createKey({
      keyType: KeyType.Bls12381g2,
      privateKey: TypedArrayEncoder.fromBase58('2szQ7zB4tKLJPsGK3YTp9SNQ6hoWYFG5rGhmgfQM4nb7'),
    })
  })

  afterAll(async () => {
    await faberAgent.shutdown()
    await faberAgent.wallet.delete()
    await aliceAgent.shutdown()
    await aliceAgent.wallet.delete()
  })

  test('Alice starts with V2 (ld format, BbsBlsSignature2020 signature) credential proposal to Faber', async () => {
    testLogger.test('Alice sends (v2 jsonld) credential proposal to Faber')
    const credentialExchangeRecord = await aliceAgent.credentials.proposeCredential({
      connectionId: aliceConnectionId,
      protocolVersion: 'v2',
      credentialFormats: {
        jsonld: signCredentialOptions,
      },
      comment: 'v2 propose credential test for W3C Credentials',
    })

    expect(credentialExchangeRecord.connectionId).toEqual(aliceConnectionId)
    expect(credentialExchangeRecord.protocolVersion).toEqual('v2')
    expect(credentialExchangeRecord.state).toEqual(CredentialState.ProposalSent)
    expect(credentialExchangeRecord.threadId).not.toBeNull()

    testLogger.test('Faber waits for credential proposal from Alice')
    faberCredentialRecord = await waitForCredentialRecordSubject(faberReplay, {
      threadId: credentialExchangeRecord.threadId,
      state: CredentialState.ProposalReceived,
    })

    testLogger.test('Faber sends credential offer to Alice')
    await faberAgent.credentials.acceptProposal({
      credentialRecordId: faberCredentialRecord.id,
      comment: 'V2 W3C Offer',
    })

    testLogger.test('Alice waits for credential offer from Faber')
    aliceCredentialRecord = await waitForCredentialRecordSubject(aliceReplay, {
      threadId: faberCredentialRecord.threadId,
      state: CredentialState.OfferReceived,
    })

    const offerMessage = await faberAgent.credentials.findOfferMessage(faberCredentialRecord.id)
    expect(JsonTransformer.toJSON(offerMessage)).toMatchObject({
      '@type': 'https://didcomm.org/issue-credential/2.0/offer-credential',
      '@id': expect.any(String),
      comment: 'V2 W3C Offer',
      formats: [
        {
          attach_id: expect.any(String),
          format: 'aries/ld-proof-vc-detail@v1.0',
        },
      ],
      'offers~attach': [
        {
          '@id': expect.any(String),
          'mime-type': 'application/json',
          data: expect.any(Object),
          lastmod_time: undefined,
          byte_count: undefined,
        },
      ],
      '~thread': {
        thid: expect.any(String),
        pthid: undefined,
        sender_order: undefined,
        received_orders: undefined,
      },
      '~service': undefined,
      '~attach': undefined,
      '~please_ack': undefined,
      '~timing': undefined,
      '~transport': undefined,
      '~l10n': undefined,
      credential_preview: expect.any(Object),
      replacement_id: undefined,
    })
    expect(aliceCredentialRecord.id).not.toBeNull()
    expect(aliceCredentialRecord.type).toBe(CredentialExchangeRecord.type)

    const offerCredentialExchangeRecord = await aliceAgent.credentials.acceptOffer({
      credentialRecordId: aliceCredentialRecord.id,
      credentialFormats: {
        jsonld: undefined,
      },
    })

    expect(offerCredentialExchangeRecord.connectionId).toEqual(aliceConnectionId)
    expect(offerCredentialExchangeRecord.protocolVersion).toEqual('v2')
    expect(offerCredentialExchangeRecord.state).toEqual(CredentialState.RequestSent)
    expect(offerCredentialExchangeRecord.threadId).not.toBeNull()

    testLogger.test('Faber waits for credential request from Alice')
    await waitForCredentialRecordSubject(faberReplay, {
      threadId: aliceCredentialRecord.threadId,
      state: CredentialState.RequestReceived,
    })

    testLogger.test('Faber sends credential to Alice')
    await faberAgent.credentials.acceptRequest({
      credentialRecordId: faberCredentialRecord.id,
      comment: 'V2 W3C Offer',
    })

    testLogger.test('Alice waits for credential from Faber')
    aliceCredentialRecord = await waitForCredentialRecordSubject(aliceReplay, {
      threadId: faberCredentialRecord.threadId,
      state: CredentialState.CredentialReceived,
    })

    testLogger.test('Alice sends credential ack to Faber')
    await aliceAgent.credentials.acceptCredential({ credentialRecordId: aliceCredentialRecord.id })

    testLogger.test('Faber waits for credential ack from Alice')
    faberCredentialRecord = await waitForCredentialRecordSubject(faberReplay, {
      threadId: faberCredentialRecord.threadId,
      state: CredentialState.Done,
    })
    expect(aliceCredentialRecord).toMatchObject({
      type: CredentialExchangeRecord.type,
      id: expect.any(String),
      createdAt: expect.any(Date),
      threadId: expect.any(String),
      connectionId: expect.any(String),
      state: CredentialState.CredentialReceived,
    })

    const credentialMessage = await faberAgent.credentials.findCredentialMessage(faberCredentialRecord.id)
    const w3cCredential = (credentialMessage as V2IssueCredentialMessage).credentialAttachments[0].getDataAsJson()

    expect(w3cCredential).toMatchObject({
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
        'https://w3id.org/citizenship/v1',
        'https://w3id.org/security/bbs/v1',
      ],
      id: 'https://issuer.oidp.uscis.gov/credentials/83627465',
      type: ['VerifiableCredential', 'PermanentResidentCard'],
      issuer:
        'did:key:zUC72Q7XD4PE4CrMiDVXuvZng3sBvMmaGgNeTUJuzavH2BS7ThbHL9FhsZM9QYY5fqAQ4MB8M9oudz3tfuaX36Ajr97QRW7LBt6WWmrtESe6Bs5NYzFtLWEmeVtvRYVAgjFcJSa',
      issuanceDate: '2019-12-03T12:19:52Z',
      expirationDate: '2029-12-03T12:19:52Z',
      identifier: '83627465',
      name: 'Permanent Resident Card',
      credentialSubject: {
        id: 'did:example:b34ca6cd37bbf23',
        type: ['PermanentResident', 'Person'],
        givenName: 'JOHN',
        familyName: 'SMITH',
        gender: 'Male',
        image: 'data:image/png;base64,iVBORw0KGgokJggg==',
        residentSince: '2015-01-01',
        description: 'Government of Example Permanent Resident Card.',
        lprCategory: 'C09',
        lprNumber: '999-999-999',
        commuterClassification: 'C1',
        birthCountry: 'Bahamas',
        birthDate: '1958-07-17',
      },
      proof: {
        type: 'BbsBlsSignature2020',
        created: expect.any(String),
        verificationMethod:
          'did:key:zUC72Q7XD4PE4CrMiDVXuvZng3sBvMmaGgNeTUJuzavH2BS7ThbHL9FhsZM9QYY5fqAQ4MB8M9oudz3tfuaX36Ajr97QRW7LBt6WWmrtESe6Bs5NYzFtLWEmeVtvRYVAgjFcJSa#zUC72Q7XD4PE4CrMiDVXuvZng3sBvMmaGgNeTUJuzavH2BS7ThbHL9FhsZM9QYY5fqAQ4MB8M9oudz3tfuaX36Ajr97QRW7LBt6WWmrtESe6Bs5NYzFtLWEmeVtvRYVAgjFcJSa',
        proofPurpose: 'assertionMethod',
        proofValue: expect.any(String),
      },
    })

    expect(JsonTransformer.toJSON(credentialMessage)).toMatchObject({
      '@type': 'https://didcomm.org/issue-credential/2.0/issue-credential',
      '@id': expect.any(String),
      comment: 'V2 W3C Offer',
      formats: [
        {
          attach_id: expect.any(String),
          format: 'aries/ld-proof-vc@v1.0',
        },
      ],
      'credentials~attach': [
        {
          '@id': expect.any(String),
          'mime-type': 'application/json',
          data: expect.any(Object),
          lastmod_time: undefined,
          byte_count: undefined,
        },
      ],
      '~thread': {
        thid: expect.any(String),
        pthid: undefined,
        sender_order: undefined,
        received_orders: undefined,
      },
      '~please_ack': { on: ['RECEIPT'] },
      '~service': undefined,
      '~attach': undefined,
      '~timing': undefined,
      '~transport': undefined,
      '~l10n': undefined,
    })
  })
})
