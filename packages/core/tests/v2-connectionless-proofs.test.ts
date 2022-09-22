import type { SubjectMessage } from '../../../tests/transport/SubjectInboundTransport'
import type { ProofStateChangedEvent } from '../src/modules/proofs'
import type { CreateProofRequestOptions } from '../src/modules/proofs/ProofsApiOptions'
import type { IndyProofFormat } from '../src/modules/proofs/formats/indy/IndyProofFormat'
import type { V2ProofService } from '../src/modules/proofs/protocol/v2'

import { Subject, ReplaySubject } from 'rxjs'

import { SubjectInboundTransport } from '../../../tests/transport/SubjectInboundTransport'
import { SubjectOutboundTransport } from '../../../tests/transport/SubjectOutboundTransport'
import { V1CredentialPreview } from '../src'
import { Agent } from '../src/agent/Agent'
import { Attachment, AttachmentData } from '../src/decorators/attachment/Attachment'
import { HandshakeProtocol } from '../src/modules/connections/models/HandshakeProtocol'
import {
  PredicateType,
  ProofState,
  ProofAttributeInfo,
  AttributeFilter,
  ProofPredicateInfo,
  AutoAcceptProof,
  ProofEventTypes,
} from '../src/modules/proofs'
import { ProofProtocolVersion } from '../src/modules/proofs/models/ProofProtocolVersion'
import { MediatorPickupStrategy } from '../src/modules/routing/MediatorPickupStrategy'
import { LinkedAttachment } from '../src/utils/LinkedAttachment'
import { uuid } from '../src/utils/uuid'

import {
  getAgentOptions,
  issueCredential,
  makeConnection,
  prepareForIssuance,
  setupProofsTest,
  waitForProofRecordSubject,
} from './helpers'
import testLogger from './logger'

describe('Present Proof', () => {
  let agents: Agent[]

  afterEach(async () => {
    for (const agent of agents) {
      await agent.shutdown()
      await agent.wallet.delete()
    }
  })

  test('Faber starts with connection-less proof requests to Alice', async () => {
    const { aliceAgent, faberAgent, aliceReplay, credDefId, faberReplay } = await setupProofsTest(
      'Faber connection-less Proofs',
      'Alice connection-less Proofs',
      AutoAcceptProof.Never
    )
    agents = [aliceAgent, faberAgent]
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

    const outOfBandRequestOptions: CreateProofRequestOptions<[IndyProofFormat], [V2ProofService]> = {
      protocolVersion: ProofProtocolVersion.V2,
      proofFormats: {
        indy: {
          name: 'test-proof-request',
          version: '1.0',
          nonce: '12345678901',
          requestedAttributes: attributes,
          requestedPredicates: predicates,
        },
      },
    }

    let aliceProofRecordPromise = waitForProofRecordSubject(aliceReplay, {
      state: ProofState.RequestReceived,
    })

    // eslint-disable-next-line prefer-const
    let { proofRecord: faberProofRecord, message } = await faberAgent.proofs.createRequest(outOfBandRequestOptions)

    const { message: requestMessage } = await faberAgent.oob.createLegacyConnectionlessInvitation({
      recordId: faberProofRecord.id,
      message,
      domain: 'https://a-domain.com',
    })

    await aliceAgent.receiveMessage(requestMessage.toJSON())

    testLogger.test('Alice waits for presentation request from Faber')
    let aliceProofRecord = await aliceProofRecordPromise

    testLogger.test('Alice accepts presentation request from Faber')

    const requestedCredentials = await aliceAgent.proofs.autoSelectCredentialsForProofRequest({
      proofRecordId: aliceProofRecord.id,
      config: {
        filterByPresentationPreview: true,
      },
    })

    const faberProofRecordPromise = waitForProofRecordSubject(faberReplay, {
      threadId: aliceProofRecord.threadId,
      state: ProofState.PresentationReceived,
    })

    await aliceAgent.proofs.acceptRequest({
      proofRecordId: aliceProofRecord.id,
      proofFormats: { indy: requestedCredentials.proofFormats.indy },
    })

    testLogger.test('Faber waits for presentation from Alice')
    faberProofRecord = await faberProofRecordPromise

    // assert presentation is valid
    expect(faberProofRecord.isVerified).toBe(true)

    aliceProofRecordPromise = waitForProofRecordSubject(aliceReplay, {
      threadId: aliceProofRecord.threadId,
      state: ProofState.Done,
    })

    // Faber accepts presentation
    await faberAgent.proofs.acceptPresentation(faberProofRecord.id)

    // Alice waits till it receives presentation ack
    aliceProofRecord = await aliceProofRecordPromise
  })

  test('Faber starts with connection-less proof requests to Alice with auto-accept enabled', async () => {
    testLogger.test('Faber sends presentation request to Alice')

    const { aliceAgent, faberAgent, aliceReplay, credDefId, faberReplay } = await setupProofsTest(
      'Faber connection-less Proofs - Auto Accept',
      'Alice connection-less Proofs - Auto Accept',
      AutoAcceptProof.Always
    )

    agents = [aliceAgent, faberAgent]

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

    const outOfBandRequestOptions: CreateProofRequestOptions<[IndyProofFormat], [V2ProofService]> = {
      protocolVersion: ProofProtocolVersion.V2,
      proofFormats: {
        indy: {
          name: 'test-proof-request',
          version: '1.0',
          nonce: '12345678901',
          requestedAttributes: attributes,
          requestedPredicates: predicates,
        },
      },
      autoAcceptProof: AutoAcceptProof.ContentApproved,
    }

    const aliceProofRecordPromise = waitForProofRecordSubject(aliceReplay, {
      state: ProofState.Done,
    })

    const faberProofRecordPromise = waitForProofRecordSubject(faberReplay, {
      state: ProofState.Done,
    })

    // eslint-disable-next-line prefer-const
    let { message, proofRecord: faberProofRecord } = await faberAgent.proofs.createRequest(outOfBandRequestOptions)

    const { message: requestMessage } = await faberAgent.oob.createLegacyConnectionlessInvitation({
      recordId: faberProofRecord.id,
      message,
      domain: 'https://a-domain.com',
    })
    await aliceAgent.receiveMessage(requestMessage.toJSON())

    await aliceProofRecordPromise

    await faberProofRecordPromise
  })

  test('Faber starts with connection-less proof requests to Alice with auto-accept enabled and both agents having a mediator', async () => {
    testLogger.test('Faber sends presentation request to Alice')

    const credentialPreview = V1CredentialPreview.fromRecord({
      name: 'John',
      age: '99',
    })

    const unique = uuid().substring(0, 4)

    const mediatorOptions = getAgentOptions(`Connectionless proofs with mediator Mediator-${unique}`, {
      autoAcceptMediationRequests: true,
      endpoints: ['rxjs:mediator'],
    })

    const faberMessages = new Subject<SubjectMessage>()
    const aliceMessages = new Subject<SubjectMessage>()
    const mediatorMessages = new Subject<SubjectMessage>()

    const subjectMap = {
      'rxjs:mediator': mediatorMessages,
    }

    // Initialize mediator
    const mediatorAgent = new Agent(mediatorOptions)
    mediatorAgent.registerOutboundTransport(new SubjectOutboundTransport(subjectMap))
    mediatorAgent.registerInboundTransport(new SubjectInboundTransport(mediatorMessages))
    await mediatorAgent.initialize()

    const faberMediationOutOfBandRecord = await mediatorAgent.oob.createInvitation({
      label: 'faber invitation',
      handshakeProtocols: [HandshakeProtocol.Connections],
    })

    const aliceMediationOutOfBandRecord = await mediatorAgent.oob.createInvitation({
      label: 'alice invitation',
      handshakeProtocols: [HandshakeProtocol.Connections],
    })

    const faberOptions = getAgentOptions(`Connectionless proofs with mediator Faber-${unique}`, {
      autoAcceptProofs: AutoAcceptProof.Always,
      mediatorConnectionsInvite: faberMediationOutOfBandRecord.outOfBandInvitation.toUrl({
        domain: 'https://example.com',
      }),
      mediatorPickupStrategy: MediatorPickupStrategy.PickUpV1,
    })

    const aliceOptions = getAgentOptions(`Connectionless proofs with mediator Alice-${unique}`, {
      autoAcceptProofs: AutoAcceptProof.Always,
      // logger: new TestLogger(LogLevel.test),
      mediatorConnectionsInvite: aliceMediationOutOfBandRecord.outOfBandInvitation.toUrl({
        domain: 'https://example.com',
      }),
      mediatorPickupStrategy: MediatorPickupStrategy.PickUpV1,
    })

    const faberAgent = new Agent(faberOptions)
    faberAgent.registerOutboundTransport(new SubjectOutboundTransport(subjectMap))
    faberAgent.registerInboundTransport(new SubjectInboundTransport(faberMessages))
    await faberAgent.initialize()

    const aliceAgent = new Agent(aliceOptions)
    aliceAgent.registerOutboundTransport(new SubjectOutboundTransport(subjectMap))
    aliceAgent.registerInboundTransport(new SubjectInboundTransport(aliceMessages))
    await aliceAgent.initialize()

    agents = [aliceAgent, faberAgent, mediatorAgent]

    const { definition } = await prepareForIssuance(faberAgent, ['name', 'age', 'image_0', 'image_1'])

    const [faberConnection, aliceConnection] = await makeConnection(faberAgent, aliceAgent)
    expect(faberConnection.isReady).toBe(true)
    expect(aliceConnection.isReady).toBe(true)

    await issueCredential({
      issuerAgent: faberAgent,
      issuerConnectionId: faberConnection.id,
      holderAgent: aliceAgent,
      credentialTemplate: {
        credentialDefinitionId: definition.id,
        attributes: credentialPreview.attributes,
        linkedAttachments: [
          new LinkedAttachment({
            name: 'image_0',
            attachment: new Attachment({
              filename: 'picture-of-a-cat.png',
              data: new AttachmentData({ base64: 'cGljdHVyZSBvZiBhIGNhdA==' }),
            }),
          }),
          new LinkedAttachment({
            name: 'image_1',
            attachment: new Attachment({
              filename: 'picture-of-a-dog.png',
              data: new AttachmentData({ base64: 'UGljdHVyZSBvZiBhIGRvZw==' }),
            }),
          }),
        ],
      },
    })
    const faberReplay = new ReplaySubject<ProofStateChangedEvent>()
    const aliceReplay = new ReplaySubject<ProofStateChangedEvent>()

    faberAgent.events.observable<ProofStateChangedEvent>(ProofEventTypes.ProofStateChanged).subscribe(faberReplay)
    aliceAgent.events.observable<ProofStateChangedEvent>(ProofEventTypes.ProofStateChanged).subscribe(aliceReplay)

    const attributes = {
      name: new ProofAttributeInfo({
        name: 'name',
        restrictions: [
          new AttributeFilter({
            credentialDefinitionId: definition.id,
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
            credentialDefinitionId: definition.id,
          }),
        ],
      }),
    }

    const outOfBandRequestOptions: CreateProofRequestOptions<[IndyProofFormat], [V2ProofService]> = {
      protocolVersion: ProofProtocolVersion.V2,
      proofFormats: {
        indy: {
          name: 'test-proof-request',
          version: '1.0',
          nonce: '12345678901',
          requestedAttributes: attributes,
          requestedPredicates: predicates,
        },
      },
      autoAcceptProof: AutoAcceptProof.ContentApproved,
    }

    const aliceProofRecordPromise = waitForProofRecordSubject(aliceReplay, {
      state: ProofState.Done,
    })

    const faberProofRecordPromise = waitForProofRecordSubject(faberReplay, {
      state: ProofState.Done,
    })

    // eslint-disable-next-line prefer-const
    let { message, proofRecord: faberProofRecord } = await faberAgent.proofs.createRequest(outOfBandRequestOptions)

    const { message: requestMessage } = await faberAgent.oob.createLegacyConnectionlessInvitation({
      recordId: faberProofRecord.id,
      message,
      domain: 'https://a-domain.com',
    })

    const mediationRecord = await faberAgent.mediationRecipient.findDefaultMediator()
    if (!mediationRecord) {
      throw new Error('Faber agent has no default mediator')
    }

    expect(requestMessage).toMatchObject({
      service: {
        recipientKeys: [expect.any(String)],
        routingKeys: mediationRecord.routingKeys,
        serviceEndpoint: mediationRecord.endpoint,
      },
    })

    await aliceAgent.receiveMessage(requestMessage.toJSON())

    await aliceProofRecordPromise

    await faberProofRecordPromise
  })
})
