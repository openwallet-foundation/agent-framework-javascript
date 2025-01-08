import type { SubjectMessage } from '../../../../../../../../tests/transport/SubjectInboundTransport'
import type { AnonCredsTestsAgent } from '../../../../../../../anoncreds/tests/legacyAnonCredsSetup'

import { Subject } from 'rxjs'

import { SubjectInboundTransport } from '../../../../../../../../tests/transport/SubjectInboundTransport'
import { SubjectOutboundTransport } from '../../../../../../../../tests/transport/SubjectOutboundTransport'
import { V1CredentialPreview } from '../../../../../../../anoncreds/src'
import {
  getAnonCredsIndyModules,
  issueLegacyAnonCredsCredential,
  prepareForAnonCredsIssuance,
  setupAnonCredsTests,
} from '../../../../../../../anoncreds/tests/legacyAnonCredsSetup'
import {
  waitForProofExchangeRecordSubject,
  makeConnection,
  testLogger,
  setupEventReplaySubjects,
  waitForProofExchangeRecord,
  getInMemoryAgentOptions,
} from '../../../../../../tests'
import { Agent } from '../../../../../agent/Agent'
import { uuid } from '../../../../../utils/uuid'
import { CredentialEventTypes } from '../../../../credentials'
import { Attachment, AttachmentData, HandshakeProtocol, LinkedAttachment } from '../../../../didcomm'
import { MediatorModule, MediatorPickupStrategy, MediationRecipientModule } from '../../../../didcomm/modules/routing'
import { ProofEventTypes } from '../../../ProofEvents'
import { AutoAcceptProof, ProofState } from '../../../models'

describe('V2 Connectionless Proofs - Indy', () => {
  let agents: Agent[]

  afterEach(async () => {
    for (const agent of agents) {
      await agent.shutdown()
      await agent.wallet.delete()
    }
  })

  const connectionlessTest = async (returnRoute?: boolean) => {
    const {
      issuerAgent: faberAgent,
      issuerReplay: faberReplay,
      holderAgent: aliceAgent,
      holderReplay: aliceReplay,
      credentialDefinitionId,
      issuerHolderConnectionId: faberConnectionId,
    } = await setupAnonCredsTests({
      issuerName: 'Faber connection-less Proofs v2',
      holderName: 'Alice connection-less Proofs v2',
      autoAcceptProofs: AutoAcceptProof.Never,
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
    testLogger.test('Faber sends presentation request to Alice')

    // eslint-disable-next-line prefer-const
    let { proofRecord: faberProofExchangeRecord, message } = await faberAgent.proofs.createRequest({
      protocolVersion: 'v2',
      proofFormats: {
        indy: {
          name: 'test-proof-request',
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

    const { message: requestMessage } = await faberAgent.oob.createLegacyConnectionlessInvitation({
      recordId: faberProofExchangeRecord.id,
      message,
      domain: 'https://a-domain.com',
    })

    await aliceAgent.receiveMessage(requestMessage.toJSON())

    testLogger.test('Alice waits for presentation request from Faber')
    let aliceProofExchangeRecord = await waitForProofExchangeRecordSubject(aliceReplay, {
      state: ProofState.RequestReceived,
    })

    testLogger.test('Alice accepts presentation request from Faber')
    const requestedCredentials = await aliceAgent.proofs.selectCredentialsForRequest({
      proofRecordId: aliceProofExchangeRecord.id,
    })

    aliceProofExchangeRecord = await aliceAgent.proofs.acceptRequest({
      proofRecordId: aliceProofExchangeRecord.id,
      useReturnRoute: returnRoute,
      proofFormats: { indy: requestedCredentials.proofFormats.indy },
    })

    testLogger.test('Faber waits for presentation from Alice')
    faberProofExchangeRecord = await waitForProofExchangeRecordSubject(faberReplay, {
      threadId: aliceProofExchangeRecord.threadId,
      state: ProofState.PresentationReceived,
    })

    const sentPresentationMessage = aliceAgent.proofs.findPresentationMessage(aliceProofExchangeRecord.id)

    // assert presentation is valid
    expect(faberProofExchangeRecord.isVerified).toBe(true)

    // Faber accepts presentation
    await faberAgent.proofs.acceptPresentation({ proofRecordId: faberProofExchangeRecord.id })

    // Alice waits until it receives presentation ack
    aliceProofExchangeRecord = await waitForProofExchangeRecordSubject(aliceReplay, {
      threadId: aliceProofExchangeRecord.threadId,
      state: ProofState.Done,
    })
    return sentPresentationMessage
  }

  test('Faber starts with connection-less proof requests to Alice', async () => {
    await connectionlessTest()
  })

  test('Faber starts with connection-less proof requests to Alice with auto-accept enabled', async () => {
    testLogger.test('Faber sends presentation request to Alice')

    const {
      issuerAgent: faberAgent,
      issuerReplay: faberReplay,
      holderAgent: aliceAgent,
      holderReplay: aliceReplay,
      credentialDefinitionId,
      issuerHolderConnectionId: faberConnectionId,
    } = await setupAnonCredsTests({
      issuerName: 'Faber connection-less Proofs v2 - Auto Accept',
      holderName: 'Alice connection-less Proofs v2 - Auto Accept',
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

    // eslint-disable-next-line prefer-const
    let { message, proofRecord: faberProofExchangeRecord } = await faberAgent.proofs.createRequest({
      protocolVersion: 'v2',
      proofFormats: {
        indy: {
          name: 'test-proof-request',
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
      autoAcceptProof: AutoAcceptProof.ContentApproved,
    })

    const { message: requestMessage } = await faberAgent.oob.createLegacyConnectionlessInvitation({
      recordId: faberProofExchangeRecord.id,
      message,
      domain: 'https://a-domain.com',
    })

    await aliceAgent.receiveMessage(requestMessage.toJSON())

    await waitForProofExchangeRecordSubject(aliceReplay, {
      state: ProofState.Done,
      threadId: requestMessage.threadId,
    })

    await waitForProofExchangeRecordSubject(faberReplay, {
      state: ProofState.Done,
      threadId: requestMessage.threadId,
    })
  })

  test('Faber starts with connection-less proof requests to Alice with auto-accept enabled and both agents having a mediator', async () => {
    testLogger.test('Faber sends presentation request to Alice')

    const credentialPreview = V1CredentialPreview.fromRecord({
      name: 'John',
      age: '99',
    })

    const unique = uuid().substring(0, 4)

    const mediatorOptions = getInMemoryAgentOptions(
      `Connectionless proofs with mediator Mediator-${unique}`,
      {
        endpoints: ['rxjs:mediator'],
      },
      {},
      {
        ...getAnonCredsIndyModules({
          autoAcceptProofs: AutoAcceptProof.Always,
        }),
        mediator: new MediatorModule({
          autoAcceptMediationRequests: true,
        }),
      }
    )

    const mediatorMessages = new Subject<SubjectMessage>()
    const subjectMap = { 'rxjs:mediator': mediatorMessages }

    // Initialize mediator
    const mediatorAgent = new Agent(mediatorOptions)
    mediatorAgent.didcomm.registerOutboundTransport(new SubjectOutboundTransport(subjectMap))
    mediatorAgent.didcomm.registerInboundTransport(new SubjectInboundTransport(mediatorMessages))
    await mediatorAgent.initialize()

    const faberMediationOutOfBandRecord = await mediatorAgent.oob.createInvitation({
      label: 'faber invitation',
      handshakeProtocols: [HandshakeProtocol.Connections],
    })

    const aliceMediationOutOfBandRecord = await mediatorAgent.oob.createInvitation({
      label: 'alice invitation',
      handshakeProtocols: [HandshakeProtocol.Connections],
    })

    const faberOptions = getInMemoryAgentOptions(
      `Connectionless proofs with mediator Faber-${unique}`,
      {},
      {},
      {
        ...getAnonCredsIndyModules({
          autoAcceptProofs: AutoAcceptProof.Always,
        }),
        mediationRecipient: new MediationRecipientModule({
          mediatorInvitationUrl: faberMediationOutOfBandRecord.outOfBandInvitation.toUrl({
            domain: 'https://example.com',
          }),
          mediatorPickupStrategy: MediatorPickupStrategy.PickUpV1,
        }),
      }
    )

    const aliceOptions = getInMemoryAgentOptions(
      `Connectionless proofs with mediator Alice-${unique}`,
      {},
      {},
      {
        ...getAnonCredsIndyModules({
          autoAcceptProofs: AutoAcceptProof.Always,
        }),
        mediationRecipient: new MediationRecipientModule({
          mediatorInvitationUrl: aliceMediationOutOfBandRecord.outOfBandInvitation.toUrl({
            domain: 'https://example.com',
          }),
          mediatorPickupStrategy: MediatorPickupStrategy.PickUpV1,
        }),
      }
    )

    const faberAgent = new Agent(faberOptions)
    faberAgent.didcomm.registerOutboundTransport(new SubjectOutboundTransport(subjectMap))
    await faberAgent.initialize()

    const aliceAgent = new Agent(aliceOptions)
    aliceAgent.didcomm.registerOutboundTransport(new SubjectOutboundTransport(subjectMap))
    await aliceAgent.initialize()

    const [faberReplay, aliceReplay] = setupEventReplaySubjects(
      [faberAgent, aliceAgent],
      [CredentialEventTypes.CredentialStateChanged, ProofEventTypes.ProofStateChanged]
    )
    agents = [aliceAgent, faberAgent, mediatorAgent]

    const { credentialDefinition } = await prepareForAnonCredsIssuance(faberAgent, {
      attributeNames: ['name', 'age', 'image_0', 'image_1'],
    })

    const [faberConnection] = await makeConnection(faberAgent, aliceAgent)

    // issue credential with two linked attachments
    await issueLegacyAnonCredsCredential({
      issuerAgent: faberAgent as AnonCredsTestsAgent,
      issuerReplay: faberReplay,
      issuerHolderConnectionId: faberConnection.id,
      holderAgent: aliceAgent as AnonCredsTestsAgent,
      holderReplay: aliceReplay,
      offer: {
        credentialDefinitionId: credentialDefinition.credentialDefinitionId,
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

    // eslint-disable-next-line prefer-const
    let { message, proofRecord: faberProofExchangeRecord } = await faberAgent.proofs.createRequest({
      protocolVersion: 'v2',
      proofFormats: {
        indy: {
          name: 'test-proof-request',
          version: '1.0',
          requested_attributes: {
            name: {
              name: 'name',
              restrictions: [
                {
                  cred_def_id: credentialDefinition.credentialDefinitionId,
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
                  cred_def_id: credentialDefinition.credentialDefinitionId,
                },
              ],
            },
          },
        },
      },
      autoAcceptProof: AutoAcceptProof.ContentApproved,
    })

    const { message: requestMessage } = await faberAgent.oob.createLegacyConnectionlessInvitation({
      recordId: faberProofExchangeRecord.id,
      message,
      domain: 'https://a-domain.com',
    })

    const mediationRecord = await faberAgent.mediationRecipient.findDefaultMediator()
    if (!mediationRecord) throw new Error('Faber agent has no default mediator')

    expect(requestMessage).toMatchObject({
      service: {
        recipientKeys: [expect.any(String)],
        routingKeys: mediationRecord.routingKeys,
        serviceEndpoint: mediationRecord.endpoint,
      },
    })

    await aliceAgent.receiveMessage(requestMessage.toJSON())

    await waitForProofExchangeRecordSubject(aliceReplay, {
      state: ProofState.Done,
      threadId: requestMessage.threadId,
    })

    await waitForProofExchangeRecordSubject(faberReplay, {
      state: ProofState.Done,
      threadId: requestMessage.threadId,
    })
  })

  test('Faber starts with connection-less proof requests to Alice with auto-accept enabled and without an outbound transport', async () => {
    testLogger.test('Faber sends presentation request to Alice')

    const {
      issuerAgent: faberAgent,
      issuerReplay: faberReplay,
      holderAgent: aliceAgent,
      holderReplay: aliceReplay,
      credentialDefinitionId,
      issuerHolderConnectionId: faberConnectionId,
    } = await setupAnonCredsTests({
      issuerName: 'Faber connection-less Proofs v2 - Auto Accept',
      holderName: 'Alice connection-less Proofs v2 - Auto Accept',
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

    // eslint-disable-next-line prefer-const
    let { message, proofRecord: faberProofExchangeRecord } = await faberAgent.proofs.createRequest({
      protocolVersion: 'v2',
      proofFormats: {
        indy: {
          name: 'test-proof-request',
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
      autoAcceptProof: AutoAcceptProof.ContentApproved,
    })

    const { message: requestMessage } = await faberAgent.oob.createLegacyConnectionlessInvitation({
      recordId: faberProofExchangeRecord.id,
      message,
      domain: 'rxjs:faber',
    })

    for (const transport of faberAgent.didcomm.outboundTransports) {
      await faberAgent.didcomm.unregisterOutboundTransport(transport)
    }

    await aliceAgent.receiveMessage(requestMessage.toJSON())
    await waitForProofExchangeRecordSubject(aliceReplay, {
      state: ProofState.Done,
      threadId: requestMessage.threadId,
    })

    await waitForProofExchangeRecordSubject(faberReplay, {
      state: ProofState.Done,
      threadId: requestMessage.threadId,
    })
  })

  test('Faber starts with connection-less proof requests to Alice but gets Problem Reported', async () => {
    testLogger.test('Faber sends presentation request to Alice')

    const {
      issuerAgent: faberAgent,
      issuerReplay: faberReplay,
      holderAgent: aliceAgent,
      holderReplay: aliceReplay,
      credentialDefinitionId,
      issuerHolderConnectionId: faberConnectionId,
    } = await setupAnonCredsTests({
      issuerName: 'Faber connection-less Proofs v2 - Reject Request',
      holderName: 'Alice connection-less Proofs v2 - Reject Request',
      autoAcceptProofs: AutoAcceptProof.Never,
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

    // eslint-disable-next-line prefer-const
    // eslint-disable-next-line prefer-const
    let { message, proofRecord: faberProofExchangeRecord } = await faberAgent.proofs.createRequest({
      protocolVersion: 'v2',
      proofFormats: {
        indy: {
          name: 'test-proof-request',
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
          requested_predicates: {},
        },
      },
      autoAcceptProof: AutoAcceptProof.ContentApproved,
    })

    const { message: requestMessage } = await faberAgent.oob.createLegacyConnectionlessInvitation({
      recordId: faberProofExchangeRecord.id,
      message,
      domain: 'rxjs:faber',
    })

    for (const transport of faberAgent.didcomm.outboundTransports) {
      await faberAgent.didcomm.unregisterOutboundTransport(transport)
    }

    const aliceProofExchangeRecordPromise = waitForProofExchangeRecord(aliceAgent, {
      state: ProofState.RequestReceived,
    })

    await aliceAgent.receiveMessage(requestMessage.toJSON())
    const aliceProofExchangeRecord = await aliceProofExchangeRecordPromise

    await aliceAgent.proofs.declineRequest({ proofRecordId: aliceProofExchangeRecord.id, sendProblemReport: true })

    await waitForProofExchangeRecordSubject(aliceReplay, {
      state: ProofState.Declined,
      threadId: requestMessage.threadId,
    })

    await waitForProofExchangeRecordSubject(faberReplay, {
      state: ProofState.Abandoned,
      threadId: requestMessage.threadId,
    })
  })
})
