/* eslint-disable @typescript-eslint/no-non-null-assertion */
import type { SubjectMessage } from '../../../tests/transport/SubjectInboundTransport'
import type { AnonCredsCredentialFormatService } from '../../anoncreds/src'
import type { CreateCredentialOfferOptions, V2CredentialProtocol } from '../src/modules/credentials'
import type { AgentMessage, AgentMessageReceivedEvent } from '@credo-ts/core'

import { Subject } from 'rxjs'

import { SubjectInboundTransport } from '../../../tests/transport/SubjectInboundTransport'
import { SubjectOutboundTransport } from '../../../tests/transport/SubjectOutboundTransport'
import { getAnonCredsIndyModules } from '../../anoncreds/tests/legacyAnonCredsSetup'
import {
  anoncredsDefinitionFourAttributesNoRevocation,
  storePreCreatedAnonCredsDefinition,
} from '../../anoncreds/tests/preCreatedAnonCredsDefinition'
import { Agent } from '../src/agent/Agent'
import { Key } from '../src/crypto'
import { DidExchangeState, HandshakeProtocol } from '../src/modules/connections'
import { OutOfBandDidCommService } from '../src/modules/oob/domain/OutOfBandDidCommService'
import { OutOfBandEventTypes } from '../src/modules/oob/domain/OutOfBandEvents'
import { OutOfBandRole } from '../src/modules/oob/domain/OutOfBandRole'
import { OutOfBandState } from '../src/modules/oob/domain/OutOfBandState'
import { OutOfBandInvitation } from '../src/modules/oob/messages'
import { JsonEncoder, JsonTransformer } from '../src/utils'

import { TestMessage } from './TestMessage'
import { getInMemoryAgentOptions, waitForCredentialRecord } from './helpers'

import { AgentEventTypes, CredoError, AutoAcceptCredential, CredentialState } from '@credo-ts/core'

const faberAgentOptions = getInMemoryAgentOptions(
  'Faber Agent OOB',
  {
    endpoints: ['rxjs:faber'],
  },
  getAnonCredsIndyModules({
    autoAcceptCredentials: AutoAcceptCredential.ContentApproved,
  })
)
const aliceAgentOptions = getInMemoryAgentOptions(
  'Alice Agent OOB',
  {
    endpoints: ['rxjs:alice'],
  },
  getAnonCredsIndyModules({
    autoAcceptCredentials: AutoAcceptCredential.ContentApproved,
  })
)

describe('out of band', () => {
  const makeConnectionConfig = {
    goal: 'To make a connection',
    goalCode: 'p2p-messaging',
    label: 'Faber College',
    alias: `Faber's connection with Alice`,
    imageUrl: 'http://faber.image.url',
  }

  const issueCredentialConfig = {
    goal: 'To issue a credential',
    goalCode: 'issue-vc',
    label: 'Faber College',
    handshake: false,
  }

  const receiveInvitationConfig = {
    autoAcceptConnection: false,
  }

  let faberAgent: Agent<ReturnType<typeof getAnonCredsIndyModules>>
  let aliceAgent: Agent<ReturnType<typeof getAnonCredsIndyModules>>
  let credentialTemplate: CreateCredentialOfferOptions<[V2CredentialProtocol<[AnonCredsCredentialFormatService]>]>

  beforeAll(async () => {
    const faberMessages = new Subject<SubjectMessage>()
    const aliceMessages = new Subject<SubjectMessage>()
    const subjectMap = {
      'rxjs:faber': faberMessages,
      'rxjs:alice': aliceMessages,
    }

    faberAgent = new Agent(faberAgentOptions)

    faberAgent.registerInboundTransport(new SubjectInboundTransport(faberMessages))
    faberAgent.registerOutboundTransport(new SubjectOutboundTransport(subjectMap))
    await faberAgent.initialize()

    aliceAgent = new Agent(aliceAgentOptions)
    aliceAgent.registerInboundTransport(new SubjectInboundTransport(aliceMessages))
    aliceAgent.registerOutboundTransport(new SubjectOutboundTransport(subjectMap))
    await aliceAgent.initialize()

    await aliceAgent.modules.anoncreds.createLinkSecret()

    const { credentialDefinitionId } = await storePreCreatedAnonCredsDefinition(
      faberAgent,
      anoncredsDefinitionFourAttributesNoRevocation
    )
    credentialTemplate = {
      protocolVersion: 'v2',
      credentialFormats: {
        anoncreds: {
          attributes: [
            {
              name: 'name',
              value: 'name',
            },
            {
              name: 'age',
              value: 'age',
            },
            {
              name: 'profile_picture',
              value: 'profile_picture',
            },
            {
              name: 'x-ray',
              value: 'x-ray',
            },
          ],
          credentialDefinitionId,
        },
      },
      autoAcceptCredential: AutoAcceptCredential.Never,
    }
  })

  afterAll(async () => {
    await faberAgent.shutdown()
    await faberAgent.wallet.delete()
    await aliceAgent.shutdown()
    await aliceAgent.wallet.delete()
  })

  afterEach(async () => {
    const credentials = await aliceAgent.credentials.getAll()
    for (const credential of credentials) {
      await aliceAgent.credentials.deleteById(credential.id)
    }

    const connections = await faberAgent.connections.getAll()
    for (const connection of connections) {
      await faberAgent.connections.deleteById(connection.id)
    }

    jest.resetAllMocks()
  })

  describe('createInvitation', () => {
    test('throw error when there is no handshake or message', async () => {
      await expect(faberAgent.oob.createInvitation({ label: 'test-connection', handshake: false })).rejects.toEqual(
        new CredoError('One or both of handshake_protocols and requests~attach MUST be included in the message.')
      )
    })

    test('throw error when multiUseInvitation is true and messages are provided', async () => {
      await expect(
        faberAgent.oob.createInvitation({
          label: 'test-connection',
          messages: [{} as AgentMessage],
          multiUseInvitation: true,
        })
      ).rejects.toEqual(new CredoError("Attribute 'multiUseInvitation' can not be 'true' when 'messages' is defined."))
    })

    test('handles empty messages array as no messages being passed', async () => {
      await expect(
        faberAgent.oob.createInvitation({
          messages: [],
          handshake: false,
        })
      ).rejects.toEqual(
        new CredoError('One or both of handshake_protocols and requests~attach MUST be included in the message.')
      )
    })

    test('create OOB record', async () => {
      const outOfBandRecord = await faberAgent.oob.createInvitation(makeConnectionConfig)
      // expect contains services

      expect(outOfBandRecord.autoAcceptConnection).toBe(true)
      expect(outOfBandRecord.role).toBe(OutOfBandRole.Sender)
      expect(outOfBandRecord.state).toBe(OutOfBandState.AwaitResponse)
      expect(outOfBandRecord.alias).toBe(makeConnectionConfig.alias)
      expect(outOfBandRecord.reusable).toBe(false)
      expect(outOfBandRecord.outOfBandInvitation.goal).toBe(makeConnectionConfig.goal)
      expect(outOfBandRecord.outOfBandInvitation.goalCode).toBe(makeConnectionConfig.goalCode)
      expect(outOfBandRecord.outOfBandInvitation.label).toBe(makeConnectionConfig.label)
      expect(outOfBandRecord.outOfBandInvitation.imageUrl).toBe(makeConnectionConfig.imageUrl)
    })

    test('create OOB message only with handshake', async () => {
      const { outOfBandInvitation } = await faberAgent.oob.createInvitation(makeConnectionConfig)

      // expect supported handshake protocols
      expect(outOfBandInvitation.handshakeProtocols).toContain('https://didcomm.org/didexchange/1.1')
      expect(outOfBandInvitation.getRequests()).toBeUndefined()

      // expect contains services
      const [service] = outOfBandInvitation.getInlineServices()
      expect(service).toMatchObject(
        new OutOfBandDidCommService({
          id: expect.any(String),
          serviceEndpoint: 'rxjs:faber',
          recipientKeys: [expect.stringContaining('did:key:')],
          routingKeys: [],
        })
      )
    })

    test('create OOB message only with requests', async () => {
      const { message } = await faberAgent.credentials.createOffer(credentialTemplate)
      const { outOfBandInvitation } = await faberAgent.oob.createInvitation({
        label: 'test-connection',
        handshake: false,
        messages: [message],
      })

      // expect supported handshake protocols
      expect(outOfBandInvitation.handshakeProtocols).toBeUndefined()
      expect(outOfBandInvitation.getRequests()).toHaveLength(1)

      // expect contains services
      const [service] = outOfBandInvitation.getServices()
      expect(service).toMatchObject(
        new OutOfBandDidCommService({
          id: expect.any(String),
          serviceEndpoint: 'rxjs:faber',
          recipientKeys: [expect.stringContaining('did:key:')],
          routingKeys: [],
        })
      )
    })

    test('create OOB message with both handshake and requests', async () => {
      const { message } = await faberAgent.credentials.createOffer(credentialTemplate)
      const { outOfBandInvitation } = await faberAgent.oob.createInvitation({
        label: 'test-connection',
        handshakeProtocols: [HandshakeProtocol.Connections],
        messages: [message],
      })

      // expect supported handshake protocols
      expect(outOfBandInvitation.handshakeProtocols).toContain('https://didcomm.org/connections/1.0')
      expect(outOfBandInvitation.getRequests()).toHaveLength(1)

      // expect contains services
      const [service] = outOfBandInvitation.getInlineServices()
      expect(service).toMatchObject(
        new OutOfBandDidCommService({
          id: expect.any(String),
          serviceEndpoint: 'rxjs:faber',
          recipientKeys: [expect.stringMatching('did:key:')],
          routingKeys: [],
        })
      )
    })

    test('emits OutOfBandStateChanged event', async () => {
      const eventListener = jest.fn()

      faberAgent.events.on(OutOfBandEventTypes.OutOfBandStateChanged, eventListener)
      const outOfBandRecord = await faberAgent.oob.createInvitation({
        label: 'test-connection',
        handshake: true,
      })

      faberAgent.events.off(OutOfBandEventTypes.OutOfBandStateChanged, eventListener)

      expect(eventListener).toHaveBeenCalledWith({
        type: OutOfBandEventTypes.OutOfBandStateChanged,
        metadata: {
          contextCorrelationId: 'default',
        },
        payload: {
          outOfBandRecord,
          previousState: null,
        },
      })
    })
  })

  describe('receiveInvitation', () => {
    test('receive OOB connection invitation', async () => {
      const outOfBandRecord = await faberAgent.oob.createInvitation(makeConnectionConfig)
      const { outOfBandInvitation } = outOfBandRecord

      const { outOfBandRecord: receivedOutOfBandRecord, connectionRecord } = await aliceAgent.oob.receiveInvitation(
        outOfBandInvitation,
        {
          autoAcceptInvitation: false,
          autoAcceptConnection: false,
        }
      )

      expect(connectionRecord).not.toBeDefined()
      expect(receivedOutOfBandRecord.role).toBe(OutOfBandRole.Receiver)
      expect(receivedOutOfBandRecord.state).toBe(OutOfBandState.Initial)
      expect(receivedOutOfBandRecord.outOfBandInvitation).toEqual(outOfBandInvitation)
    })

    test(`make a connection with ${HandshakeProtocol.DidExchange} on OOB invitation encoded in URL`, async () => {
      const outOfBandRecord = await faberAgent.oob.createInvitation(makeConnectionConfig)
      const { outOfBandInvitation } = outOfBandRecord
      const urlMessage = outOfBandInvitation.toUrl({ domain: 'http://example.com' })

      // eslint-disable-next-line prefer-const
      let { outOfBandRecord: receivedOutOfBandRecord, connectionRecord: aliceFaberConnection } =
        await aliceAgent.oob.receiveInvitationFromUrl(urlMessage)
      expect(receivedOutOfBandRecord.state).toBe(OutOfBandState.PrepareResponse)

      aliceFaberConnection = await aliceAgent.connections.returnWhenIsConnected(aliceFaberConnection!.id)
      expect(aliceFaberConnection.state).toBe(DidExchangeState.Completed)

      let [faberAliceConnection] = await faberAgent.connections.findAllByOutOfBandId(outOfBandRecord!.id)
      faberAliceConnection = await faberAgent.connections.returnWhenIsConnected(faberAliceConnection!.id)
      expect(faberAliceConnection?.state).toBe(DidExchangeState.Completed)

      expect(aliceFaberConnection).toBeConnectedWith(faberAliceConnection!)
      expect(aliceFaberConnection.imageUrl).toBe(makeConnectionConfig.imageUrl)
      expect(faberAliceConnection).toBeConnectedWith(aliceFaberConnection)
      expect(faberAliceConnection.alias).toBe(makeConnectionConfig.alias)
    })

    test(`make a connection with ${HandshakeProtocol.Connections} based on OOB invitation encoded in URL`, async () => {
      const outOfBandRecord = await faberAgent.oob.createInvitation({
        ...makeConnectionConfig,
        handshakeProtocols: [HandshakeProtocol.Connections],
      })
      const { outOfBandInvitation } = outOfBandRecord
      const urlMessage = outOfBandInvitation.toUrl({ domain: 'http://example.com' })

      let { connectionRecord: aliceFaberConnection } = await aliceAgent.oob.receiveInvitationFromUrl(urlMessage)

      aliceFaberConnection = await aliceAgent.connections.returnWhenIsConnected(aliceFaberConnection!.id)
      expect(aliceFaberConnection.state).toBe(DidExchangeState.Completed)

      let [faberAliceConnection] = await faberAgent.connections.findAllByOutOfBandId(outOfBandRecord!.id)
      faberAliceConnection = await faberAgent.connections.returnWhenIsConnected(faberAliceConnection!.id)
      expect(faberAliceConnection.state).toBe(DidExchangeState.Completed)

      expect(aliceFaberConnection).toBeConnectedWith(faberAliceConnection)
      expect(faberAliceConnection).toBeConnectedWith(aliceFaberConnection)
      expect(faberAliceConnection.alias).toBe(makeConnectionConfig.alias)
    })

    test('make a connection based on old connection invitation encoded in URL', async () => {
      const { outOfBandRecord, invitation } = await faberAgent.oob.createLegacyInvitation(makeConnectionConfig)
      const urlMessage = invitation.toUrl({ domain: 'http://example.com' })

      let { connectionRecord: aliceFaberConnection } = await aliceAgent.oob.receiveInvitationFromUrl(urlMessage)

      aliceFaberConnection = await aliceAgent.connections.returnWhenIsConnected(aliceFaberConnection!.id)
      let [faberAliceConnection] = await faberAgent.connections.findAllByOutOfBandId(outOfBandRecord.id)
      faberAliceConnection = await faberAgent.connections.returnWhenIsConnected(faberAliceConnection!.id)

      expect(aliceFaberConnection.state).toBe(DidExchangeState.Completed)
      expect(faberAliceConnection.state).toBe(DidExchangeState.Completed)

      expect(faberAliceConnection).toBeConnectedWith(aliceFaberConnection)
      expect(aliceFaberConnection).toBeConnectedWith(faberAliceConnection)
    })

    test('make a connection based on old connection invitation with multiple endpoints uses first endpoint for invitation', async () => {
      const { invitation } = await faberAgent.oob.createLegacyInvitation({
        ...makeConnectionConfig,
        routing: {
          endpoints: ['https://endpoint-1.com', 'https://endpoint-2.com'],
          routingKeys: [Key.fromFingerprint('z6MkiP5ghmdLFh1GyGRQQQLVJhJtjQjTpxUY3AnY3h5gu3BE')],
          recipientKey: Key.fromFingerprint('z6MkuXrzmDjBoy7r9LA1Czjv9eQXMGr9gt6JBH8zPUMKkCQH'),
        },
      })

      expect(invitation.serviceEndpoint).toBe('https://endpoint-1.com')
    })

    test('process credential offer requests based on OOB message', async () => {
      const { message } = await faberAgent.credentials.createOffer(credentialTemplate)
      const { outOfBandInvitation } = await faberAgent.oob.createInvitation({
        ...issueCredentialConfig,
        messages: [message],
      })

      const urlMessage = outOfBandInvitation.toUrl({ domain: 'http://example.com' })

      const aliceCredentialRecordPromise = waitForCredentialRecord(aliceAgent, {
        state: CredentialState.OfferReceived,
        threadId: message.threadId,
      })
      await aliceAgent.oob.receiveInvitationFromUrl(urlMessage, receiveInvitationConfig)

      const aliceCredentialRecord = await aliceCredentialRecordPromise
      expect(aliceCredentialRecord.state).toBe(CredentialState.OfferReceived)
    })

    test('process credential offer requests with legacy did:sov prefix on message type based on OOB message', async () => {
      const { message } = await faberAgent.credentials.createOffer(credentialTemplate)

      // we need to override the message type to use the legacy did:sov prefix
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-ignore
      message.type = message.type.replace('https://didcomm.org', 'did:sov:BzCbsNYhMrjHiqZDTUASHg;spec')
      const { outOfBandInvitation } = await faberAgent.oob.createInvitation({
        ...issueCredentialConfig,
        messages: [message],
      })

      const urlMessage = outOfBandInvitation.toUrl({ domain: 'http://example.com' })

      const aliceCredentialRecordPromise = waitForCredentialRecord(aliceAgent, {
        state: CredentialState.OfferReceived,
        threadId: message.threadId,
      })
      await aliceAgent.oob.receiveInvitationFromUrl(urlMessage, receiveInvitationConfig)

      const aliceCredentialRecord = await aliceCredentialRecordPromise
      expect(aliceCredentialRecord.state).toBe(CredentialState.OfferReceived)
    })

    test('do not process requests when a connection is not ready', async () => {
      const eventListener = jest.fn()
      aliceAgent.events.on<AgentMessageReceivedEvent>(AgentEventTypes.AgentMessageReceived, eventListener)

      const { message } = await faberAgent.credentials.createOffer(credentialTemplate)
      const { outOfBandInvitation } = await faberAgent.oob.createInvitation({
        ...makeConnectionConfig,
        messages: [message],
      })

      // First, we crate a connection but we won't accept it, therefore it won't be ready
      await aliceAgent.oob.receiveInvitation(outOfBandInvitation, { autoAcceptConnection: false })

      // Event should not be emitted because an agent must wait until the connection is ready
      expect(eventListener).toHaveBeenCalledTimes(0)

      aliceAgent.events.off<AgentMessageReceivedEvent>(AgentEventTypes.AgentMessageReceived, eventListener)
    })

    test('make a connection based on OOB invitation and process requests after the acceptation', async () => {
      const { message } = await faberAgent.credentials.createOffer(credentialTemplate)
      const outOfBandRecord = await faberAgent.oob.createInvitation({
        ...makeConnectionConfig,
        messages: [message],
      })
      const { outOfBandInvitation } = outOfBandRecord

      // First, we crate a connection but we won't accept it, therefore it won't be ready
      const { outOfBandRecord: aliceFaberOutOfBandRecord } = await aliceAgent.oob.receiveInvitation(
        outOfBandInvitation,
        {
          autoAcceptInvitation: false,
          autoAcceptConnection: false,
        }
      )

      const aliceCredentialRecordPromise = waitForCredentialRecord(aliceAgent, {
        state: CredentialState.OfferReceived,
        threadId: message.threadId,
        // We need to create the connection beforehand so it can take a while to complete
        timeoutMs: 20000,
      })

      // Accept connection invitation
      let { connectionRecord: aliceFaberConnection } = await aliceAgent.oob.acceptInvitation(
        aliceFaberOutOfBandRecord.id,
        {
          label: 'alice',
          autoAcceptConnection: true,
        }
      )

      // Wait until connection is ready
      aliceFaberConnection = await aliceAgent.connections.returnWhenIsConnected(aliceFaberConnection!.id)

      let [faberAliceConnection] = await faberAgent.connections.findAllByOutOfBandId(outOfBandRecord!.id)
      faberAliceConnection = await faberAgent.connections.returnWhenIsConnected(faberAliceConnection!.id)
      expect(faberAliceConnection).toBeConnectedWith(aliceFaberConnection)
      expect(aliceFaberConnection).toBeConnectedWith(faberAliceConnection)

      const aliceCredentialRecord = await aliceCredentialRecordPromise
      expect(aliceCredentialRecord.state).toBe(CredentialState.OfferReceived)
    })

    test('do not create a new connection when no messages and handshake reuse succeeds', async () => {
      const aliceReuseListener = jest.fn()
      const faberReuseListener = jest.fn()

      // Create first connection
      const outOfBandRecord = await faberAgent.oob.createInvitation(makeConnectionConfig)
      let { connectionRecord: firstAliceFaberConnection } = await aliceAgent.oob.receiveInvitation(
        outOfBandRecord.outOfBandInvitation
      )
      firstAliceFaberConnection = await aliceAgent.connections.returnWhenIsConnected(firstAliceFaberConnection!.id)

      const [firstFaberAliceConnection] = await faberAgent.connections.findAllByOutOfBandId(outOfBandRecord.id)

      // Create second connection
      const outOfBandRecord2 = await faberAgent.oob.createInvitation(makeConnectionConfig)

      // Take over the recipientKeys from the first invitation so they match when encoded
      const [firstInvitationService] = outOfBandRecord.outOfBandInvitation.getInlineServices()
      const [secondInvitationService] = outOfBandRecord2.outOfBandInvitation.getInlineServices()
      secondInvitationService.recipientKeys = firstInvitationService.recipientKeys

      aliceAgent.events.on(OutOfBandEventTypes.HandshakeReused, aliceReuseListener)
      faberAgent.events.on(OutOfBandEventTypes.HandshakeReused, faberReuseListener)

      const {
        connectionRecord: secondAliceFaberConnection,
        outOfBandRecord: { id: secondOobRecordId },
      } = await aliceAgent.oob.receiveInvitation(outOfBandRecord2.outOfBandInvitation, { reuseConnection: true })

      aliceAgent.events.off(OutOfBandEventTypes.HandshakeReused, aliceReuseListener)
      faberAgent.events.off(OutOfBandEventTypes.HandshakeReused, faberReuseListener)
      await aliceAgent.connections.returnWhenIsConnected(secondAliceFaberConnection!.id)

      // There shouldn't be any connection records for this oob id, as we reused an existing one
      expect((await faberAgent.connections.findAllByOutOfBandId(secondOobRecordId)).length).toBe(0)

      expect(firstAliceFaberConnection.id).toEqual(secondAliceFaberConnection?.id)

      expect(faberReuseListener).toHaveBeenCalledTimes(1)
      expect(aliceReuseListener).toHaveBeenCalledTimes(1)
      const [[faberEvent]] = faberReuseListener.mock.calls
      const [[aliceEvent]] = aliceReuseListener.mock.calls

      const reuseThreadId = faberEvent.payload.reuseThreadId

      expect(faberEvent).toMatchObject({
        type: OutOfBandEventTypes.HandshakeReused,
        payload: {
          connectionRecord: {
            id: firstFaberAliceConnection.id,
          },
          outOfBandRecord: {
            id: outOfBandRecord2.id,
          },
          reuseThreadId,
        },
      })

      expect(aliceEvent).toMatchObject({
        type: OutOfBandEventTypes.HandshakeReused,
        payload: {
          connectionRecord: {
            id: firstAliceFaberConnection.id,
          },
          outOfBandRecord: {
            id: secondOobRecordId,
          },
          reuseThreadId,
        },
      })
    })

    test('create a new connection when connection exists and reuse is false', async () => {
      const reuseListener = jest.fn()

      // Create first connection
      const outOfBandRecord = await faberAgent.oob.createInvitation(makeConnectionConfig)
      let { connectionRecord: firstAliceFaberConnection } = await aliceAgent.oob.receiveInvitation(
        outOfBandRecord.outOfBandInvitation
      )
      firstAliceFaberConnection = await aliceAgent.connections.returnWhenIsConnected(firstAliceFaberConnection!.id)

      // Create second connection
      const outOfBandRecord2 = await faberAgent.oob.createInvitation(makeConnectionConfig)

      aliceAgent.events.on(OutOfBandEventTypes.HandshakeReused, reuseListener)
      faberAgent.events.on(OutOfBandEventTypes.HandshakeReused, reuseListener)

      const { connectionRecord: secondAliceFaberConnection } = await aliceAgent.oob.receiveInvitation(
        outOfBandRecord2.outOfBandInvitation,
        { reuseConnection: false }
      )

      aliceAgent.events.off(OutOfBandEventTypes.HandshakeReused, reuseListener)
      faberAgent.events.off(OutOfBandEventTypes.HandshakeReused, reuseListener)
      await aliceAgent.connections.returnWhenIsConnected(secondAliceFaberConnection!.id)

      // If we're not reusing the connection, the reuse listener shouldn't be called
      expect(reuseListener).not.toHaveBeenCalled()
      expect(firstAliceFaberConnection.id).not.toEqual(secondAliceFaberConnection?.id)

      const faberConnections = await faberAgent.connections.getAll()
      let [firstFaberAliceConnection, secondFaberAliceConnection] = faberConnections
      firstFaberAliceConnection = await faberAgent.connections.returnWhenIsConnected(firstFaberAliceConnection.id)
      secondFaberAliceConnection = await faberAgent.connections.returnWhenIsConnected(secondFaberAliceConnection.id)

      // expect the two connections contain the two out of band ids
      expect(faberConnections.map((c) => c.outOfBandId)).toEqual(
        expect.arrayContaining([outOfBandRecord.id, outOfBandRecord2.id])
      )

      expect(faberConnections).toHaveLength(2)
      expect(firstFaberAliceConnection.state).toBe(DidExchangeState.Completed)
      expect(secondFaberAliceConnection.state).toBe(DidExchangeState.Completed)
    })

    test('throws an error when the invitation has already been received', async () => {
      const outOfBandRecord = await faberAgent.oob.createInvitation(makeConnectionConfig)
      const { outOfBandInvitation } = outOfBandRecord

      const { connectionRecord: aliceFaberConnection } = await aliceAgent.oob.receiveInvitation(outOfBandInvitation)

      // Wait until connection is ready
      await aliceAgent.connections.returnWhenIsConnected(aliceFaberConnection!.id)

      const [faberAliceConnection] = await faberAgent.connections.findAllByOutOfBandId(outOfBandRecord.id)
      await faberAgent.connections.returnWhenIsConnected(faberAliceConnection!.id)

      // Try to receive the invitation again
      await expect(aliceAgent.oob.receiveInvitation(outOfBandInvitation)).rejects.toThrow(
        new CredoError(
          `An out of band record with invitation ${outOfBandInvitation.id} has already been received. Invitations should have a unique id.`
        )
      )
    })

    test('emits OutOfBandStateChanged event', async () => {
      const eventListener = jest.fn()
      const { outOfBandInvitation, id } = await faberAgent.oob.createInvitation(makeConnectionConfig)

      aliceAgent.events.on(OutOfBandEventTypes.OutOfBandStateChanged, eventListener)

      const { outOfBandRecord, connectionRecord } = await aliceAgent.oob.receiveInvitation(outOfBandInvitation, {
        autoAcceptConnection: true,
        autoAcceptInvitation: true,
      })

      // Wait for the connection to complete so we don't get wallet closed errors
      await aliceAgent.connections.returnWhenIsConnected(connectionRecord!.id)
      aliceAgent.events.off(OutOfBandEventTypes.OutOfBandStateChanged, eventListener)

      const [faberAliceConnection] = await faberAgent.connections.findAllByOutOfBandId(id)
      await faberAgent.connections.returnWhenIsConnected(faberAliceConnection.id)

      // Receiving the invitation
      expect(eventListener).toHaveBeenNthCalledWith(1, {
        type: OutOfBandEventTypes.OutOfBandStateChanged,
        metadata: {
          contextCorrelationId: 'default',
        },
        payload: {
          outOfBandRecord: expect.objectContaining({ state: OutOfBandState.Initial }),
          previousState: null,
        },
      })

      // Accepting the invitation
      expect(eventListener).toHaveBeenNthCalledWith(2, {
        type: OutOfBandEventTypes.OutOfBandStateChanged,
        metadata: {
          contextCorrelationId: 'default',
        },
        payload: {
          outOfBandRecord,
          previousState: OutOfBandState.Initial,
        },
      })
    })

    test.skip('do not create a new connection when connection exists and multiuse is false', async () => {
      const outOfBandRecord = await faberAgent.oob.createInvitation({
        ...makeConnectionConfig,
        multiUseInvitation: false,
      })
      const { outOfBandInvitation } = outOfBandRecord

      let { connectionRecord: firstAliceFaberConnection } = await aliceAgent.oob.receiveInvitation(outOfBandInvitation)
      firstAliceFaberConnection = await aliceAgent.connections.returnWhenIsConnected(firstAliceFaberConnection!.id)

      await aliceAgent.oob.receiveInvitation(outOfBandInvitation)

      // TODO Somehow check agents throws an error or sends problem report

      let [faberAliceConnection] = await faberAgent.connections.findAllByOutOfBandId(outOfBandRecord!.id)
      faberAliceConnection = await faberAgent.connections.returnWhenIsConnected(faberAliceConnection!.id)

      const faberConnections = await faberAgent.connections.getAll()
      expect(faberConnections).toHaveLength(1)
      expect(faberAliceConnection.state).toBe(DidExchangeState.Completed)
      expect(firstAliceFaberConnection.state).toBe(DidExchangeState.Completed)
    })

    test('throw an error when handshake protocols are not supported', async () => {
      const outOfBandInvitation = new OutOfBandInvitation({ label: 'test-connection', services: [] })
      const unsupportedProtocol = 'https://didcomm.org/unsupported-connections-protocol/1.0'
      outOfBandInvitation.handshakeProtocols = [unsupportedProtocol as HandshakeProtocol]

      await expect(aliceAgent.oob.receiveInvitation(outOfBandInvitation, receiveInvitationConfig)).rejects.toEqual(
        new CredoError(
          `Handshake protocols [${unsupportedProtocol}] are not supported. Supported protocols are [https://didcomm.org/didexchange/1.x,https://didcomm.org/connections/1.x]`
        )
      )
    })

    test('throw an error when the OOB message does not contain either handshake or requests', async () => {
      const outOfBandInvitation = new OutOfBandInvitation({ label: 'test-connection', services: [] })

      await expect(aliceAgent.oob.receiveInvitation(outOfBandInvitation, receiveInvitationConfig)).rejects.toEqual(
        new CredoError('One or both of handshake_protocols and requests~attach MUST be included in the message.')
      )
    })

    test('throw an error when the OOB message contains unsupported message request', async () => {
      const testMessage = new TestMessage()
      testMessage.type = 'https://didcomm.org/test-protocol/1.0/test-message'
      const { outOfBandInvitation } = await faberAgent.oob.createInvitation({
        ...issueCredentialConfig,
        messages: [testMessage],
      })

      await expect(aliceAgent.oob.receiveInvitation(outOfBandInvitation, receiveInvitationConfig)).rejects.toEqual(
        new CredoError('There is no message in requests~attach supported by agent.')
      )
    })

    test(`make two connections with ${HandshakeProtocol.DidExchange} by reusing the did from the first connection as the 'invitationDid' in oob invitation for the second connection`, async () => {
      const outOfBandRecord1 = await faberAgent.oob.createInvitation({})

      let { connectionRecord: aliceFaberConnection } = await aliceAgent.oob.receiveInvitation(
        outOfBandRecord1.outOfBandInvitation
      )

      aliceFaberConnection = await aliceAgent.connections.returnWhenIsConnected(aliceFaberConnection!.id)
      expect(aliceFaberConnection.state).toBe(DidExchangeState.Completed)

      let [faberAliceConnection] = await faberAgent.connections.findAllByOutOfBandId(outOfBandRecord1!.id)
      faberAliceConnection = await faberAgent.connections.returnWhenIsConnected(faberAliceConnection!.id)
      expect(faberAliceConnection?.state).toBe(DidExchangeState.Completed)

      // Use the invitation did from the first connection to create the second connection
      const outOfBandRecord2 = await faberAgent.oob.createInvitation({
        invitationDid: outOfBandRecord1.outOfBandInvitation.invitationDids[0],
      })

      let { connectionRecord: aliceFaberConnection2 } = await aliceAgent.oob.receiveInvitation(
        outOfBandRecord2.outOfBandInvitation
      )
      aliceFaberConnection2 = await aliceAgent.connections.returnWhenIsConnected(aliceFaberConnection2!.id)
      expect(aliceFaberConnection2.state).toBe(DidExchangeState.Completed)

      let [faberAliceConnection2] = await faberAgent.connections.findAllByOutOfBandId(outOfBandRecord2!.id)
      faberAliceConnection2 = await faberAgent.connections.returnWhenIsConnected(faberAliceConnection2!.id)
      expect(faberAliceConnection2?.state).toBe(DidExchangeState.Completed)
    })
  })

  describe('messages and connection exchange', () => {
    test('oob exchange with handshake where response is received to invitation', async () => {
      const { message } = await faberAgent.credentials.createOffer(credentialTemplate)
      const outOfBandRecord = await faberAgent.oob.createInvitation({
        handshake: true,
        messages: [message],
      })
      const { outOfBandInvitation } = outOfBandRecord

      await aliceAgent.oob.receiveInvitation(outOfBandInvitation)

      const aliceCredentialRecordPromise = waitForCredentialRecord(aliceAgent, {
        state: CredentialState.OfferReceived,
        threadId: message.threadId,
        timeoutMs: 10000,
      })

      const aliceCredentialRecord = await aliceCredentialRecordPromise
      expect(aliceCredentialRecord.state).toBe(CredentialState.OfferReceived)

      // If we receive the event, we know the processing went well
      const faberCredentialRecordPromise = waitForCredentialRecord(faberAgent, {
        state: CredentialState.RequestReceived,
        threadId: message.threadId,
        timeoutMs: 10000,
      })

      await aliceAgent.credentials.acceptOffer({
        credentialRecordId: aliceCredentialRecord.id,
      })

      await faberCredentialRecordPromise
    })

    test('oob exchange with reuse where response is received to invitation', async () => {
      const { message } = await faberAgent.credentials.createOffer(credentialTemplate)

      const routing = await faberAgent.mediationRecipient.getRouting({})
      const connectionOutOfBandRecord = await faberAgent.oob.createInvitation({
        routing,
      })

      // Create connection
      const { connectionRecord } = await aliceAgent.oob.receiveInvitation(connectionOutOfBandRecord.outOfBandInvitation)
      if (!connectionRecord) throw new Error('Connection record is undefined')
      await aliceAgent.connections.returnWhenIsConnected(connectionRecord.id)

      // Create offer and reuse
      const outOfBandRecord = await faberAgent.oob.createInvitation({
        routing,
        messages: [message],
      })
      // Create connection
      const { connectionRecord: offerConnectionRecord } = await aliceAgent.oob.receiveInvitation(
        outOfBandRecord.outOfBandInvitation,
        {
          reuseConnection: true,
        }
      )
      if (!offerConnectionRecord) throw new Error('Connection record is undefined')

      // Should be the same, as connection is reused.
      expect(offerConnectionRecord.id).toEqual(connectionRecord.id)

      const aliceCredentialRecordPromise = waitForCredentialRecord(aliceAgent, {
        state: CredentialState.OfferReceived,
        threadId: message.threadId,
        timeoutMs: 10000,
      })

      const aliceCredentialRecord = await aliceCredentialRecordPromise
      expect(aliceCredentialRecord.state).toBe(CredentialState.OfferReceived)

      // If we receive the event, we know the processing went well
      const faberCredentialRecordPromise = waitForCredentialRecord(faberAgent, {
        state: CredentialState.RequestReceived,
        threadId: message.threadId,
        timeoutMs: 10000,
      })

      await aliceAgent.credentials.acceptOffer({
        credentialRecordId: aliceCredentialRecord.id,
      })

      await faberCredentialRecordPromise
    })
  })

  describe('connection-less exchange', () => {
    test('oob exchange without handshake where response is received to invitation', async () => {
      const { message } = await faberAgent.credentials.createOffer(credentialTemplate)
      const outOfBandRecord = await faberAgent.oob.createInvitation({
        handshake: false,
        messages: [message],
      })
      const { outOfBandInvitation } = outOfBandRecord

      await aliceAgent.oob.receiveInvitation(outOfBandInvitation)

      const aliceCredentialRecordPromise = waitForCredentialRecord(aliceAgent, {
        state: CredentialState.OfferReceived,
        threadId: message.threadId,
        timeoutMs: 10000,
      })

      const aliceCredentialRecord = await aliceCredentialRecordPromise
      expect(aliceCredentialRecord.state).toBe(CredentialState.OfferReceived)

      // If we receive the event, we know the processing went well
      const faberCredentialRecordPromise = waitForCredentialRecord(faberAgent, {
        state: CredentialState.RequestReceived,
        threadId: message.threadId,
        timeoutMs: 10000,
      })

      await aliceAgent.credentials.acceptOffer({
        credentialRecordId: aliceCredentialRecord.id,
      })

      await faberCredentialRecordPromise
    })

    test('oob exchange without handshake where response is received and custom routing is used on recipient', async () => {
      const { message } = await faberAgent.credentials.createOffer(credentialTemplate)
      const outOfBandRecord = await faberAgent.oob.createInvitation({
        handshake: false,
        messages: [message],
      })
      const { outOfBandInvitation } = outOfBandRecord

      const routing = await aliceAgent.mediationRecipient.getRouting({})

      await aliceAgent.oob.receiveInvitation(outOfBandInvitation, {
        routing,
      })

      const aliceCredentialRecordPromise = waitForCredentialRecord(aliceAgent, {
        state: CredentialState.OfferReceived,
        threadId: message.threadId,
        timeoutMs: 10000,
      })

      const aliceCredentialRecord = await aliceCredentialRecordPromise
      expect(aliceCredentialRecord.state).toBe(CredentialState.OfferReceived)

      // If we receive the event, we know the processing went well
      const faberCredentialRecordPromise = waitForCredentialRecord(faberAgent, {
        state: CredentialState.RequestReceived,
        threadId: message.threadId,
        timeoutMs: 10000,
      })

      await aliceAgent.credentials.acceptOffer({
        credentialRecordId: aliceCredentialRecord.id,
      })

      const faberCredentialRecord = await faberCredentialRecordPromise

      const faberCredentialRequest = await faberAgent.credentials.findRequestMessage(faberCredentialRecord.id)

      expect(JsonTransformer.toJSON(faberCredentialRequest?.service)).toEqual({
        recipientKeys: [routing.recipientKey.publicKeyBase58],
        serviceEndpoint: routing.endpoints[0],
        routingKeys: routing.routingKeys.map((r) => r.publicKeyBase58),
      })
    })

    test('legacy connectionless exchange where response is received to invitation', async () => {
      const { message, credentialRecord } = await faberAgent.credentials.createOffer(credentialTemplate)
      const { invitationUrl } = await faberAgent.oob.createLegacyConnectionlessInvitation({
        domain: 'http://example.com',
        message,
        recordId: credentialRecord.id,
      })

      const aliceCredentialRecordPromise = waitForCredentialRecord(aliceAgent, {
        state: CredentialState.OfferReceived,
        threadId: message.threadId,
        timeoutMs: 10000,
      })
      await aliceAgent.oob.receiveInvitationFromUrl(invitationUrl)

      const aliceCredentialRecord = await aliceCredentialRecordPromise
      expect(aliceCredentialRecord.state).toBe(CredentialState.OfferReceived)

      // If we receive the event, we know the processing went well
      const faberCredentialRecordPromise = waitForCredentialRecord(faberAgent, {
        state: CredentialState.RequestReceived,
        threadId: message.threadId,
        timeoutMs: 10000,
      })

      await aliceAgent.credentials.acceptOffer({
        credentialRecordId: aliceCredentialRecord.id,
      })

      await faberCredentialRecordPromise
    })

    test('legacy connectionless exchange where response is received to invitation and custom routing is used on recipient', async () => {
      const { message, credentialRecord } = await faberAgent.credentials.createOffer(credentialTemplate)
      const { invitationUrl } = await faberAgent.oob.createLegacyConnectionlessInvitation({
        domain: 'http://example.com',
        message,
        recordId: credentialRecord.id,
      })

      const routing = await aliceAgent.mediationRecipient.getRouting({})

      const aliceCredentialRecordPromise = waitForCredentialRecord(aliceAgent, {
        state: CredentialState.OfferReceived,
        threadId: message.threadId,
        timeoutMs: 10000,
      })
      await aliceAgent.oob.receiveInvitationFromUrl(invitationUrl, { routing })

      const aliceCredentialRecord = await aliceCredentialRecordPromise
      expect(aliceCredentialRecord.state).toBe(CredentialState.OfferReceived)

      // If we receive the event, we know the processing went well
      const faberCredentialRecordPromise = waitForCredentialRecord(faberAgent, {
        state: CredentialState.RequestReceived,
        threadId: message.threadId,
        timeoutMs: 10000,
      })

      await aliceAgent.credentials.acceptOffer({
        credentialRecordId: aliceCredentialRecord.id,
      })

      const faberCredentialRecord = await faberCredentialRecordPromise

      const faberCredentialRequest = await faberAgent.credentials.findRequestMessage(faberCredentialRecord.id)

      expect(JsonTransformer.toJSON(faberCredentialRequest?.service)).toEqual({
        recipientKeys: [routing.recipientKey.publicKeyBase58],
        serviceEndpoint: routing.endpoints[0],
        routingKeys: routing.routingKeys.map((r) => r.publicKeyBase58),
      })
    })

    test('legacy connectionless exchange without receiving message through oob receiveInvitation, where response is received to invitation', async () => {
      const { message, credentialRecord } = await faberAgent.credentials.createOffer(credentialTemplate)
      const { message: messageWithService } = await faberAgent.oob.createLegacyConnectionlessInvitation({
        domain: 'http://example.com',
        message,
        recordId: credentialRecord.id,
      })

      const aliceCredentialRecordPromise = waitForCredentialRecord(aliceAgent, {
        state: CredentialState.OfferReceived,
        threadId: message.threadId,
        timeoutMs: 10000,
      })
      await aliceAgent.receiveMessage(messageWithService.toJSON())

      const aliceCredentialRecord = await aliceCredentialRecordPromise
      expect(aliceCredentialRecord.state).toBe(CredentialState.OfferReceived)

      // If we receive the event, we know the processing went well
      const faberCredentialRecordPromise = waitForCredentialRecord(faberAgent, {
        state: CredentialState.RequestReceived,
        threadId: message.threadId,
        timeoutMs: 10000,
      })

      await aliceAgent.credentials.acceptOffer({
        credentialRecordId: aliceCredentialRecord.id,
      })

      await faberCredentialRecordPromise
    })

    test('add ~service decorator to the message and returns invitation url in createLegacyConnectionlessInvitation', async () => {
      const { message, credentialRecord } = await faberAgent.credentials.createOffer(credentialTemplate)

      const { message: offerMessage, invitationUrl } = await faberAgent.oob.createLegacyConnectionlessInvitation({
        recordId: credentialRecord.id,
        domain: 'https://test.com',
        message,
      })

      expect(offerMessage.service).toMatchObject({
        serviceEndpoint: expect.any(String),
        recipientKeys: [expect.any(String)],
        routingKeys: [],
      })

      expect(invitationUrl).toEqual(expect.stringContaining('https://test.com?d_m='))

      const messageBase64 = invitationUrl.split('https://test.com?d_m=')[1]

      expect(JsonEncoder.fromBase64(messageBase64)).toMatchObject({
        '@id': expect.any(String),
        '@type': 'https://didcomm.org/issue-credential/2.0/offer-credential',
      })
    })
  })
})
