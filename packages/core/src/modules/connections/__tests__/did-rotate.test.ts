/* eslint-disable @typescript-eslint/no-non-null-assertion */

import { ReplaySubject, first, firstValueFrom, timeout } from 'rxjs'

import { MessageSender } from '../../..//agent/MessageSender'
import { setupSubjectTransports, testLogger } from '../../../../tests'
import {
  getInMemoryAgentOptions,
  makeConnection,
  waitForAgentMessageProcessedEvent,
  waitForBasicMessage,
  waitForDidRotate,
} from '../../../../tests/helpers'
import { Agent } from '../../../agent/Agent'
import { getOutboundMessageContext } from '../../../agent/getOutboundMessageContext'
import { RecordNotFoundError } from '../../../error'
import { uuid } from '../../../utils/uuid'
import { BasicMessage } from '../../basic-messages'
import { createPeerDidDocumentFromServices } from '../../dids'
import { ConnectionsModule } from '../ConnectionsModule'
import { DidRotateProblemReportMessage, HangupMessage, DidRotateAckMessage } from '../messages'
import { ConnectionRecord } from '../repository'

import { InMemoryDidRegistry } from './InMemoryDidRegistry'

// This is the most common flow
describe('Rotation E2E tests', () => {
  let aliceAgent: Agent
  let bobAgent: Agent
  let aliceBobConnection: ConnectionRecord | undefined
  let bobAliceConnection: ConnectionRecord | undefined

  beforeEach(async () => {
    const aliceAgentOptions = getInMemoryAgentOptions(
      'DID Rotate Alice',
      {
        label: 'alice',
        endpoints: ['rxjs:alice'],
        logger: testLogger,
      },
      {
        connections: new ConnectionsModule({
          autoAcceptConnections: true,
        }),
      }
    )
    const bobAgentOptions = getInMemoryAgentOptions(
      'DID Rotate Bob',
      {
        label: 'bob',
        endpoints: ['rxjs:bob'],
        logger: testLogger,
      },
      {
        connections: new ConnectionsModule({
          autoAcceptConnections: true,
        }),
      }
    )

    aliceAgent = new Agent(aliceAgentOptions)
    bobAgent = new Agent(bobAgentOptions)

    setupSubjectTransports([aliceAgent, bobAgent])
    await aliceAgent.initialize()
    await bobAgent.initialize()
    ;[aliceBobConnection, bobAliceConnection] = await makeConnection(aliceAgent, bobAgent)
  })

  afterEach(async () => {
    await aliceAgent.shutdown()
    await aliceAgent.wallet.delete()
    await bobAgent.shutdown()
    await bobAgent.wallet.delete()
  })

  describe('Rotation from did:peer:1 to did:peer:4', () => {
    test('Rotate succesfully and send messages to new did afterwards', async () => {
      const oldDid = aliceBobConnection!.did
      expect(bobAliceConnection!.theirDid).toEqual(oldDid)

      // Send message to initial did
      await bobAgent.basicMessages.sendMessage(bobAliceConnection!.id, 'Hello initial did')

      await waitForBasicMessage(aliceAgent, { content: 'Hello initial did' })

      // Do did rotate
      const { newDid } = await aliceAgent.connections.rotate({ connectionId: aliceBobConnection!.id })

      // Wait for acknowledge
      await waitForAgentMessageProcessedEvent(aliceAgent, { messageType: DidRotateAckMessage.type.messageTypeUri })

      // Check that new did is taken into account by both parties
      const newAliceBobConnection = await aliceAgent.connections.getById(aliceBobConnection!.id)
      const newBobAliceConnection = await bobAgent.connections.getById(bobAliceConnection!.id)

      expect(newAliceBobConnection.did).toEqual(newDid)
      expect(newBobAliceConnection.theirDid).toEqual(newDid)

      // And also they store it into previous dids array
      expect(newAliceBobConnection.previousDids).toContain(oldDid)
      expect(newBobAliceConnection.previousTheirDids).toContain(oldDid)

      // Send message to new did
      await bobAgent.basicMessages.sendMessage(bobAliceConnection!.id, 'Hello new did')

      await waitForBasicMessage(aliceAgent, { content: 'Hello new did', connectionId: aliceBobConnection!.id })
    })

    test('Rotate succesfully and send messages to previous did afterwards', async () => {
      // Send message to initial did
      await bobAgent.basicMessages.sendMessage(bobAliceConnection!.id, 'Hello initial did')

      await waitForBasicMessage(aliceAgent, { content: 'Hello initial did' })

      const messageToPreviousDid = await getOutboundMessageContext(bobAgent.context, {
        message: new BasicMessage({ content: 'Message to previous did' }),
        connectionRecord: bobAliceConnection,
      })

      // Do did rotate
      await aliceAgent.connections.rotate({ connectionId: aliceBobConnection!.id })

      // Wait for acknowledge
      await waitForAgentMessageProcessedEvent(aliceAgent, { messageType: DidRotateAckMessage.type.messageTypeUri })

      // Send message to previous did
      await bobAgent.dependencyManager.resolve(MessageSender).sendMessage(messageToPreviousDid)

      await waitForBasicMessage(aliceAgent, {
        content: 'Message to previous did',
        connectionId: aliceBobConnection!.id,
      })
    })
  })

  describe('Rotation specifying did and routing externally', () => {
    test('Rotate succesfully and send messages to new did afterwards', async () => {
      const oldDid = aliceBobConnection!.did
      expect(bobAliceConnection!.theirDid).toEqual(oldDid)

      // Send message to initial did
      await bobAgent.basicMessages.sendMessage(bobAliceConnection!.id, 'Hello initial did')

      await waitForBasicMessage(aliceAgent, { content: 'Hello initial did' })

      // Create a new external did

      // Make a common in-memory did registry for both agents
      const didRegistry = new InMemoryDidRegistry()
      aliceAgent.dids.config.addRegistrar(didRegistry)
      aliceAgent.dids.config.addResolver(didRegistry)
      bobAgent.dids.config.addRegistrar(didRegistry)
      bobAgent.dids.config.addResolver(didRegistry)

      const didRouting = await aliceAgent.mediationRecipient.getRouting({})
      const did = `did:inmemory:${uuid()}`
      const didDocument = createPeerDidDocumentFromServices([
        {
          id: 'didcomm',
          recipientKeys: [didRouting.recipientKey],
          routingKeys: didRouting.routingKeys,
          serviceEndpoint: didRouting.endpoints[0],
        },
      ])
      didDocument.id = did

      await aliceAgent.dids.create({
        did,
        didDocument,
      })

      // Do did rotate
      const { newDid } = await aliceAgent.connections.rotate({
        connectionId: aliceBobConnection!.id,
        toDid: did,
      })

      // Wait for acknowledge
      await waitForAgentMessageProcessedEvent(aliceAgent, { messageType: DidRotateAckMessage.type.messageTypeUri })

      // Check that new did is taken into account by both parties
      const newAliceBobConnection = await aliceAgent.connections.getById(aliceBobConnection!.id)
      const newBobAliceConnection = await bobAgent.connections.getById(bobAliceConnection!.id)

      expect(newAliceBobConnection.did).toEqual(newDid)
      expect(newBobAliceConnection.theirDid).toEqual(newDid)

      // And also they store it into previous dids array
      expect(newAliceBobConnection.previousDids).toContain(oldDid)
      expect(newBobAliceConnection.previousTheirDids).toContain(oldDid)

      // Send message to new did
      await bobAgent.basicMessages.sendMessage(bobAliceConnection!.id, 'Hello new did')

      await waitForBasicMessage(aliceAgent, { content: 'Hello new did', connectionId: aliceBobConnection!.id })
    })

    test('Rotate succesfully and send messages to previous did afterwards', async () => {
      // Send message to initial did
      await bobAgent.basicMessages.sendMessage(bobAliceConnection!.id, 'Hello initial did')

      await waitForBasicMessage(aliceAgent, { content: 'Hello initial did' })

      const messageToPreviousDid = await getOutboundMessageContext(bobAgent.context, {
        message: new BasicMessage({ content: 'Message to previous did' }),
        connectionRecord: bobAliceConnection,
      })

      // Create a new external did

      // Make a common in-memory did registry for both agents
      const didRegistry = new InMemoryDidRegistry()
      aliceAgent.dids.config.addRegistrar(didRegistry)
      aliceAgent.dids.config.addResolver(didRegistry)
      bobAgent.dids.config.addRegistrar(didRegistry)
      bobAgent.dids.config.addResolver(didRegistry)

      const didRouting = await aliceAgent.mediationRecipient.getRouting({})
      const did = `did:inmemory:${uuid()}`
      const didDocument = createPeerDidDocumentFromServices([
        {
          id: 'didcomm',
          recipientKeys: [didRouting.recipientKey],
          routingKeys: didRouting.routingKeys,
          serviceEndpoint: didRouting.endpoints[0],
        },
      ])
      didDocument.id = did

      await aliceAgent.dids.create({
        did,
        didDocument,
      })

      const waitForAllDidRotate = Promise.all([waitForDidRotate(aliceAgent, {}), waitForDidRotate(bobAgent, {})])

      // Do did rotate
      await aliceAgent.connections.rotate({ connectionId: aliceBobConnection!.id, toDid: did })

      // Wait for acknowledge
      await waitForAgentMessageProcessedEvent(aliceAgent, { messageType: DidRotateAckMessage.type.messageTypeUri })
      const [firstRotate, secondRotate] = await waitForAllDidRotate

      const preRotateDid = aliceBobConnection!.did
      expect(firstRotate).toEqual({
        connectionRecord: expect.any(ConnectionRecord),
        ourDid: {
          from: preRotateDid,
          to: did,
        },
        theirDid: undefined,
      })

      expect(secondRotate).toEqual({
        connectionRecord: expect.any(ConnectionRecord),
        ourDid: undefined,
        theirDid: {
          from: preRotateDid,
          to: did,
        },
      })

      // Send message to previous did
      await bobAgent.dependencyManager.resolve(MessageSender).sendMessage(messageToPreviousDid)

      await waitForBasicMessage(aliceAgent, {
        content: 'Message to previous did',
        connectionId: aliceBobConnection!.id,
      })
    })

    test('Rotate failed and send messages to previous did afterwards', async () => {
      // Send message to initial did
      await bobAgent.basicMessages.sendMessage(bobAliceConnection!.id, 'Hello initial did')

      await waitForBasicMessage(aliceAgent, { content: 'Hello initial did' })

      const messageToPreviousDid = await getOutboundMessageContext(bobAgent.context, {
        message: new BasicMessage({ content: 'Message to previous did' }),
        connectionRecord: bobAliceConnection,
      })

      // Create a new external did

      // Use custom registry only for Alice agent, in order to force an error on Bob side
      const didRegistry = new InMemoryDidRegistry()
      aliceAgent.dids.config.addRegistrar(didRegistry)
      aliceAgent.dids.config.addResolver(didRegistry)

      const didRouting = await aliceAgent.mediationRecipient.getRouting({})
      const did = `did:inmemory:${uuid()}`
      const didDocument = createPeerDidDocumentFromServices([
        {
          id: 'didcomm',
          recipientKeys: [didRouting.recipientKey],
          routingKeys: didRouting.routingKeys,
          serviceEndpoint: didRouting.endpoints[0],
        },
      ])
      didDocument.id = did

      await aliceAgent.dids.create({
        did,
        didDocument,
      })

      // Do did rotate
      await aliceAgent.connections.rotate({ connectionId: aliceBobConnection!.id, toDid: did })

      // Wait for a problem report
      await waitForAgentMessageProcessedEvent(aliceAgent, {
        messageType: DidRotateProblemReportMessage.type.messageTypeUri,
      })

      // Send message to previous did
      await bobAgent.dependencyManager.resolve(MessageSender).sendMessage(messageToPreviousDid)

      await waitForBasicMessage(aliceAgent, {
        content: 'Message to previous did',
        connectionId: aliceBobConnection!.id,
      })

      // Send message to stored did (should be the previous one)
      await bobAgent.basicMessages.sendMessage(bobAliceConnection!.id, 'Message after did rotation failure')

      await waitForBasicMessage(aliceAgent, {
        content: 'Message after did rotation failure',
        connectionId: aliceBobConnection!.id,
      })
    })
  })

  describe('Hangup', () => {
    test('Hangup without record deletion', async () => {
      // Send message to initial did
      await bobAgent.basicMessages.sendMessage(bobAliceConnection!.id, 'Hello initial did')

      await waitForBasicMessage(aliceAgent, { content: 'Hello initial did' })

      // Store an outbound context so we can attempt to send a message even if the connection is terminated.
      // A bit hacky, but may happen in some cases where message retry mechanisms are being used
      const messageBeforeHangup = await getOutboundMessageContext(bobAgent.context, {
        message: new BasicMessage({ content: 'Message before hangup' }),
        connectionRecord: bobAliceConnection!.clone(),
      })

      await aliceAgent.connections.hangup({ connectionId: aliceBobConnection!.id })

      // Wait for hangup
      await waitForAgentMessageProcessedEvent(bobAgent, {
        messageType: HangupMessage.type.messageTypeUri,
      })

      // If Bob attempts to send a message to Alice after they received the hangup, framework should reject it
      expect(bobAgent.basicMessages.sendMessage(bobAliceConnection!.id, 'Message after hangup')).rejects.toThrowError()

      // If Bob sends a message afterwards, Alice should still be able to receive it
      await bobAgent.dependencyManager.resolve(MessageSender).sendMessage(messageBeforeHangup)

      await waitForBasicMessage(aliceAgent, {
        content: 'Message before hangup',
        connectionId: aliceBobConnection!.id,
      })
    })

    test('Hangup and delete connection record', async () => {
      // Send message to initial did
      await bobAgent.basicMessages.sendMessage(bobAliceConnection!.id, 'Hello initial did')

      await waitForBasicMessage(aliceAgent, { content: 'Hello initial did' })

      // Store an outbound context so we can attempt to send a message even if the connection is terminated.
      // A bit hacky, but may happen in some cases where message retry mechanisms are being used
      const messageBeforeHangup = await getOutboundMessageContext(bobAgent.context, {
        message: new BasicMessage({ content: 'Message before hangup' }),
        connectionRecord: bobAliceConnection!.clone(),
      })

      await aliceAgent.connections.hangup({ connectionId: aliceBobConnection!.id, deleteAfterHangup: true })

      // Verify that alice connection has been effectively deleted
      expect(aliceAgent.connections.getById(aliceBobConnection!.id)).rejects.toThrow(RecordNotFoundError)

      // Wait for hangup
      await waitForAgentMessageProcessedEvent(bobAgent, {
        messageType: HangupMessage.type.messageTypeUri,
      })

      // If Bob sends a message afterwards, Alice should not receive it since the connection has been deleted
      await bobAgent.dependencyManager.resolve(MessageSender).sendMessage(messageBeforeHangup)

      // An error is thrown by Alice agent and, after inspecting all basic messages, it cannot be found
      // TODO: Update as soon as agent sends error events upon reception of messages
      const observable = aliceAgent.events.observable('AgentReceiveMessageError')
      const subject = new ReplaySubject(1)
      observable.pipe(first(), timeout({ first: 10000 })).subscribe(subject)
      await firstValueFrom(subject)

      const aliceBasicMessages = await aliceAgent.basicMessages.findAllByQuery({})
      expect(aliceBasicMessages.find((message) => message.content === 'Message before hangup')).toBeUndefined()
    })
  })
})
