import type { DidCommDocumentService } from '../../didcomm'

import { Subject } from 'rxjs'

import {
  agentDependencies,
  getAgentContext,
  getMockConnection,
  getMockOutOfBand,
  mockFunction,
} from '../../../../tests/helpers'
import { EventEmitter } from '../../../agent/EventEmitter'
import { InboundMessageContext } from '../../../agent/models/InboundMessageContext'
import { KeyType, Key } from '../../../crypto'
import { CredoError } from '../../../error'
import { DidExchangeState } from '../../connections/models'
import { OutOfBandService } from '../OutOfBandService'
import { OutOfBandEventTypes } from '../domain/OutOfBandEvents'
import { OutOfBandRole } from '../domain/OutOfBandRole'
import { OutOfBandState } from '../domain/OutOfBandState'
import { HandshakeReuseMessage } from '../messages'
import { HandshakeReuseAcceptedMessage } from '../messages/HandshakeReuseAcceptedMessage'
import { OutOfBandRepository } from '../repository'

jest.mock('../repository/OutOfBandRepository')
const OutOfBandRepositoryMock = OutOfBandRepository as jest.Mock<OutOfBandRepository>

const key = Key.fromPublicKeyBase58('8HH5gYEeNc3z7PYXmd54d4x6qAfCNrqQqEB3nS7Zfu7K', KeyType.Ed25519)

const agentContext = getAgentContext()

describe('OutOfBandService', () => {
  let outOfBandRepository: OutOfBandRepository
  let outOfBandService: OutOfBandService
  let didCommDocumentService: DidCommDocumentService
  let eventEmitter: EventEmitter

  beforeEach(async () => {
    eventEmitter = new EventEmitter(agentDependencies, new Subject())
    outOfBandRepository = new OutOfBandRepositoryMock()
    didCommDocumentService = {} as DidCommDocumentService
    outOfBandService = new OutOfBandService(outOfBandRepository, eventEmitter, didCommDocumentService)
  })

  describe('processHandshakeReuse', () => {
    test('throw error when no parentThreadId is present', async () => {
      const reuseMessage = new HandshakeReuseMessage({
        parentThreadId: 'parentThreadId',
      })

      reuseMessage.setThread({
        parentThreadId: undefined,
      })

      const messageContext = new InboundMessageContext(reuseMessage, {
        agentContext,
        senderKey: key,
        recipientKey: key,
      })

      await expect(outOfBandService.processHandshakeReuse(messageContext)).rejects.toThrowError(
        new CredoError('handshake-reuse message must have a parent thread id')
      )
    })

    test('throw error when no out of band record is found for parentThreadId', async () => {
      const reuseMessage = new HandshakeReuseMessage({
        parentThreadId: 'parentThreadId',
      })

      const messageContext = new InboundMessageContext(reuseMessage, {
        agentContext,
        senderKey: key,
        recipientKey: key,
      })

      await expect(outOfBandService.processHandshakeReuse(messageContext)).rejects.toThrowError(
        new CredoError('No out of band record found for handshake-reuse message')
      )
    })

    test('throw error when role or state is incorrect ', async () => {
      const reuseMessage = new HandshakeReuseMessage({
        parentThreadId: 'parentThreadId',
      })

      const messageContext = new InboundMessageContext(reuseMessage, {
        agentContext,
        senderKey: key,
        recipientKey: key,
      })

      // Correct state, incorrect role
      const mockOob = getMockOutOfBand({
        state: OutOfBandState.AwaitResponse,
        role: OutOfBandRole.Receiver,
      })
      mockFunction(outOfBandRepository.findSingleByQuery).mockResolvedValue(mockOob)

      await expect(outOfBandService.processHandshakeReuse(messageContext)).rejects.toThrowError(
        new CredoError('Invalid out-of-band record role receiver, expected is sender.')
      )

      mockOob.state = OutOfBandState.PrepareResponse
      mockOob.role = OutOfBandRole.Sender
      await expect(outOfBandService.processHandshakeReuse(messageContext)).rejects.toThrowError(
        new CredoError('Invalid out-of-band record state prepare-response, valid states are: await-response.')
      )
    })

    test('throw error when the out of band record has request messages ', async () => {
      const reuseMessage = new HandshakeReuseMessage({
        parentThreadId: 'parentThreadId',
      })

      const messageContext = new InboundMessageContext(reuseMessage, {
        agentContext,
        senderKey: key,
        recipientKey: key,
      })

      const mockOob = getMockOutOfBand({
        state: OutOfBandState.AwaitResponse,
        role: OutOfBandRole.Sender,
      })
      mockOob.outOfBandInvitation.addRequest(reuseMessage)
      mockFunction(outOfBandRepository.findSingleByQuery).mockResolvedValue(mockOob)

      await expect(outOfBandService.processHandshakeReuse(messageContext)).rejects.toThrowError(
        new CredoError('Handshake reuse should only be used when no requests are present')
      )
    })

    test("throw error when the message context doesn't have a ready connection", async () => {
      const reuseMessage = new HandshakeReuseMessage({
        parentThreadId: 'parentThreadId',
      })

      const messageContext = new InboundMessageContext(reuseMessage, {
        agentContext,
        senderKey: key,
        recipientKey: key,
      })

      const mockOob = getMockOutOfBand({
        state: OutOfBandState.AwaitResponse,
        role: OutOfBandRole.Sender,
      })
      mockFunction(outOfBandRepository.findSingleByQuery).mockResolvedValue(mockOob)

      await expect(outOfBandService.processHandshakeReuse(messageContext)).rejects.toThrowError(
        new CredoError(`No connection associated with incoming message ${reuseMessage.type}`)
      )
    })

    test('emits handshake reused event ', async () => {
      const reuseMessage = new HandshakeReuseMessage({
        parentThreadId: 'parentThreadId',
      })

      const reuseListener = jest.fn()

      const connection = getMockConnection({ state: DidExchangeState.Completed })
      const messageContext = new InboundMessageContext(reuseMessage, {
        agentContext,
        senderKey: key,
        recipientKey: key,
        connection,
      })

      const mockOob = getMockOutOfBand({
        state: OutOfBandState.AwaitResponse,
        role: OutOfBandRole.Sender,
      })
      mockFunction(outOfBandRepository.findSingleByQuery).mockResolvedValue(mockOob)

      eventEmitter.on(OutOfBandEventTypes.HandshakeReused, reuseListener)
      await outOfBandService.processHandshakeReuse(messageContext)
      eventEmitter.off(OutOfBandEventTypes.HandshakeReused, reuseListener)

      expect(reuseListener).toHaveBeenCalledTimes(1)
      const [[reuseEvent]] = reuseListener.mock.calls

      expect(reuseEvent).toMatchObject({
        type: OutOfBandEventTypes.HandshakeReused,
        payload: {
          connectionRecord: connection,
          outOfBandRecord: mockOob,
          reuseThreadId: reuseMessage.threadId,
        },
      })
    })

    it('updates state to done if out of band record is not reusable', async () => {
      const reuseMessage = new HandshakeReuseMessage({
        parentThreadId: 'parentThreadId',
      })

      const messageContext = new InboundMessageContext(reuseMessage, {
        agentContext,
        senderKey: key,
        recipientKey: key,
        connection: getMockConnection({ state: DidExchangeState.Completed }),
      })

      const mockOob = getMockOutOfBand({
        state: OutOfBandState.AwaitResponse,
        role: OutOfBandRole.Sender,
        reusable: true,
      })
      mockFunction(outOfBandRepository.findSingleByQuery).mockResolvedValue(mockOob)

      const updateStateSpy = jest.spyOn(outOfBandService, 'updateState')

      // Reusable shouldn't update state
      await outOfBandService.processHandshakeReuse(messageContext)
      expect(updateStateSpy).not.toHaveBeenCalled()

      // Non-reusable should update state
      mockOob.reusable = false
      await outOfBandService.processHandshakeReuse(messageContext)
      expect(updateStateSpy).toHaveBeenCalledWith(agentContext, mockOob, OutOfBandState.Done)
    })

    it('returns a handshake-reuse-accepted message', async () => {
      const reuseMessage = new HandshakeReuseMessage({
        parentThreadId: 'parentThreadId',
      })

      const messageContext = new InboundMessageContext(reuseMessage, {
        agentContext,
        senderKey: key,
        recipientKey: key,
        connection: getMockConnection({ state: DidExchangeState.Completed }),
      })

      const mockOob = getMockOutOfBand({
        state: OutOfBandState.AwaitResponse,
        role: OutOfBandRole.Sender,
      })
      mockFunction(outOfBandRepository.findSingleByQuery).mockResolvedValue(mockOob)

      const reuseAcceptedMessage = await outOfBandService.processHandshakeReuse(messageContext)

      expect(reuseAcceptedMessage).toBeInstanceOf(HandshakeReuseAcceptedMessage)
      expect(reuseAcceptedMessage.thread).toMatchObject({
        threadId: reuseMessage.id,
        parentThreadId: reuseMessage.thread?.parentThreadId,
      })
    })
  })

  describe('processHandshakeReuseAccepted', () => {
    test('throw error when no parentThreadId is present', async () => {
      const reuseAcceptedMessage = new HandshakeReuseAcceptedMessage({
        threadId: 'threadId',
        parentThreadId: 'parentThreadId',
      })

      reuseAcceptedMessage.setThread({
        parentThreadId: undefined,
      })

      const messageContext = new InboundMessageContext(reuseAcceptedMessage, {
        agentContext,
        senderKey: key,
        recipientKey: key,
      })

      await expect(outOfBandService.processHandshakeReuseAccepted(messageContext)).rejects.toThrowError(
        new CredoError('handshake-reuse-accepted message must have a parent thread id')
      )
    })

    test('throw error when no out of band record is found for parentThreadId', async () => {
      const reuseAcceptedMessage = new HandshakeReuseAcceptedMessage({
        parentThreadId: 'parentThreadId',
        threadId: 'threadId',
      })

      const messageContext = new InboundMessageContext(reuseAcceptedMessage, {
        agentContext,
        senderKey: key,
        recipientKey: key,
      })

      await expect(outOfBandService.processHandshakeReuseAccepted(messageContext)).rejects.toThrowError(
        new CredoError('No out of band record found for handshake-reuse-accepted message')
      )
    })

    test('throw error when role or state is incorrect ', async () => {
      const reuseAcceptedMessage = new HandshakeReuseAcceptedMessage({
        parentThreadId: 'parentThreadId',
        threadId: 'threadId',
      })

      const messageContext = new InboundMessageContext(reuseAcceptedMessage, {
        agentContext,
        senderKey: key,
        recipientKey: key,
      })

      // Correct state, incorrect role
      const mockOob = getMockOutOfBand({
        state: OutOfBandState.PrepareResponse,
        role: OutOfBandRole.Sender,
      })
      mockFunction(outOfBandRepository.findSingleByQuery).mockResolvedValue(mockOob)

      await expect(outOfBandService.processHandshakeReuseAccepted(messageContext)).rejects.toThrowError(
        new CredoError('Invalid out-of-band record role sender, expected is receiver.')
      )

      mockOob.state = OutOfBandState.AwaitResponse
      mockOob.role = OutOfBandRole.Receiver
      await expect(outOfBandService.processHandshakeReuseAccepted(messageContext)).rejects.toThrowError(
        new CredoError('Invalid out-of-band record state await-response, valid states are: prepare-response.')
      )
    })

    test("throw error when the message context doesn't have a ready connection", async () => {
      const reuseAcceptedMessage = new HandshakeReuseAcceptedMessage({
        parentThreadId: 'parentThreadId',
        threadId: 'threadId',
      })

      const messageContext = new InboundMessageContext(reuseAcceptedMessage, {
        agentContext,
        senderKey: key,
        recipientKey: key,
      })

      const mockOob = getMockOutOfBand({
        state: OutOfBandState.PrepareResponse,
        role: OutOfBandRole.Receiver,
      })
      mockFunction(outOfBandRepository.findSingleByQuery).mockResolvedValue(mockOob)

      await expect(outOfBandService.processHandshakeReuseAccepted(messageContext)).rejects.toThrowError(
        new CredoError(`No connection associated with incoming message ${reuseAcceptedMessage.type}`)
      )
    })

    test("throw error when the reuseConnectionId on the oob record doesn't match with the inbound message connection id", async () => {
      const reuseAcceptedMessage = new HandshakeReuseAcceptedMessage({
        parentThreadId: 'parentThreadId',
        threadId: 'threadId',
      })

      const messageContext = new InboundMessageContext(reuseAcceptedMessage, {
        agentContext,
        senderKey: key,
        recipientKey: key,
        connection: getMockConnection({ state: DidExchangeState.Completed, id: 'connectionId' }),
      })

      const mockOob = getMockOutOfBand({
        state: OutOfBandState.PrepareResponse,
        role: OutOfBandRole.Receiver,
        reuseConnectionId: 'anotherConnectionId',
      })
      mockFunction(outOfBandRepository.findSingleByQuery).mockResolvedValue(mockOob)

      await expect(outOfBandService.processHandshakeReuseAccepted(messageContext)).rejects.toThrowError(
        new CredoError(`handshake-reuse-accepted is not in response to a handshake-reuse message.`)
      )
    })

    test('emits handshake reused event ', async () => {
      const reuseAcceptedMessage = new HandshakeReuseAcceptedMessage({
        parentThreadId: 'parentThreadId',
        threadId: 'threadId',
      })

      const reuseListener = jest.fn()

      const connection = getMockConnection({ state: DidExchangeState.Completed, id: 'connectionId' })
      const messageContext = new InboundMessageContext(reuseAcceptedMessage, {
        agentContext,
        senderKey: key,
        recipientKey: key,
        connection,
      })

      const mockOob = getMockOutOfBand({
        state: OutOfBandState.PrepareResponse,
        role: OutOfBandRole.Receiver,
        reuseConnectionId: 'connectionId',
      })
      mockFunction(outOfBandRepository.findSingleByQuery).mockResolvedValue(mockOob)

      eventEmitter.on(OutOfBandEventTypes.HandshakeReused, reuseListener)
      await outOfBandService.processHandshakeReuseAccepted(messageContext)
      eventEmitter.off(OutOfBandEventTypes.HandshakeReused, reuseListener)

      expect(reuseListener).toHaveBeenCalledTimes(1)
      const [[reuseEvent]] = reuseListener.mock.calls

      expect(reuseEvent).toMatchObject({
        type: OutOfBandEventTypes.HandshakeReused,
        payload: {
          connectionRecord: connection,
          outOfBandRecord: mockOob,
          reuseThreadId: reuseAcceptedMessage.threadId,
        },
      })
    })

    it('updates state to done', async () => {
      const reuseAcceptedMessage = new HandshakeReuseAcceptedMessage({
        parentThreadId: 'parentThreadId',
        threadId: 'threadId',
      })

      const messageContext = new InboundMessageContext(reuseAcceptedMessage, {
        agentContext,
        senderKey: key,
        recipientKey: key,
        connection: getMockConnection({ state: DidExchangeState.Completed, id: 'connectionId' }),
      })

      const mockOob = getMockOutOfBand({
        state: OutOfBandState.PrepareResponse,
        role: OutOfBandRole.Receiver,
        reusable: true,
        reuseConnectionId: 'connectionId',
      })
      mockFunction(outOfBandRepository.findSingleByQuery).mockResolvedValue(mockOob)

      const updateStateSpy = jest.spyOn(outOfBandService, 'updateState')

      await outOfBandService.processHandshakeReuseAccepted(messageContext)
      expect(updateStateSpy).toHaveBeenCalledWith(agentContext, mockOob, OutOfBandState.Done)
    })
  })

  describe('updateState', () => {
    test('updates the state on the out of band record', async () => {
      const mockOob = getMockOutOfBand({
        state: OutOfBandState.Initial,
      })

      await outOfBandService.updateState(agentContext, mockOob, OutOfBandState.Done)

      expect(mockOob.state).toEqual(OutOfBandState.Done)
    })

    test('updates the record in the out of band repository', async () => {
      const mockOob = getMockOutOfBand({
        state: OutOfBandState.Initial,
      })

      await outOfBandService.updateState(agentContext, mockOob, OutOfBandState.Done)

      expect(outOfBandRepository.update).toHaveBeenCalledWith(agentContext, mockOob)
    })

    test('emits an OutOfBandStateChangedEvent', async () => {
      const stateChangedListener = jest.fn()

      const mockOob = getMockOutOfBand({
        state: OutOfBandState.Initial,
      })

      eventEmitter.on(OutOfBandEventTypes.OutOfBandStateChanged, stateChangedListener)
      await outOfBandService.updateState(agentContext, mockOob, OutOfBandState.Done)
      eventEmitter.off(OutOfBandEventTypes.OutOfBandStateChanged, stateChangedListener)

      expect(stateChangedListener).toHaveBeenCalledTimes(1)
      const [[stateChangedEvent]] = stateChangedListener.mock.calls

      expect(stateChangedEvent).toMatchObject({
        type: OutOfBandEventTypes.OutOfBandStateChanged,
        payload: {
          outOfBandRecord: mockOob,
          previousState: OutOfBandState.Initial,
        },
      })
    })
  })

  describe('repository methods', () => {
    it('getById should return value from outOfBandRepository.getById', async () => {
      const expected = getMockOutOfBand()
      mockFunction(outOfBandRepository.getById).mockReturnValue(Promise.resolve(expected))
      const result = await outOfBandService.getById(agentContext, expected.id)
      expect(outOfBandRepository.getById).toBeCalledWith(agentContext, expected.id)

      expect(result).toBe(expected)
    })

    it('findById should return value from outOfBandRepository.findById', async () => {
      const expected = getMockOutOfBand()
      mockFunction(outOfBandRepository.findById).mockReturnValue(Promise.resolve(expected))
      const result = await outOfBandService.findById(agentContext, expected.id)
      expect(outOfBandRepository.findById).toBeCalledWith(agentContext, expected.id)

      expect(result).toBe(expected)
    })

    it('getAll should return value from outOfBandRepository.getAll', async () => {
      const expected = [getMockOutOfBand(), getMockOutOfBand()]

      mockFunction(outOfBandRepository.getAll).mockReturnValue(Promise.resolve(expected))
      const result = await outOfBandService.getAll(agentContext)
      expect(outOfBandRepository.getAll).toBeCalledWith(agentContext)

      expect(result).toEqual(expect.arrayContaining(expected))
    })

    it('findAllByQuery should return value from outOfBandRepository.findByQuery', async () => {
      const expected = [getMockOutOfBand(), getMockOutOfBand()]

      mockFunction(outOfBandRepository.findByQuery).mockReturnValue(Promise.resolve(expected))
      const result = await outOfBandService.findAllByQuery(agentContext, { state: OutOfBandState.Initial }, {})
      expect(outOfBandRepository.findByQuery).toBeCalledWith(agentContext, { state: OutOfBandState.Initial }, {})

      expect(result).toEqual(expect.arrayContaining(expected))
    })
  })
})
