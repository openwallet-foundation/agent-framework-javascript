import type { ActionMenuStateChangedEvent } from '../../ActionMenuEvents'
import type { ActionMenuSelection } from '../../models'
import type { AgentContext, AgentConfig, Repository } from '@credo-ts/core'

import { EventEmitter } from '@credo-ts/core'
import { DidExchangeState, InboundMessageContext } from '@credo-ts/didcomm'
import { Subject } from 'rxjs'

import {
  agentDependencies,
  getAgentConfig,
  getAgentContext,
  getMockConnection,
  mockFunction,
} from '../../../../core/tests/helpers'
import { ActionMenuEventTypes } from '../../ActionMenuEvents'
import { ActionMenuRole } from '../../ActionMenuRole'
import { ActionMenuState } from '../../ActionMenuState'
import { ActionMenuProblemReportError } from '../../errors/ActionMenuProblemReportError'
import { ActionMenuProblemReportReason } from '../../errors/ActionMenuProblemReportReason'
import { MenuMessage, MenuRequestMessage, PerformMessage } from '../../messages'
import { ActionMenu } from '../../models'
import { ActionMenuRecord, ActionMenuRepository } from '../../repository'
import { ActionMenuService } from '../ActionMenuService'

jest.mock('../../repository/ActionMenuRepository')
const ActionMenuRepositoryMock = ActionMenuRepository as jest.Mock<ActionMenuRepository>

describe('ActionMenuService', () => {
  const mockConnectionRecord = getMockConnection({
    id: 'd3849ac3-c981-455b-a1aa-a10bea6cead8',
    did: 'did:sov:C2SsBf5QUQpqSAQfhu3sd2',
    state: DidExchangeState.Completed,
  })

  let actionMenuRepository: Repository<ActionMenuRecord>
  let actionMenuService: ActionMenuService
  let eventEmitter: EventEmitter
  let agentConfig: AgentConfig
  let agentContext: AgentContext

  const mockActionMenuRecord = (options: {
    connectionId: string
    role: ActionMenuRole
    state: ActionMenuState
    threadId: string
    menu?: ActionMenu
    performedAction?: ActionMenuSelection
  }) => {
    return new ActionMenuRecord({
      connectionId: options.connectionId,
      role: options.role,
      state: options.state,
      threadId: options.threadId,
      menu: options.menu,
      performedAction: options.performedAction,
    })
  }

  beforeAll(async () => {
    agentConfig = getAgentConfig('ActionMenuServiceTest')
    agentContext = getAgentContext()
  })

  beforeEach(async () => {
    actionMenuRepository = new ActionMenuRepositoryMock()
    eventEmitter = new EventEmitter(agentDependencies, new Subject())
    actionMenuService = new ActionMenuService(actionMenuRepository, agentConfig, eventEmitter)
  })

  describe('createMenu', () => {
    let testMenu: ActionMenu

    beforeAll(() => {
      testMenu = new ActionMenu({
        description: 'menu-description',
        title: 'menu-title',
        options: [{ name: 'opt1', title: 'opt1-title', description: 'opt1-desc' }],
      })
    })

    it(`throws an error when duplicated options are specified`, async () => {
      expect(
        actionMenuService.createMenu(agentContext, {
          connection: mockConnectionRecord,
          menu: {
            title: 'menu-title',
            description: 'menu-description',
            options: [
              { name: 'opt1', description: 'desc1', title: 'title1' },
              { name: 'opt2', description: 'desc2', title: 'title2' },
              { name: 'opt1', description: 'desc3', title: 'title3' },
              { name: 'opt4', description: 'desc4', title: 'title4' },
            ],
          },
        })
      ).rejects.toThrowError('Action Menu contains duplicated options')
    })

    it(`no previous menu: emits a menu with title, description and options`, async () => {
      // No previous menu
      mockFunction(actionMenuRepository.findSingleByQuery).mockReturnValue(Promise.resolve(null))

      const eventListenerMock = jest.fn()
      eventEmitter.on<ActionMenuStateChangedEvent>(ActionMenuEventTypes.ActionMenuStateChanged, eventListenerMock)

      await actionMenuService.createMenu(agentContext, {
        connection: mockConnectionRecord,
        menu: testMenu,
      })

      expect(eventListenerMock).toHaveBeenCalledWith({
        type: ActionMenuEventTypes.ActionMenuStateChanged,
        metadata: {
          contextCorrelationId: 'mock',
        },
        payload: {
          previousState: null,
          actionMenuRecord: expect.objectContaining({
            connectionId: mockConnectionRecord.id,
            role: ActionMenuRole.Responder,
            state: ActionMenuState.AwaitingSelection,
            menu: expect.objectContaining({
              description: 'menu-description',
              title: 'menu-title',
              options: [{ name: 'opt1', title: 'opt1-title', description: 'opt1-desc' }],
            }),
          }),
        },
      })
    })

    it(`existing menu: emits a menu with title, description, options and thread`, async () => {
      // Previous menu is in Done state
      const previousMenuDone = mockActionMenuRecord({
        connectionId: mockConnectionRecord.id,
        role: ActionMenuRole.Responder,
        state: ActionMenuState.Done,
        threadId: 'threadId-1',
      })

      mockFunction(actionMenuRepository.findSingleByQuery).mockReturnValue(Promise.resolve(previousMenuDone))

      const eventListenerMock = jest.fn()
      eventEmitter.on<ActionMenuStateChangedEvent>(ActionMenuEventTypes.ActionMenuStateChanged, eventListenerMock)

      await actionMenuService.createMenu(agentContext, {
        connection: mockConnectionRecord,
        menu: testMenu,
      })

      expect(eventListenerMock).toHaveBeenCalledWith({
        type: ActionMenuEventTypes.ActionMenuStateChanged,
        metadata: {
          contextCorrelationId: 'mock',
        },
        payload: {
          previousState: ActionMenuState.Done,
          actionMenuRecord: expect.objectContaining({
            connectionId: mockConnectionRecord.id,
            threadId: 'threadId-1',
            role: ActionMenuRole.Responder,
            state: ActionMenuState.AwaitingSelection,
            menu: expect.objectContaining({
              description: 'menu-description',
              title: 'menu-title',
              options: [{ name: 'opt1', title: 'opt1-title', description: 'opt1-desc' }],
            }),
          }),
        },
      })
    })

    it(`existing menu, cleared: emits a menu with title, description, options and new thread`, async () => {
      // Previous menu is in Done state
      const previousMenuClear = mockActionMenuRecord({
        connectionId: mockConnectionRecord.id,
        role: ActionMenuRole.Responder,
        state: ActionMenuState.Null,
        threadId: 'threadId-1',
      })

      mockFunction(actionMenuRepository.findSingleByQuery).mockReturnValue(Promise.resolve(previousMenuClear))

      const eventListenerMock = jest.fn()
      eventEmitter.on<ActionMenuStateChangedEvent>(ActionMenuEventTypes.ActionMenuStateChanged, eventListenerMock)

      await actionMenuService.createMenu(agentContext, {
        connection: mockConnectionRecord,
        menu: testMenu,
      })

      expect(eventListenerMock).toHaveBeenCalledWith({
        type: ActionMenuEventTypes.ActionMenuStateChanged,
        metadata: {
          contextCorrelationId: 'mock',
        },
        payload: {
          previousState: ActionMenuState.Null,
          actionMenuRecord: expect.objectContaining({
            connectionId: mockConnectionRecord.id,
            threadId: expect.not.stringMatching('threadId-1'),
            role: ActionMenuRole.Responder,
            state: ActionMenuState.AwaitingSelection,
            menu: expect.objectContaining({
              description: 'menu-description',
              title: 'menu-title',
              options: [{ name: 'opt1', title: 'opt1-title', description: 'opt1-desc' }],
            }),
          }),
        },
      })
    })
  })

  describe('createPerform', () => {
    let mockRecord: ActionMenuRecord

    beforeEach(() => {
      const testMenu = new ActionMenu({
        description: 'menu-description',
        title: 'menu-title',
        options: [
          { name: 'opt1', title: 'opt1-title', description: 'opt1-desc' },
          { name: 'opt2', title: 'opt2-title', description: 'opt2-desc' },
        ],
      })

      mockRecord = mockActionMenuRecord({
        connectionId: mockConnectionRecord.id,
        role: ActionMenuRole.Requester,
        state: ActionMenuState.PreparingSelection,
        threadId: '123',
        menu: testMenu,
      })
    })

    it(`throws an error when invalid selection is provided`, async () => {
      expect(
        actionMenuService.createPerform(agentContext, {
          actionMenuRecord: mockRecord,
          performedAction: { name: 'fake' },
        })
      ).rejects.toThrowError('Selection does not match valid actions')
    })

    it(`throws an error when state is not preparing-selection`, async () => {
      for (const state of Object.values(ActionMenuState).filter(
        (state) => state !== ActionMenuState.PreparingSelection
      )) {
        mockRecord.state = state
        expect(
          actionMenuService.createPerform(agentContext, {
            actionMenuRecord: mockRecord,
            performedAction: { name: 'opt1' },
          })
        ).rejects.toThrowError(
          `Action Menu record is in invalid state ${state}. Valid states are: preparing-selection.`
        )
      }
    })

    it(`emits a menu with a valid selection and action menu record`, async () => {
      const eventListenerMock = jest.fn()
      eventEmitter.on<ActionMenuStateChangedEvent>(ActionMenuEventTypes.ActionMenuStateChanged, eventListenerMock)

      mockFunction(actionMenuRepository.findSingleByQuery).mockReturnValue(Promise.resolve(mockRecord))

      await actionMenuService.createPerform(agentContext, {
        actionMenuRecord: mockRecord,
        performedAction: { name: 'opt2' },
      })

      expect(eventListenerMock).toHaveBeenCalledWith({
        type: ActionMenuEventTypes.ActionMenuStateChanged,
        metadata: {
          contextCorrelationId: 'mock',
        },
        payload: {
          previousState: ActionMenuState.PreparingSelection,
          actionMenuRecord: expect.objectContaining({
            connectionId: mockConnectionRecord.id,
            role: ActionMenuRole.Requester,
            state: ActionMenuState.Done,
            performedAction: { name: 'opt2' },
          }),
        },
      })
    })
  })

  describe('createRequest', () => {
    let mockRecord: ActionMenuRecord

    beforeEach(() => {
      const testMenu = new ActionMenu({
        description: 'menu-description',
        title: 'menu-title',
        options: [
          { name: 'opt1', title: 'opt1-title', description: 'opt1-desc' },
          { name: 'opt2', title: 'opt2-title', description: 'opt2-desc' },
        ],
      })

      mockRecord = mockActionMenuRecord({
        connectionId: mockConnectionRecord.id,
        role: ActionMenuRole.Requester,
        state: ActionMenuState.PreparingSelection,
        threadId: '123',
        menu: testMenu,
      })
    })

    it(`no existing record: emits event and creates new request and record`, async () => {
      mockFunction(actionMenuRepository.findSingleByQuery).mockReturnValue(Promise.resolve(null))

      const eventListenerMock = jest.fn()
      eventEmitter.on<ActionMenuStateChangedEvent>(ActionMenuEventTypes.ActionMenuStateChanged, eventListenerMock)

      const { message, record } = await actionMenuService.createRequest(agentContext, {
        connection: mockConnectionRecord,
      })

      const expectedRecord = {
        id: expect.any(String),
        connectionId: mockConnectionRecord.id,
        role: ActionMenuRole.Requester,
        threadId: message.threadId,
        state: ActionMenuState.AwaitingRootMenu,
        menu: undefined,
        performedAction: undefined,
      }
      expect(record).toMatchObject(expectedRecord)

      expect(actionMenuRepository.save).toHaveBeenCalledWith(agentContext, expect.objectContaining(expectedRecord))
      expect(actionMenuRepository.update).not.toHaveBeenCalled()

      expect(eventListenerMock).toHaveBeenCalledWith({
        type: ActionMenuEventTypes.ActionMenuStateChanged,
        metadata: {
          contextCorrelationId: 'mock',
        },
        payload: {
          previousState: null,
          actionMenuRecord: expect.objectContaining(expectedRecord),
        },
      })
    })

    it(`already existing record: emits event, creates new request and updates record`, async () => {
      mockFunction(actionMenuRepository.findSingleByQuery).mockReturnValue(Promise.resolve(mockRecord))

      const previousState = mockRecord.state

      const eventListenerMock = jest.fn()
      eventEmitter.on<ActionMenuStateChangedEvent>(ActionMenuEventTypes.ActionMenuStateChanged, eventListenerMock)

      const { message, record } = await actionMenuService.createRequest(agentContext, {
        connection: mockConnectionRecord,
      })

      const expectedRecord = {
        id: expect.any(String),
        connectionId: mockConnectionRecord.id,
        role: ActionMenuRole.Requester,
        threadId: message.threadId,
        state: ActionMenuState.AwaitingRootMenu,
        menu: undefined,
        performedAction: undefined,
      }
      expect(record).toMatchObject(expectedRecord)

      expect(actionMenuRepository.update).toHaveBeenCalledWith(agentContext, expect.objectContaining(expectedRecord))
      expect(actionMenuRepository.save).not.toHaveBeenCalled()

      expect(eventListenerMock).toHaveBeenCalledWith({
        type: ActionMenuEventTypes.ActionMenuStateChanged,
        metadata: {
          contextCorrelationId: 'mock',
        },
        payload: {
          previousState,
          actionMenuRecord: expect.objectContaining(expectedRecord),
        },
      })
    })
  })

  describe('clearMenu', () => {
    let mockRecord: ActionMenuRecord

    beforeEach(() => {
      const testMenu = new ActionMenu({
        description: 'menu-description',
        title: 'menu-title',
        options: [
          { name: 'opt1', title: 'opt1-title', description: 'opt1-desc' },
          { name: 'opt2', title: 'opt2-title', description: 'opt2-desc' },
        ],
      })

      mockRecord = mockActionMenuRecord({
        connectionId: mockConnectionRecord.id,
        role: ActionMenuRole.Requester,
        state: ActionMenuState.PreparingSelection,
        threadId: '123',
        menu: testMenu,
        performedAction: { name: 'opt1' },
      })
    })

    it(`requester role: emits a cleared menu`, async () => {
      const eventListenerMock = jest.fn()
      eventEmitter.on<ActionMenuStateChangedEvent>(ActionMenuEventTypes.ActionMenuStateChanged, eventListenerMock)

      mockRecord.role = ActionMenuRole.Requester
      mockFunction(actionMenuRepository.findSingleByQuery).mockReturnValue(Promise.resolve(mockRecord))

      await actionMenuService.clearMenu(agentContext, {
        actionMenuRecord: mockRecord,
      })

      expect(eventListenerMock).toHaveBeenCalledWith({
        type: ActionMenuEventTypes.ActionMenuStateChanged,
        metadata: {
          contextCorrelationId: 'mock',
        },
        payload: {
          previousState: ActionMenuState.PreparingSelection,
          actionMenuRecord: expect.objectContaining({
            connectionId: mockConnectionRecord.id,
            role: ActionMenuRole.Requester,
            state: ActionMenuState.Null,
            menu: undefined,
            performedAction: undefined,
          }),
        },
      })
    })

    it(`responder role: emits a cleared menu`, async () => {
      const eventListenerMock = jest.fn()
      eventEmitter.on<ActionMenuStateChangedEvent>(ActionMenuEventTypes.ActionMenuStateChanged, eventListenerMock)

      mockRecord.state = ActionMenuState.AwaitingSelection
      mockRecord.role = ActionMenuRole.Responder
      mockFunction(actionMenuRepository.findSingleByQuery).mockReturnValue(Promise.resolve(mockRecord))

      await actionMenuService.clearMenu(agentContext, {
        actionMenuRecord: mockRecord,
      })

      expect(eventListenerMock).toHaveBeenCalledWith({
        type: ActionMenuEventTypes.ActionMenuStateChanged,
        metadata: {
          contextCorrelationId: 'mock',
        },
        payload: {
          previousState: ActionMenuState.AwaitingSelection,
          actionMenuRecord: expect.objectContaining({
            connectionId: mockConnectionRecord.id,
            role: ActionMenuRole.Responder,
            state: ActionMenuState.Null,
            menu: undefined,
            performedAction: undefined,
          }),
        },
      })
    })
  })

  describe('processMenu', () => {
    let mockRecord: ActionMenuRecord
    let mockMenuMessage: MenuMessage

    beforeEach(() => {
      mockRecord = mockActionMenuRecord({
        connectionId: mockConnectionRecord.id,
        role: ActionMenuRole.Requester,
        state: ActionMenuState.PreparingSelection,
        threadId: '123',
        menu: new ActionMenu({
          description: 'menu-description',
          title: 'menu-title',
          options: [
            { name: 'opt1', title: 'opt1-title', description: 'opt1-desc' },
            { name: 'opt2', title: 'opt2-title', description: 'opt2-desc' },
          ],
        }),
        performedAction: { name: 'opt1' },
      })

      mockMenuMessage = new MenuMessage({
        title: 'incoming title',
        description: 'incoming description',
        options: [
          {
            title: 'incoming option 1 title',
            description: 'incoming option 1 description',
            name: 'incoming option 1 name',
          },
        ],
      })
    })

    it(`emits event and creates record when no previous record`, async () => {
      const messageContext = new InboundMessageContext(mockMenuMessage, {
        agentContext,
        connection: mockConnectionRecord,
      })

      const eventListenerMock = jest.fn()
      eventEmitter.on<ActionMenuStateChangedEvent>(ActionMenuEventTypes.ActionMenuStateChanged, eventListenerMock)

      mockFunction(actionMenuRepository.findSingleByQuery).mockReturnValue(Promise.resolve(null))

      await actionMenuService.processMenu(messageContext)

      const expectedRecord = {
        connectionId: mockConnectionRecord.id,
        role: ActionMenuRole.Requester,
        state: ActionMenuState.PreparingSelection,
        threadId: messageContext.message.threadId,
        menu: expect.objectContaining({
          title: 'incoming title',
          description: 'incoming description',
          options: [
            {
              title: 'incoming option 1 title',
              description: 'incoming option 1 description',
              name: 'incoming option 1 name',
            },
          ],
        }),
        performedAction: undefined,
      }

      expect(actionMenuRepository.save).toHaveBeenCalledWith(agentContext, expect.objectContaining(expectedRecord))
      expect(actionMenuRepository.update).not.toHaveBeenCalled()

      expect(eventListenerMock).toHaveBeenCalledWith({
        type: ActionMenuEventTypes.ActionMenuStateChanged,
        metadata: {
          contextCorrelationId: 'mock',
        },
        payload: {
          previousState: null,
          actionMenuRecord: expect.objectContaining(expectedRecord),
        },
      })
    })

    it(`emits event and updates record when existing record`, async () => {
      const messageContext = new InboundMessageContext(mockMenuMessage, {
        agentContext,
        connection: mockConnectionRecord,
      })

      const eventListenerMock = jest.fn()
      eventEmitter.on<ActionMenuStateChangedEvent>(ActionMenuEventTypes.ActionMenuStateChanged, eventListenerMock)

      // It should accept any previous state
      for (const state of Object.values(ActionMenuState)) {
        mockRecord.state = state
        const previousState = state
        mockFunction(actionMenuRepository.findSingleByQuery).mockReturnValue(Promise.resolve(mockRecord))

        await actionMenuService.processMenu(messageContext)

        const expectedRecord = {
          connectionId: mockConnectionRecord.id,
          role: ActionMenuRole.Requester,
          state: ActionMenuState.PreparingSelection,
          threadId: messageContext.message.threadId,
          menu: expect.objectContaining({
            title: 'incoming title',
            description: 'incoming description',
            options: [
              {
                title: 'incoming option 1 title',
                description: 'incoming option 1 description',
                name: 'incoming option 1 name',
              },
            ],
          }),
          performedAction: undefined,
        }

        expect(actionMenuRepository.update).toHaveBeenCalledWith(agentContext, expect.objectContaining(expectedRecord))
        expect(actionMenuRepository.save).not.toHaveBeenCalled()

        expect(eventListenerMock).toHaveBeenCalledWith({
          type: ActionMenuEventTypes.ActionMenuStateChanged,
          metadata: {
            contextCorrelationId: 'mock',
          },
          payload: {
            previousState,
            actionMenuRecord: expect.objectContaining(expectedRecord),
          },
        })
      }
    })
  })

  describe('processPerform', () => {
    let mockRecord: ActionMenuRecord

    beforeEach(() => {
      mockRecord = mockActionMenuRecord({
        connectionId: mockConnectionRecord.id,
        role: ActionMenuRole.Responder,
        state: ActionMenuState.AwaitingSelection,
        threadId: '123',
        menu: new ActionMenu({
          description: 'menu-description',
          title: 'menu-title',
          options: [
            { name: 'opt1', title: 'opt1-title', description: 'opt1-desc' },
            { name: 'opt2', title: 'opt2-title', description: 'opt2-desc' },
          ],
        }),
      })
    })

    it(`emits event and saves record when valid selection and thread Id`, async () => {
      const mockPerformMessage = new PerformMessage({
        name: 'opt1',
        threadId: '123',
      })

      const messageContext = new InboundMessageContext(mockPerformMessage, {
        agentContext,
        connection: mockConnectionRecord,
      })

      const eventListenerMock = jest.fn()
      eventEmitter.on<ActionMenuStateChangedEvent>(ActionMenuEventTypes.ActionMenuStateChanged, eventListenerMock)

      mockFunction(actionMenuRepository.findSingleByQuery).mockReturnValue(Promise.resolve(mockRecord))

      await actionMenuService.processPerform(messageContext)

      const expectedRecord = {
        connectionId: mockConnectionRecord.id,
        role: ActionMenuRole.Responder,
        state: ActionMenuState.Done,
        threadId: messageContext.message.threadId,
        menu: expect.objectContaining({
          description: 'menu-description',
          title: 'menu-title',
          options: [
            { name: 'opt1', title: 'opt1-title', description: 'opt1-desc' },
            { name: 'opt2', title: 'opt2-title', description: 'opt2-desc' },
          ],
        }),
        performedAction: { name: 'opt1' },
      }

      expect(actionMenuRepository.findSingleByQuery).toHaveBeenCalledWith(
        agentContext,
        expect.objectContaining({
          connectionId: mockConnectionRecord.id,
          role: ActionMenuRole.Responder,
          threadId: messageContext.message.threadId,
        })
      )
      expect(actionMenuRepository.update).toHaveBeenCalledWith(agentContext, expect.objectContaining(expectedRecord))
      expect(actionMenuRepository.save).not.toHaveBeenCalled()

      expect(eventListenerMock).toHaveBeenCalledWith({
        type: ActionMenuEventTypes.ActionMenuStateChanged,
        metadata: {
          contextCorrelationId: 'mock',
        },
        payload: {
          previousState: ActionMenuState.AwaitingSelection,
          actionMenuRecord: expect.objectContaining(expectedRecord),
        },
      })
    })

    it(`throws error when invalid selection`, async () => {
      const mockPerformMessage = new PerformMessage({
        name: 'fake',
        threadId: '123',
      })

      const messageContext = new InboundMessageContext(mockPerformMessage, {
        agentContext,
        connection: mockConnectionRecord,
      })

      const eventListenerMock = jest.fn()
      eventEmitter.on<ActionMenuStateChangedEvent>(ActionMenuEventTypes.ActionMenuStateChanged, eventListenerMock)

      mockFunction(actionMenuRepository.findSingleByQuery).mockReturnValue(Promise.resolve(mockRecord))

      expect(actionMenuService.processPerform(messageContext)).rejects.toThrowError(
        'Selection does not match valid actions'
      )

      expect(actionMenuRepository.update).not.toHaveBeenCalled()
      expect(actionMenuRepository.save).not.toHaveBeenCalled()
      expect(eventListenerMock).not.toHaveBeenCalled()
    })

    it(`throws error when record not found`, async () => {
      const mockPerformMessage = new PerformMessage({
        name: 'opt1',
        threadId: '122',
      })

      const messageContext = new InboundMessageContext(mockPerformMessage, {
        agentContext,
        connection: mockConnectionRecord,
      })

      const eventListenerMock = jest.fn()
      eventEmitter.on<ActionMenuStateChangedEvent>(ActionMenuEventTypes.ActionMenuStateChanged, eventListenerMock)

      mockFunction(actionMenuRepository.findSingleByQuery).mockReturnValue(Promise.resolve(null))

      expect(actionMenuService.processPerform(messageContext)).rejects.toThrowError(
        `No Action Menu found with thread id ${mockPerformMessage.threadId}`
      )

      expect(actionMenuRepository.update).not.toHaveBeenCalled()
      expect(actionMenuRepository.save).not.toHaveBeenCalled()
      expect(eventListenerMock).not.toHaveBeenCalled()
    })

    it(`throws error when invalid state`, async () => {
      const mockPerformMessage = new PerformMessage({
        name: 'opt1',
        threadId: '123',
      })

      const messageContext = new InboundMessageContext(mockPerformMessage, {
        agentContext,
        connection: mockConnectionRecord,
      })

      const eventListenerMock = jest.fn()
      eventEmitter.on<ActionMenuStateChangedEvent>(ActionMenuEventTypes.ActionMenuStateChanged, eventListenerMock)

      mockRecord.state = ActionMenuState.Done
      mockFunction(actionMenuRepository.findSingleByQuery).mockReturnValue(Promise.resolve(mockRecord))

      expect(actionMenuService.processPerform(messageContext)).rejects.toThrowError(
        `Action Menu record is in invalid state ${mockRecord.state}. Valid states are: ${ActionMenuState.AwaitingSelection}.`
      )

      expect(actionMenuRepository.update).not.toHaveBeenCalled()
      expect(actionMenuRepository.save).not.toHaveBeenCalled()
      expect(eventListenerMock).not.toHaveBeenCalled()
    })

    it(`throws problem report error when menu has been cleared`, async () => {
      const mockPerformMessage = new PerformMessage({
        name: 'opt1',
        threadId: '123',
      })

      const messageContext = new InboundMessageContext(mockPerformMessage, {
        agentContext,
        connection: mockConnectionRecord,
      })

      const eventListenerMock = jest.fn()
      eventEmitter.on<ActionMenuStateChangedEvent>(ActionMenuEventTypes.ActionMenuStateChanged, eventListenerMock)

      mockRecord.state = ActionMenuState.Null
      mockFunction(actionMenuRepository.findSingleByQuery).mockReturnValue(Promise.resolve(mockRecord))

      expect(actionMenuService.processPerform(messageContext)).rejects.toThrowError(
        new ActionMenuProblemReportError('Action Menu has been cleared by the responder', {
          problemCode: ActionMenuProblemReportReason.Timeout,
        })
      )

      expect(actionMenuRepository.update).not.toHaveBeenCalled()
      expect(actionMenuRepository.save).not.toHaveBeenCalled()
      expect(eventListenerMock).not.toHaveBeenCalled()
    })
  })

  describe('processRequest', () => {
    let mockRecord: ActionMenuRecord
    let mockMenuRequestMessage: MenuRequestMessage

    beforeEach(() => {
      mockRecord = mockActionMenuRecord({
        connectionId: mockConnectionRecord.id,
        role: ActionMenuRole.Responder,
        state: ActionMenuState.PreparingRootMenu,
        threadId: '123',
        menu: new ActionMenu({
          description: 'menu-description',
          title: 'menu-title',
          options: [
            { name: 'opt1', title: 'opt1-title', description: 'opt1-desc' },
            { name: 'opt2', title: 'opt2-title', description: 'opt2-desc' },
          ],
        }),
        performedAction: { name: 'opt1' },
      })

      mockMenuRequestMessage = new MenuRequestMessage({})
    })

    it(`emits event and creates record when no previous record`, async () => {
      const messageContext = new InboundMessageContext(mockMenuRequestMessage, {
        agentContext,
        connection: mockConnectionRecord,
      })

      const eventListenerMock = jest.fn()
      eventEmitter.on<ActionMenuStateChangedEvent>(ActionMenuEventTypes.ActionMenuStateChanged, eventListenerMock)

      mockFunction(actionMenuRepository.findSingleByQuery).mockReturnValue(Promise.resolve(null))

      await actionMenuService.processRequest(messageContext)

      const expectedRecord = {
        connectionId: mockConnectionRecord.id,
        role: ActionMenuRole.Responder,
        state: ActionMenuState.PreparingRootMenu,
        threadId: messageContext.message.threadId,
        menu: undefined,
        performedAction: undefined,
      }

      expect(actionMenuRepository.save).toHaveBeenCalledWith(agentContext, expect.objectContaining(expectedRecord))
      expect(actionMenuRepository.update).not.toHaveBeenCalled()

      expect(eventListenerMock).toHaveBeenCalledWith({
        type: ActionMenuEventTypes.ActionMenuStateChanged,
        metadata: {
          contextCorrelationId: 'mock',
        },
        payload: {
          previousState: null,
          actionMenuRecord: expect.objectContaining(expectedRecord),
        },
      })
    })

    it(`emits event and updates record when existing record`, async () => {
      const messageContext = new InboundMessageContext(mockMenuRequestMessage, {
        agentContext,
        connection: mockConnectionRecord,
      })

      const eventListenerMock = jest.fn()
      eventEmitter.on<ActionMenuStateChangedEvent>(ActionMenuEventTypes.ActionMenuStateChanged, eventListenerMock)

      // It should accept any previous state
      for (const state of Object.values(ActionMenuState)) {
        mockRecord.state = state
        const previousState = state
        mockFunction(actionMenuRepository.findSingleByQuery).mockReturnValue(Promise.resolve(mockRecord))

        await actionMenuService.processRequest(messageContext)

        const expectedRecord = {
          connectionId: mockConnectionRecord.id,
          role: ActionMenuRole.Responder,
          state: ActionMenuState.PreparingRootMenu,
          threadId: messageContext.message.threadId,
          menu: undefined,
          performedAction: undefined,
        }

        expect(actionMenuRepository.update).toHaveBeenCalledWith(agentContext, expect.objectContaining(expectedRecord))
        expect(actionMenuRepository.save).not.toHaveBeenCalled()

        expect(eventListenerMock).toHaveBeenCalledWith({
          type: ActionMenuEventTypes.ActionMenuStateChanged,
          metadata: {
            contextCorrelationId: 'mock',
          },
          payload: {
            previousState,
            actionMenuRecord: expect.objectContaining(expectedRecord),
          },
        })
      }
    })
  })
})
