import type { EventEmitter as NativeEventEmitter } from 'events'

import { Subject } from 'rxjs'

import { EventEmitter } from '../../../core/src/agent/EventEmitter'
import { agentDependencies, getAgentContext } from '../../../core/tests/helpers'

const mockEmit = jest.fn()
const mockOn = jest.fn()
const mockOff = jest.fn()
const mock = jest.fn().mockImplementation(() => {
  return { emit: mockEmit, on: mockOn, off: mockOff }
}) as jest.Mock<NativeEventEmitter>

const eventEmitter = new EventEmitter(
  { ...agentDependencies, EventEmitterClass: mock as unknown as typeof NativeEventEmitter },
  new Subject()
)
const agentContext = getAgentContext({})

describe('EventEmitter', () => {
  afterEach(() => {
    jest.clearAllMocks()
  })

  describe('emit', () => {
    test("calls 'emit' on native event emitter instance", () => {
      eventEmitter.emit(agentContext, {
        payload: { some: 'payload' },
        type: 'some-event',
      })

      expect(mockEmit).toHaveBeenCalledWith('some-event', {
        payload: { some: 'payload' },
        type: 'some-event',
        metadata: {
          contextCorrelationId: agentContext.contextCorrelationId,
        },
      })
    })
  })

  describe('on', () => {
    test("calls 'on' on native event emitter instance", () => {
      const listener = jest.fn()
      eventEmitter.on('some-event', listener)

      expect(mockOn).toHaveBeenCalledWith('some-event', listener)
    })
  })
  describe('off', () => {
    test("calls 'off' on native event emitter instance", () => {
      const listener = jest.fn()
      eventEmitter.off('some-event', listener)

      expect(mockOff).toHaveBeenCalledWith('some-event', listener)
    })
  })
})
