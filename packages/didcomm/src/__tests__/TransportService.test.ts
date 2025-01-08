import { Subject } from 'rxjs'

import { EventEmitter } from '../../../core/src/agent/EventEmitter'
import { agentDependencies, getAgentContext, getMockConnection } from '../../../core/tests/helpers'
import { TransportService } from '../TransportService'
import { DidExchangeRole } from '../modules'

import { DummyTransportSession } from './stubs'

describe('TransportService', () => {
  describe('removeSession', () => {
    let transportService: TransportService

    beforeEach(() => {
      transportService = new TransportService(getAgentContext(), new EventEmitter(agentDependencies, new Subject()))
    })

    test(`remove session saved for a given connection`, () => {
      const connection = getMockConnection({ id: 'test-123', role: DidExchangeRole.Responder })
      const session = new DummyTransportSession('dummy-session-123')
      session.connectionId = connection.id

      transportService.saveSession(session)
      expect(transportService.findSessionByConnectionId(connection.id)).toEqual(session)

      transportService.removeSession(session)
      expect(transportService.findSessionByConnectionId(connection.id)).toEqual(undefined)
    })
  })
})
