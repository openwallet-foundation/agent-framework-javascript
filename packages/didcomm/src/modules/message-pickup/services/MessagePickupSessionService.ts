import type { AgentContext } from '@credo-ts/core'
import type { TransportSessionRemovedEvent } from '../../../transport'
import type { MessagePickupLiveSessionRemovedEvent, MessagePickupLiveSessionSavedEvent } from '../MessagePickupEvents'
import type { MessagePickupSession, MessagePickupSessionRole } from '../MessagePickupSession'

import { takeUntil, type Subject } from 'rxjs'

import { EventEmitter, InjectionSymbols, injectable, utils } from '@credo-ts/core'

import { TransportEventTypes } from '../../../transport'
import { MessagePickupEventTypes } from '../MessagePickupEvents'

/**
 * @internal
 * The Message Pickup session service keeps track of all {@link MessagePickupSession}
 *
 * It is initially intended for Message Holder/Mediator role, where only Live Mode sessions are
 * considered.
 */
@injectable()
export class MessagePickupSessionService {
  private sessions: MessagePickupSession[]

  public constructor() {
    this.sessions = []
  }

  public start(agentContext: AgentContext) {
    const stop$ = agentContext.dependencyManager.resolve<Subject<boolean>>(InjectionSymbols.Stop$)
    const eventEmitter = agentContext.dependencyManager.resolve(EventEmitter)
    this.sessions = []

    eventEmitter
      .observable<TransportSessionRemovedEvent>(TransportEventTypes.TransportSessionRemoved)
      .pipe(takeUntil(stop$))
      .subscribe({
        next: (e) => {
          const connectionId = e.payload.session.connectionId
          if (connectionId) this.removeLiveSession(agentContext, { connectionId })
        },
      })
  }

  public getLiveSession(agentContext: AgentContext, sessionId: string) {
    return this.sessions.find((session) => session.id === sessionId)
  }

  public getLiveSessionByConnectionId(
    agentContext: AgentContext,
    options: { connectionId: string; role?: MessagePickupSessionRole }
  ) {
    const { connectionId, role } = options

    return this.sessions.find(
      (session) => session.connectionId === connectionId && (role === undefined || role === session.role)
    )
  }

  public saveLiveSession(
    agentContext: AgentContext,
    options: { connectionId: string; protocolVersion: string; role: MessagePickupSessionRole }
  ) {
    const { connectionId, protocolVersion, role } = options

    // First remove any live session for the given connection Id
    this.removeLiveSession(agentContext, { connectionId })

    const session = {
      id: utils.uuid(),
      connectionId,
      protocolVersion,
      role,
    }

    this.sessions.push(session)

    const eventEmitter = agentContext.dependencyManager.resolve(EventEmitter)
    eventEmitter.emit<MessagePickupLiveSessionSavedEvent>(agentContext, {
      type: MessagePickupEventTypes.LiveSessionSaved,
      payload: {
        session,
      },
    })
  }

  public removeLiveSession(agentContext: AgentContext, options: { connectionId: string }) {
    const itemIndex = this.sessions.findIndex((session) => session.connectionId === options.connectionId)

    if (itemIndex > -1) {
      const [session] = this.sessions.splice(itemIndex, 1)
      const eventEmitter = agentContext.dependencyManager.resolve(EventEmitter)

      eventEmitter.emit<MessagePickupLiveSessionRemovedEvent>(agentContext, {
        type: MessagePickupEventTypes.LiveSessionRemoved,
        payload: {
          session,
        },
      })
    }
  }
}
