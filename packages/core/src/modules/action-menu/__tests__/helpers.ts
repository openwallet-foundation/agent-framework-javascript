import type { Agent } from '../../../agent/Agent'
import type { ActionMenuStateChangedEvent } from '../ActionMenuEvents'
import type { ActionMenuRole } from '../ActionMenuRole'
import type { ActionMenuState } from '../ActionMenuState'
import type { Observable } from 'rxjs'

import { catchError, filter, firstValueFrom, map, ReplaySubject, timeout } from 'rxjs'

import { ActionMenuEventTypes } from '../ActionMenuEvents'

export async function waitForActionMenuRecord(
  agent: Agent,
  options: {
    threadId?: string
    role?: ActionMenuRole
    state?: ActionMenuState
    previousState?: ActionMenuState | null
    timeoutMs?: number
  }
) {
  const observable = agent.events.observable<ActionMenuStateChangedEvent>(ActionMenuEventTypes.ActionMenuStateChanged)

  return waitForActionMenuRecordSubject(observable, options)
}

export function waitForActionMenuRecordSubject(
  subject: ReplaySubject<ActionMenuStateChangedEvent> | Observable<ActionMenuStateChangedEvent>,
  {
    threadId,
    role,
    state,
    previousState,
    timeoutMs = 10000,
  }: {
    threadId?: string
    role?: ActionMenuRole
    state?: ActionMenuState
    previousState?: ActionMenuState | null
    timeoutMs?: number
  }
) {
  const observable = subject instanceof ReplaySubject ? subject.asObservable() : subject
  return firstValueFrom(
    observable.pipe(
      filter((e) => previousState === undefined || e.payload.previousState === previousState),
      filter((e) => threadId === undefined || e.payload.actionMenuRecord.threadId === threadId),
      filter((e) => role === undefined || e.payload.actionMenuRecord.role === role),
      filter((e) => state === undefined || e.payload.actionMenuRecord.state === state),
      timeout(timeoutMs),
      catchError(() => {
        throw new Error(
          `ActionMenuStateChangedEvent event not emitted within specified timeout: {
    previousState: ${previousState},
    threadId: ${threadId},
    state: ${state}
  }`
        )
      }),
      map((e) => e.payload.actionMenuRecord)
    )
  )
}
