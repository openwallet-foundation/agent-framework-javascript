import type {
  DiscoverFeaturesDisclosureReceivedEvent,
  DiscoverFeaturesQueryReceivedEvent,
} from '../DiscoverFeaturesEvents'
import type { Observable } from 'rxjs'

import { map, catchError, timeout, firstValueFrom, ReplaySubject } from 'rxjs'

export function waitForDisclosureSubject(
  subject: ReplaySubject<DiscoverFeaturesDisclosureReceivedEvent> | Observable<DiscoverFeaturesDisclosureReceivedEvent>,
  { timeoutMs = 10000 }: { timeoutMs: number }
) {
  const observable = subject instanceof ReplaySubject ? subject.asObservable() : subject

  return firstValueFrom(
    observable.pipe(
      timeout(timeoutMs),
      catchError(() => {
        throw new Error(`DiscoverFeaturesDisclosureReceivedEvent event not emitted within specified timeout`)
      }),
      map((e) => e.payload)
    )
  )
}

export function waitForQuerySubject(
  subject: ReplaySubject<DiscoverFeaturesQueryReceivedEvent> | Observable<DiscoverFeaturesQueryReceivedEvent>,
  { timeoutMs = 10000 }: { timeoutMs: number }
) {
  const observable = subject instanceof ReplaySubject ? subject.asObservable() : subject

  return firstValueFrom(
    observable.pipe(
      timeout(timeoutMs),
      catchError(() => {
        throw new Error(`DiscoverFeaturesQueryReceivedEvent event not emitted within specified timeout`)
      }),
      map((e) => e.payload)
    )
  )
}
