import type { Observable } from 'rxjs'

import { filter } from 'rxjs'

export function filterContextCorrelationId(contextCorrelationId: string) {
  return <T extends BaseEvent>(source: Observable<T>) => {
    return source.pipe(filter((event) => event.metadata.contextCorrelationId === contextCorrelationId))
  }
}

export interface EventMetadata {
  contextCorrelationId: string
}

export interface BaseEvent {
  type: string
  payload: Record<string, unknown>
  metadata: EventMetadata
}
