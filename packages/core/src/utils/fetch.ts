import type { AgentDependencies } from '../agent/AgentDependencies'

import { AbortController } from 'abort-controller'

export async function fetchWithTimeout(
  fetch: AgentDependencies['fetch'],
  url: string,
  init?: Omit<RequestInit, 'signal'> & {
    /**
     * @default 5000
     */
    timeoutMs?: number
  }
) {
  const abortController = new AbortController()
  const timeoutMs = init?.timeoutMs ?? 5000

  const timeout = setTimeout(() => abortController.abort(), timeoutMs)

  try {
    return await fetch(url, {
      ...init,
      signal: abortController.signal as NonNullable<RequestInit['signal']>,
    })
  } finally {
    clearTimeout(timeout)
  }
}
