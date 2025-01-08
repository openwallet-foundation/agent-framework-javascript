import type { AgentContext } from '@credo-ts/core'

export interface InboundTransport {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  start(agent: AgentContext): Promise<void>
  stop(): Promise<void>
}
