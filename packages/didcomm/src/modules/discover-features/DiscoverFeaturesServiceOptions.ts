import type { AgentMessage } from '../../AgentMessage'
import type { FeatureQueryOptions } from '../../models'

export interface CreateQueryOptions {
  queries: FeatureQueryOptions[]
  comment?: string
}

export interface CreateDisclosureOptions {
  disclosureQueries: FeatureQueryOptions[]
  threadId?: string
}

export interface DiscoverFeaturesProtocolMsgReturnType<MessageType extends AgentMessage> {
  message: MessageType
}
