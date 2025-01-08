import type { BaseAgent } from '../../agent/BaseAgent'
import type { VersionString } from '../../utils/version'

import { updateV0_3ToV0_3_1 } from './updates/0.3-0.3.1'
import { updateV0_3_1ToV0_4 } from './updates/0.3.1-0.4'
import { updateV0_4ToV0_5 } from './updates/0.4-0.5'

export const INITIAL_STORAGE_VERSION = '0.1'

export interface UpdateConfig {
  v0_1ToV0_2: V0_1ToV0_2UpdateConfig
}

export interface Update {
  fromVersion: VersionString
  toVersion: VersionString
  doUpdate: <Agent extends BaseAgent>(agent: Agent, updateConfig: UpdateConfig) => Promise<void>
}

export interface V0_1ToV0_2UpdateConfig {
  mediationRoleUpdateStrategy: 'allMediator' | 'allRecipient' | 'recipientIfEndpoint' | 'doNotChange'
}

export const DEFAULT_UPDATE_CONFIG: UpdateConfig = {
  v0_1ToV0_2: {
    mediationRoleUpdateStrategy: 'recipientIfEndpoint',
  },
}

export const supportedUpdates = [
  {
    fromVersion: '0.1',
    toVersion: '0.2',
    doUpdate: () => {}, // Nothing to do in Core module
  },
  {
    fromVersion: '0.2',
    toVersion: '0.3',
    doUpdate: () => {}, // Nothing to do in Core module
  },
  {
    fromVersion: '0.3',
    toVersion: '0.3.1',
    doUpdate: updateV0_3ToV0_3_1,
  },
  {
    fromVersion: '0.3.1',
    toVersion: '0.4',
    doUpdate: updateV0_3_1ToV0_4,
  },
  {
    fromVersion: '0.4',
    toVersion: '0.5',
    doUpdate: updateV0_4ToV0_5,
  },
] as const

// Current version is last toVersion from the supported updates
export const CURRENT_FRAMEWORK_STORAGE_VERSION = supportedUpdates[supportedUpdates.length - 1].toVersion as LastItem<
  typeof supportedUpdates
>['toVersion']

// eslint-disable-next-line @typescript-eslint/no-unused-vars
type LastItem<T extends readonly unknown[]> = T extends readonly [...infer _, infer U] ? U : T[0] | undefined
export type UpdateToVersion = (typeof supportedUpdates)[number]['toVersion']
