import type { ActionMenuRole } from '../ActionMenuRole'
import type { ActionMenuSelection } from '../models'
import type { ActionMenu } from '../models/ActionMenu'
import type { ActionMenuRecord } from '../repository'
import type { ConnectionRecord } from '@credo-ts/didcomm'

/**
 * @internal
 */
export interface CreateRequestOptions {
  connection: ConnectionRecord
}

/**
 * @internal
 */
export interface CreateMenuOptions {
  connection: ConnectionRecord
  menu: ActionMenu
}

/**
 * @internal
 */
export interface CreatePerformOptions {
  actionMenuRecord: ActionMenuRecord
  performedAction: ActionMenuSelection
}

/**
 * @internal
 */
export interface ClearMenuOptions {
  actionMenuRecord: ActionMenuRecord
}

/**
 * @internal
 */
export interface FindMenuOptions {
  connectionId: string
  role: ActionMenuRole
  threadId?: string
}
