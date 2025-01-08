import type { ProblemReportMessageOptions } from '@credo-ts/didcomm'

import { IsValidMessageType, parseMessageType, ProblemReportMessage } from '@credo-ts/didcomm'

export type ActionMenuProblemReportMessageOptions = ProblemReportMessageOptions

/**
 * @see https://github.com/hyperledger/aries-rfcs/blob/main/features/0035-report-problem/README.md
 * @internal
 */
export class ActionMenuProblemReportMessage extends ProblemReportMessage {
  /**
   * Create new ConnectionProblemReportMessage instance.
   * @param options
   */
  public constructor(options: ActionMenuProblemReportMessageOptions) {
    super(options)
  }

  @IsValidMessageType(ActionMenuProblemReportMessage.type)
  public readonly type = ActionMenuProblemReportMessage.type.messageTypeUri
  public static readonly type = parseMessageType('https://didcomm.org/action-menu/1.0/problem-report')
}
