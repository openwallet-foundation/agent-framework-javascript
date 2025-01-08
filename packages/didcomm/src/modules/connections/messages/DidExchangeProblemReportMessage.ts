import type { ProblemReportMessageOptions } from '../../../messages'

import { ProblemReportMessage } from '../../../messages'
import { IsValidMessageType, parseMessageType } from '../../../util/messageType'

export type DidExchangeProblemReportMessageOptions = ProblemReportMessageOptions

/**
 * @see https://github.com/hyperledger/aries-rfcs/blob/main/features/0035-report-problem/README.md
 */
export class DidExchangeProblemReportMessage extends ProblemReportMessage {
  public constructor(options: DidExchangeProblemReportMessageOptions) {
    super(options)
  }

  @IsValidMessageType(DidExchangeProblemReportMessage.type)
  public readonly type = DidExchangeProblemReportMessage.type.messageTypeUri
  public static readonly type = parseMessageType('https://didcomm.org/didexchange/1.1/problem-report')
}
