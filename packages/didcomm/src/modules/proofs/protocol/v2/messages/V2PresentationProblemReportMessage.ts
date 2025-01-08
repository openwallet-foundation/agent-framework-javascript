import { ProblemReportMessage } from '../../../../../messages'
import { IsValidMessageType, parseMessageType } from '../../../../../util/messageType'

/**
 * @see https://github.com/hyperledger/aries-rfcs/blob/main/features/0035-report-problem/README.md
 */
export class V2PresentationProblemReportMessage extends ProblemReportMessage {
  @IsValidMessageType(V2PresentationProblemReportMessage.type)
  public readonly type = V2PresentationProblemReportMessage.type.messageTypeUri
  public static readonly type = parseMessageType('https://didcomm.org/present-proof/2.0/problem-report')
}
