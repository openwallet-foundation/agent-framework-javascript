import type { ProblemReportMessageOptions } from '@credo-ts/didcomm'

import { ProblemReportMessage, IsValidMessageType, parseMessageType } from '@credo-ts/didcomm'

export type V1PresentationProblemReportMessageOptions = ProblemReportMessageOptions

/**
 * @see https://github.com/hyperledger/aries-rfcs/blob/main/features/0035-report-problem/README.md
 */
export class V1PresentationProblemReportMessage extends ProblemReportMessage {
  public readonly allowDidSovPrefix = true

  /**
   * Create new PresentationProblemReportMessage instance.
   * @param options description of error and multiple optional fields for reporting problem
   */
  public constructor(options: V1PresentationProblemReportMessageOptions) {
    super(options)
  }

  @IsValidMessageType(V1PresentationProblemReportMessage.type)
  public readonly type = V1PresentationProblemReportMessage.type.messageTypeUri
  public static readonly type = parseMessageType('https://didcomm.org/present-proof/1.0/problem-report')
}
