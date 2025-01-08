import type { ProblemReportMessageOptions } from '@credo-ts/didcomm'

import { ProblemReportMessage, IsValidMessageType, parseMessageType } from '@credo-ts/didcomm'

export type V1CredentialProblemReportMessageOptions = ProblemReportMessageOptions

/**
 * @see https://github.com/hyperledger/aries-rfcs/blob/main/features/0035-report-problem/README.md
 */
export class V1CredentialProblemReportMessage extends ProblemReportMessage {
  public readonly allowDidSovPrefix = true

  /**
   * Create new CredentialProblemReportMessage instance.
   * @param options
   */
  public constructor(options: V1CredentialProblemReportMessageOptions) {
    super(options)
  }

  @IsValidMessageType(V1CredentialProblemReportMessage.type)
  public readonly type = V1CredentialProblemReportMessage.type.messageTypeUri
  public static readonly type = parseMessageType('https://didcomm.org/issue-credential/1.0/problem-report')
}
