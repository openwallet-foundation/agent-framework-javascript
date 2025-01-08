import { CredoError } from '@credo-ts/core'
import { ProblemReportMessage } from '../../messages/problem-reports/ProblemReportMessage'

export interface ProblemReportErrorOptions {
  problemCode: string
}

export class ProblemReportError extends CredoError {
  public problemReport: ProblemReportMessage

  public constructor(message: string, { problemCode }: ProblemReportErrorOptions) {
    super(message)
    this.problemReport = new ProblemReportMessage({
      description: {
        en: message,
        code: problemCode,
      },
    })
  }
}
