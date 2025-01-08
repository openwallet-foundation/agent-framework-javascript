import type { ActionMenuProblemReportReason } from './ActionMenuProblemReportReason'
import type { ProblemReportErrorOptions } from '@credo-ts/didcomm'

import { ProblemReportError } from '@credo-ts/didcomm'

import { ActionMenuProblemReportMessage } from '../messages'

/**
 * @internal
 */
interface ActionMenuProblemReportErrorOptions extends ProblemReportErrorOptions {
  problemCode: ActionMenuProblemReportReason
}

/**
 * @internal
 */
export class ActionMenuProblemReportError extends ProblemReportError {
  public problemReport: ActionMenuProblemReportMessage

  public constructor(public message: string, { problemCode }: ActionMenuProblemReportErrorOptions) {
    super(message, { problemCode })
    this.problemReport = new ActionMenuProblemReportMessage({
      description: {
        en: message,
        code: problemCode,
      },
    })
  }
}
