import { AriesFrameworkError } from '@aries-framework/core'

export class IndyVdrError extends AriesFrameworkError {
  public constructor(message: string, { cause }: { cause?: Error } = {}) {
    super(message, { cause })
  }
}
