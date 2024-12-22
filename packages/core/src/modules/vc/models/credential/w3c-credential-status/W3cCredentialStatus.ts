import { plainToInstance } from 'class-transformer'
import { IsString, validateOrReject } from 'class-validator'

import { AgentContext } from '../../../../../agent/context'
import { CredoError } from '../../../../../error'
import { IsUri } from '../../../../../utils/validators'

export interface W3cCredentialStatusOptions {
  id: string
  type: string
}

export class W3cCredentialStatus {
  public constructor(options: W3cCredentialStatusOptions) {
    if (options) {
      this.id = options.id
      this.type = options.type
    }
  }

  @IsUri()
  @IsString()
  public id!: string

  @IsString()
  public type!: string
}

// Function to validate the status using the updated method
export const validateStatus = async (
  status: W3cCredentialStatus | W3cCredentialStatus[],
  agentContext: AgentContext
): Promise<boolean> => {
  const entry = plainToInstance(W3cCredentialStatus, status)

  try {
    await validateOrReject(entry)
    return true
  } catch (errors) {
    agentContext.config.logger.debug(`Credential status validation failed: ${errors}`, {
      stack: errors,
    })
    throw new CredoError(`Invalid credential status type: ${errors}`)
  }
}
