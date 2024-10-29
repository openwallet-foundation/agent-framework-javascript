import { plainToInstance } from 'class-transformer'
import { IsEnum, IsString, validateOrReject } from 'class-validator'

import { AgentContext } from '../../../../agent/context'
import { CredoError } from '../../../../error'
import { IsUri } from '../../../../utils/validators'

import { CredentialStatus, CredentialStatusPurpose, CredentialStatusType } from './W3cJsonCredentialStatus'

export interface W3cCredentialStatusOptions {
  id: string
  type: CredentialStatusType
  statusPurpose: CredentialStatusPurpose
  statusListIndex: string
  statusListCredential: string
}

export class W3cCredentialStatus {
  public constructor(options: W3cCredentialStatusOptions) {
    if (options) {
      this.id = options.id
      this.type = options.type
      this.statusPurpose = options.statusPurpose
      this.statusListIndex = options.statusListIndex
      this.statusListCredential = options.statusListCredential
    }
  }

  @IsUri()
  @IsString()
  public id!: string

  @IsEnum(['BitstringStatusListEntry'])
  @IsString()
  public type!: CredentialStatusType

  @IsEnum(CredentialStatusPurpose)
  @IsString()
  public statusPurpose!: CredentialStatusPurpose

  @IsString()
  public statusListIndex!: string

  @IsString()
  public statusListCredential!: string
}

// Function to validate the status using the updated method
export const validateStatus = async (status: CredentialStatus, agentContext: AgentContext): Promise<boolean> => {
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
