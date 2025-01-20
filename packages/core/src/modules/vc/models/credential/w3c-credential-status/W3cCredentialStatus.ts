import { plainToInstance } from 'class-transformer'
import { IsEnum, IsString, validateOrReject } from 'class-validator'

import { AgentContext } from '../../../../../agent/context'
import { CredoError } from '../../../../../error'
import { IsUri } from '../../../../../utils/validators'

import { BitStringStatusListEntry } from './bitstring-status-list/BitStringStatusList'
import { verifyBitStringCredentialStatus } from './bitstring-status-list/VerifyBitStringCredentialStatus'

export interface W3cCredentialStatusOptions {
  id: string
  type: string
}

export enum W3cCredentialStatusSupportedTypes {
  BitstringStatusListEntry = 'BitstringStatusListEntry',
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
  @IsEnum(W3cCredentialStatusSupportedTypes, { message: 'Invalid credential status type' })
  public type!: string
}

// Function to validate the status using the updated method
export const validateStatus = async (
  status: W3cCredentialStatus | W3cCredentialStatus[],
  agentContext: AgentContext
): Promise<boolean> => {
  let entry

  if (Array.isArray(status)) {
    agentContext.config.logger.debug('Credential status type is array')
    throw new CredoError(
      'Invalid credential status type. Currently only a single credentialStatus is supported per credential'
    )
  } else entry = status

  switch (entry.type) {
    case W3cCredentialStatusSupportedTypes.BitstringStatusListEntry:
      agentContext.config.logger.debug('Credential status type is BitstringStatusListEntry')
      entry = plainToInstance(BitStringStatusListEntry, entry)
      break
    default:
      throw new CredoError(
        `Invalid credential status type. Supported types are: ${Object.values(W3cCredentialStatusSupportedTypes).join(
          ', '
        )}`
      )
  }

  try {
    await validateOrReject(entry)
    switch (entry.type) {
      case W3cCredentialStatusSupportedTypes.BitstringStatusListEntry:
        await verifyBitStringCredentialStatus(entry, agentContext)
        break
      default:
        throw new CredoError(
          `Invalid credential status type. Supported types are: ${Object.values(W3cCredentialStatusSupportedTypes).join(
            ', '
          )}`
        )
    }
    return true
  } catch (errors) {
    throw new CredoError(`Error while validating credential status`, errors)
  }
}
