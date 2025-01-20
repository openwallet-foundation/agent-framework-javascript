import type { AgentContext } from '../../../../agent'
import type { W3cCredentialStatus } from '../../models/credential/w3c-credential-status/W3cCredentialStatus'


import { CredoError } from '../../../../error/CredoError'
import {
  BitStringStatusListEntry,
  verifyBitStringCredentialStatus,
} from '../../models/credential/w3c-credential-status'
import { W3cCredentialStatusSupportedTypes } from '../../models/credential/w3c-credential-status/W3cCredentialStatus'
import { JsonTransformer, SingleOrArray } from 'packages/core/src/utils'

// Function to validate the status using the updated method
export const validateStatus = async (
  credentialStatus: SingleOrArray<W3cCredentialStatus>,
  agentContext: AgentContext
): Promise<boolean> => {

  if (Array.isArray(credentialStatus)) {
    agentContext.config.logger.debug('Credential status type is array')
    throw new CredoError(
      'Invalid credential status type. Currently only a single credentialStatus is supported per credential'
    )
  }

  switch (credentialStatus.type) {
    case W3cCredentialStatusSupportedTypes.BitstringStatusListEntry:
      agentContext.config.logger.debug('Credential status type is BitstringStatusListEntry')
      const entry = JsonTransformer.fromJSON(credentialStatus, BitStringStatusListEntry)
      try {
        await verifyBitStringCredentialStatus(entry, agentContext)
      } catch (errors) {
        throw new CredoError(`Error while validating credential status`, errors)
      }
      break
    default:
      throw new CredoError(
        `Invalid credential status type. Supported types are: ${Object.values(W3cCredentialStatusSupportedTypes).join(
          ', '
        )}`
      )
  }
  return true
}
