import type { BitStringStatusListCredential, BitStringStatusListEntry } from './BitStringStatusList'
import type { AgentContext } from '../../../../../../agent/context'

import { ungzip } from 'pako'

import { CredoError } from '../../../../../../error'

// Function to fetch and parse the bit string status list credential
const fetchBitStringStatusListCredential = async (
  agentContext: AgentContext,
  url: string
): Promise<BitStringStatusListCredential> => {
  const response = await agentContext.config.agentDependencies.fetch(url, { method: 'GET' })

  if (!response.ok) {
    throw new CredoError(`Failed to fetch BitStringStatusListCredential status list. HTTP Status: ${response.status}`)
  }

  try {
    return (await response.json()) as BitStringStatusListCredential
  } catch (error) {
    throw new CredoError('Failed to parse the bit string status list credential')
  }
}

export const verifyBitStringCredentialStatus = async (
  credentialStatus: BitStringStatusListEntry,
  agentContext: AgentContext
) => {
  if (Array.isArray(credentialStatus)) {
    agentContext.config.logger.debug('Credential status type is array')
    throw new CredoError(
      'Invalid credential status type. Currently only a single BitstringStatusListEntry is supported per credential'
    )
  }

  // Fetch the bit string status list credential
  const bitStringStatusListCredential = await fetchBitStringStatusListCredential(
    agentContext,
    credentialStatus.statusListCredential
  )

  if (Array.isArray(bitStringStatusListCredential.credentialSubject)) {
    agentContext.config.logger.debug('Credential subject type is array for the fetched Bitstring Status List Credential')
    throw new CredoError(
      'Invalid credential subject type. Currently only a single credentialSubject is supported per BitstringStatusListCredential'
    )
  }

  // Decode the encoded bit string
  const encodedBitString = bitStringStatusListCredential.credentialSubject.encodedList
  const compressedBuffer = Uint8Array.from(atob(encodedBitString), (char) => char.charCodeAt(0))

  // Decompress the bit string using pako
  const decodedBitString = ungzip(compressedBuffer, { to: 'string' })
  const statusListIndex = Number(credentialStatus.statusListIndex)

  // Ensure the statusListIndex is within bounds
  if (statusListIndex < 0 || statusListIndex >= decodedBitString.length) {
    throw new CredoError('Status list index is out of bounds')
  }

  // Check if the credential is revoked
  if (decodedBitString[statusListIndex] === '1') {
    // To do: The error can be updated once we add support for status messages
    throw new CredoError(
      `Credential at index ${credentialStatus.statusListIndex} is in ${bitStringStatusListCredential.credentialSubject.statusPurpose} state.`
    )
  }

  return true
}