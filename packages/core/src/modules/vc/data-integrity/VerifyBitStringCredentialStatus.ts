import type { AgentContext } from '../../../agent/context'
import type { W3cJsonCredential } from '../models/credential/W3cJsonCredential'
import type { BitStringStatusListCredential } from '../models/credential/W3cJsonCredentialStatus'

import * as pako from 'pako'

import { CredoError } from '../../../error'
import { validateStatus } from '../models/credential/W3cCredentialStatus'

// Function to fetch and parse the bit string status list credential
const fetchBitStringStatusListCredential = async (
  agentContext: AgentContext,
  url: string
): Promise<BitStringStatusListCredential> => {
  const response = await agentContext.config.agentDependencies.fetch(url, { method: 'GET' })

  if (!response.ok) {
    throw new CredoError(`Failed to fetch bit string status list. HTTP Status: ${response.status}`)
  }

  try {
    return (await response.json()) as BitStringStatusListCredential
  } catch (error) {
    throw new CredoError('Failed to parse the bit string status list credential')
  }
}

export const verifyBitStringCredentialStatus = async (credential: W3cJsonCredential, agentContext: AgentContext) => {
  const { credentialStatus } = credential

  if (Array.isArray(credentialStatus)) {
    throw new CredoError('Verifying credential status as an array for JSON-LD credentials is currently not supported')
  }

  if (!credentialStatus || credentialStatus.statusListIndex === undefined) {
    throw new CredoError('Invalid credential status format')
  }

  // Validate credentialStatus using the class-based approach
  const isValid = await validateStatus(credentialStatus, agentContext)

  if (!isValid) {
    throw new CredoError('Invalid credential status type. Expected BitstringStatusList')
  }

  // Fetch the bit string status list credential
  const bitStringStatusListCredential = await fetchBitStringStatusListCredential(
    agentContext,
    credentialStatus.statusListCredential
  )

  // Decode the encoded bit string
  const encodedBitString = bitStringStatusListCredential.credential.credentialSubject.encodedList
  const compressedBuffer = Uint8Array.from(atob(encodedBitString), (char) => char.charCodeAt(0))

  // Decompress the bit string using pako
  const decodedBitString = pako.ungzip(compressedBuffer, { to: 'string' })
  const statusListIndex = Number(credentialStatus.statusListIndex)

  // Ensure the statusListIndex is within bounds
  if (statusListIndex < 0 || statusListIndex >= decodedBitString.length) {
    throw new CredoError('Status list index is out of bounds')
  }

  // Check if the credential is revoked
  if (decodedBitString[statusListIndex] === '1') {
    throw new CredoError(`Credential at index ${credentialStatus.statusListIndex} is revoked.`)
  }

  return true
}
