import type { JsonObject } from '../../../../types'
import type { DidDocument, VerificationMethod } from '../../domain'

import { Key } from '../../../../crypto/Key'
import { CredoError } from '../../../../error'
import { JsonEncoder, JsonTransformer } from '../../../../utils'
import { DidDocumentService } from '../../domain'
import { DidDocumentBuilder } from '../../domain/DidDocumentBuilder'
import { getKeyFromVerificationMethod, getKeyDidMappingByKeyType } from '../../domain/key-type'
import { parseDid } from '../../domain/parse'

enum DidPeerPurpose {
  Assertion = 'A',
  Encryption = 'E',
  Verification = 'V',
  CapabilityInvocation = 'I',
  CapabilityDelegation = 'D',
  Service = 'S',
}

function isDidPeerKeyPurpose(purpose: string): purpose is Exclude<DidPeerPurpose, DidPeerPurpose.Service> {
  return purpose !== DidPeerPurpose.Service && Object.values(DidPeerPurpose).includes(purpose as DidPeerPurpose)
}

const didPeerAbbreviations: { [key: string]: string | undefined } = {
  type: 't',
  DIDCommMessaging: 'dm',
  serviceEndpoint: 's',
  routingKeys: 'r',
  accept: 'a',
}

const didPeerExpansions: { [key: string]: string | undefined } = {
  t: 'type',
  dm: 'DIDCommMessaging',
  s: 'serviceEndpoint',
  r: 'routingKeys',
  a: 'accept',
}

export function didToNumAlgo2DidDocument(did: string) {
  const parsed = parseDid(did)
  const identifierWithoutNumAlgo = parsed.id.substring(2)

  // Get a list of all did document entries splitted by .
  const entries = identifierWithoutNumAlgo.split('.')
  const didDocument = new DidDocumentBuilder(did)
  let serviceIndex = 0
  let keyIndex = 1

  for (const entry of entries) {
    // Remove the purpose identifier to get the service or key content
    const entryContent = entry.substring(1)
    // Get the purpose identifier
    const purpose = entry[0]

    // Handle service entry first
    if (purpose === DidPeerPurpose.Service) {
      let services = JsonEncoder.fromBase64(entryContent)

      // Make sure we have an array of services (can be both json or array)
      services = Array.isArray(services) ? services : [services]

      for (let service of services) {
        // Expand abbreviations used for service key/values
        service = expandServiceAbbreviations(service)

        service.id = `${did}#${service.type.toLowerCase()}-${serviceIndex++}`

        didDocument.addService(JsonTransformer.fromJSON(service, DidDocumentService))
      }
    }
    // Otherwise we can be sure it is a key
    else {
      // Decode the fingerprint, and extract the verification method(s)
      const key = Key.fromFingerprint(entryContent)
      const { getVerificationMethods } = getKeyDidMappingByKeyType(key.keyType)
      const verificationMethods = getVerificationMethods(did, key)

      // Add all verification methods to the did document
      for (const verificationMethod of verificationMethods) {
        verificationMethod.id = `${did}#key-${keyIndex++}`
        addVerificationMethodToDidDocument(didDocument, verificationMethod, purpose)
      }
    }
  }

  return didDocument.build()
}

export function didDocumentToNumAlgo2Did(didDocument: DidDocument) {
  const purposeMapping = {
    [DidPeerPurpose.Assertion]: didDocument.assertionMethod,
    [DidPeerPurpose.Encryption]: didDocument.keyAgreement,
    // FIXME: should verification be authentication or verificationMethod
    // verificationMethod is general so it doesn't make a lot of sense to add
    // it to the verificationMethod list
    [DidPeerPurpose.Verification]: didDocument.authentication,
    [DidPeerPurpose.CapabilityInvocation]: didDocument.capabilityInvocation,
    [DidPeerPurpose.CapabilityDelegation]: didDocument.capabilityDelegation,
  }

  let did = 'did:peer:2'

  const keys: { id: string; encoded: string }[] = []

  for (const [purpose, entries] of Object.entries(purposeMapping)) {
    // Not all entries are required to be defined
    if (entries === undefined) continue

    // Dereference all entries to full verification methods
    const dereferenced = entries.map((entry) =>
      typeof entry === 'string' ? didDocument.dereferenceVerificationMethod(entry) : entry
    )

    // Transform all verification methods into a fingerprint (multibase, multicodec)
    dereferenced.forEach((entry) => {
      const key = getKeyFromVerificationMethod(entry)

      // Encode as '.PurposeFingerprint'
      const encoded = `.${purpose}${key.fingerprint}`

      keys.push({ id: entry.id, encoded })
    })
  }

  const prefix = 'key-'
  if (!keys.every((key) => key.id.split('#')[1]?.startsWith(prefix))) {
    throw new CredoError('Ids for keys within DID Document for did:peer:2 creation must follow the pattern `#key-n`')
  }

  // Add all encoded keys ordered by their id (#key-1, #key-2, etc.)
  did += keys
    .sort((a, b) => {
      const aFragment = a.id.split('#')[1]
      const bFragment = b.id.split('#')[1]
      const aIndex = Number(aFragment.replace(prefix, ''))
      const bIndex = Number(bFragment.replace(prefix, ''))

      return aIndex - bIndex
    })
    .map((key) => key.encoded)
    .join('')

  if (didDocument.service && didDocument.service.length > 0) {
    const abbreviatedServices = didDocument.service.map((service) => {
      // Transform to JSON, remove id property
      const serviceJson = JsonTransformer.toJSON(service)
      delete serviceJson.id

      return abbreviateServiceJson(serviceJson)
    })

    for (const abbreviatedService of abbreviatedServices) {
      const encodedService = JsonEncoder.toBase64URL(abbreviatedService)
      did += `.${DidPeerPurpose.Service}${encodedService}`
    }
  }

  return did
}

function expandServiceAbbreviations(service: JsonObject) {
  const expand = (abbreviated: string) => didPeerExpansions[abbreviated] ?? abbreviated
  const expandJson = (json: unknown): unknown => {
    if (!json) return json
    if (typeof json === 'number') return json
    if (typeof json === 'string') return expand(json)
    if (Array.isArray(json)) return json.map(expandJson)
    if (typeof json === 'object')
      return Object.entries(json as Record<string, unknown>).reduce(
        (jsonBody, [key, value]) => ({
          ...jsonBody,
          [expand(key)]: expandJson(value),
        }),
        {}
      )
  }

  const fullService = expandJson(service) as Record<string, unknown>

  // Handle the case where a legacy DIDComm v2 service has been encoded in the did:peer:2.
  // We use the legacy `DIDComm` type (over `DIDCommMessaging`)
  if ('t' in service && service.t === 'dm' && typeof service.serviceEndpoint === 'string') {
    return {
      ...fullService,
      type: 'DIDComm',
    }
  }

  return fullService
}

function abbreviateServiceJson(service: JsonObject) {
  const abbreviate = (expanded: string) => didPeerAbbreviations[expanded] ?? expanded

  const abbreviatedService = Object.entries(service).reduce(
    (serviceBody, [key, value]) => ({
      ...serviceBody,
      [abbreviate(key)]: abbreviate(value as string),
    }),
    {}
  )

  return abbreviatedService
}

function addVerificationMethodToDidDocument(
  didDocument: DidDocumentBuilder,
  verificationMethod: VerificationMethod,
  purpose: string
) {
  const purposeMapping = {
    [DidPeerPurpose.Assertion]: didDocument.addAssertionMethod.bind(didDocument),
    [DidPeerPurpose.Encryption]: didDocument.addKeyAgreement.bind(didDocument),
    // FIXME: should verification be authentication or verificationMethod
    // verificationMethod is general so it doesn't make a lot of sense to add
    // it to the verificationMethod list
    [DidPeerPurpose.Verification]: didDocument.addAuthentication.bind(didDocument),
    [DidPeerPurpose.CapabilityInvocation]: didDocument.addCapabilityInvocation.bind(didDocument),
    [DidPeerPurpose.CapabilityDelegation]: didDocument.addCapabilityDelegation.bind(didDocument),
  }

  // Verify the purpose is a did peer key purpose (service excluded)
  if (isDidPeerKeyPurpose(purpose)) {
    const addVerificationMethod = purposeMapping[purpose]

    // Add the verification method based on the method from the mapping
    addVerificationMethod(verificationMethod)
  } else {
    throw new CredoError(`Unsupported peer did purpose '${purpose}'`)
  }
}
