import type { DidDocumentService } from './service'

import { Expose, Type } from 'class-transformer'
import { IsArray, IsOptional, IsString, ValidateNested } from 'class-validator'

import { Key } from '../../../crypto/Key'
import { KeyType } from '../../../crypto/KeyType'
import { CredoError } from '../../../error'
import { JsonTransformer } from '../../../utils/JsonTransformer'
import { IsStringOrStringArray } from '../../../utils/transformers'

import { getKeyFromVerificationMethod } from './key-type'
import { IndyAgentService, ServiceTransformer, DidCommV1Service } from './service'
import { VerificationMethodTransformer, VerificationMethod, IsStringOrVerificationMethod } from './verificationMethod'

export type DidPurpose =
  | 'authentication'
  | 'keyAgreement'
  | 'assertionMethod'
  | 'capabilityInvocation'
  | 'capabilityDelegation'

type DidVerificationMethods = DidPurpose | 'verificationMethod'

interface DidDocumentOptions {
  context?: string | string[]
  id: string
  alsoKnownAs?: string[]
  controller?: string | string[]
  verificationMethod?: VerificationMethod[]
  service?: DidDocumentService[]
  authentication?: Array<string | VerificationMethod>
  assertionMethod?: Array<string | VerificationMethod>
  keyAgreement?: Array<string | VerificationMethod>
  capabilityInvocation?: Array<string | VerificationMethod>
  capabilityDelegation?: Array<string | VerificationMethod>
}

export class DidDocument {
  @Expose({ name: '@context' })
  @IsStringOrStringArray()
  public context: string | string[] = ['https://w3id.org/did/v1']

  @IsString()
  public id!: string

  @IsArray()
  @IsString({ each: true })
  @IsOptional()
  public alsoKnownAs?: string[]

  @IsStringOrStringArray()
  @IsOptional()
  public controller?: string | string[]

  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => VerificationMethod)
  @IsOptional()
  public verificationMethod?: VerificationMethod[]

  @IsArray()
  @ServiceTransformer()
  @IsOptional()
  public service?: DidDocumentService[]

  @IsArray()
  @VerificationMethodTransformer()
  @IsStringOrVerificationMethod({ each: true })
  @IsOptional()
  public authentication?: Array<string | VerificationMethod>

  @IsArray()
  @VerificationMethodTransformer()
  @IsStringOrVerificationMethod({ each: true })
  @IsOptional()
  public assertionMethod?: Array<string | VerificationMethod>

  @IsArray()
  @VerificationMethodTransformer()
  @IsStringOrVerificationMethod({ each: true })
  @IsOptional()
  public keyAgreement?: Array<string | VerificationMethod>

  @IsArray()
  @VerificationMethodTransformer()
  @IsStringOrVerificationMethod({ each: true })
  @IsOptional()
  public capabilityInvocation?: Array<string | VerificationMethod>

  @IsArray()
  @VerificationMethodTransformer()
  @IsStringOrVerificationMethod({ each: true })
  @IsOptional()
  public capabilityDelegation?: Array<string | VerificationMethod>

  public constructor(options: DidDocumentOptions) {
    if (options) {
      this.context = options.context ?? this.context
      this.id = options.id
      this.alsoKnownAs = options.alsoKnownAs
      this.controller = options.controller
      this.verificationMethod = options.verificationMethod
      this.service = options.service
      this.authentication = options.authentication
      this.assertionMethod = options.assertionMethod
      this.keyAgreement = options.keyAgreement
      this.capabilityInvocation = options.capabilityInvocation
      this.capabilityDelegation = options.capabilityDelegation
    }
  }

  public dereferenceVerificationMethod(keyId: string) {
    // TODO: once we use JSON-LD we should use that to resolve references in did documents.
    // for now we check whether the key id ends with the keyId.
    // so if looking for #123 and key.id is did:key:123#123, it is valid. But #123 as key.id is also valid
    const verificationMethod = this.verificationMethod?.find((key) => key.id.endsWith(keyId))

    if (!verificationMethod) {
      throw new CredoError(`Unable to locate verification method with id '${keyId}'`)
    }

    return verificationMethod
  }

  public dereferenceKey(keyId: string, allowedPurposes?: DidVerificationMethods[]) {
    const allPurposes: DidVerificationMethods[] = [
      'authentication',
      'keyAgreement',
      'assertionMethod',
      'capabilityInvocation',
      'capabilityDelegation',
      'verificationMethod',
    ]

    const purposes = allowedPurposes ?? allPurposes

    for (const purpose of purposes) {
      for (const key of this[purpose] ?? []) {
        if (typeof key === 'string' && key.endsWith(keyId)) {
          return this.dereferenceVerificationMethod(key)
        } else if (typeof key !== 'string' && key.id.endsWith(keyId)) {
          return key
        }
      }
    }

    throw new CredoError(`Unable to locate verification method with id '${keyId}' in purposes ${purposes}`)
  }

  /**
   * Returns all of the service endpoints matching the given type.
   *
   * @param type The type of service(s) to query.
   */
  public getServicesByType<S extends DidDocumentService = DidDocumentService>(type: string): S[] {
    return (this.service?.filter((service) => service.type === type) ?? []) as S[]
  }

  /**
   * Returns all of the service endpoints matching the given class
   *
   * @param classType The class to query services.
   */
  public getServicesByClassType<S extends DidDocumentService = DidDocumentService>(
    classType: new (...args: never[]) => S
  ): S[] {
    return (this.service?.filter((service) => service instanceof classType) ?? []) as S[]
  }

  /**
   * Get all DIDComm services ordered by priority descending. This means the highest
   * priority will be the first entry.
   */
  public get didCommServices(): Array<IndyAgentService | DidCommV1Service> {
    const didCommServiceTypes = [IndyAgentService.type, DidCommV1Service.type]
    const services = (this.service?.filter((service) => didCommServiceTypes.includes(service.type)) ?? []) as Array<
      IndyAgentService | DidCommV1Service
    >

    // Sort services based on indicated priority
    return services.sort((a, b) => a.priority - b.priority)
  }

  // TODO: it would probably be easier if we add a utility to each service so we don't have to handle logic for all service types here
  public get recipientKeys(): Key[] {
    let recipientKeys: Key[] = []

    for (const service of this.didCommServices) {
      if (service.type === IndyAgentService.type) {
        recipientKeys = [
          ...recipientKeys,
          ...service.recipientKeys.map((publicKeyBase58) => Key.fromPublicKeyBase58(publicKeyBase58, KeyType.Ed25519)),
        ]
      } else if (service.type === DidCommV1Service.type) {
        recipientKeys = [
          ...recipientKeys,
          ...service.recipientKeys.map((recipientKey) =>
            getKeyFromVerificationMethod(this.dereferenceKey(recipientKey, ['authentication', 'keyAgreement']))
          ),
        ]
      }
    }

    return recipientKeys
  }

  public toJSON() {
    return JsonTransformer.toJSON(this)
  }
}

/**
 * Extracting the verification method for signature type
 * @param type Signature type
 * @param didDocument DidDocument
 * @returns verification method
 */
export async function findVerificationMethodByKeyType(
  keyType: string,
  didDocument: DidDocument
): Promise<VerificationMethod | null> {
  const didVerificationMethods: DidVerificationMethods[] = [
    'verificationMethod',
    'authentication',
    'keyAgreement',
    'assertionMethod',
    'capabilityInvocation',
    'capabilityDelegation',
  ]
  for await (const purpose of didVerificationMethods) {
    const key: VerificationMethod[] | (string | VerificationMethod)[] | undefined = didDocument[purpose]
    if (key instanceof Array) {
      for await (const method of key) {
        if (typeof method !== 'string') {
          if (method.type === keyType) {
            return method
          }
        }
      }
    }
  }

  return null
}
