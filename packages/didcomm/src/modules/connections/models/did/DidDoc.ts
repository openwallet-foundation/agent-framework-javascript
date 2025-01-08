import type { Authentication } from './authentication'
import type { PublicKey } from './publicKey'
import type { DidDocumentService } from '@credo-ts/core'

import { Expose } from 'class-transformer'
import { Equals, IsArray, IsString, ValidateNested } from 'class-validator'

import { ServiceTransformer, DidCommV1Service, IndyAgentService } from '@credo-ts/core'

import { AuthenticationTransformer } from './authentication'
import { PublicKeyTransformer } from './publicKey'

type DidDocOptions = Pick<DidDoc, 'id' | 'publicKey' | 'service' | 'authentication'>

export class DidDoc {
  @Expose({ name: '@context' })
  @Equals('https://w3id.org/did/v1')
  public context = 'https://w3id.org/did/v1'

  @IsString()
  public id!: string

  @IsArray()
  @ValidateNested()
  @PublicKeyTransformer()
  public publicKey: PublicKey[] = []

  @IsArray()
  @ValidateNested()
  @ServiceTransformer()
  public service: DidDocumentService[] = []

  @IsArray()
  @ValidateNested()
  @AuthenticationTransformer()
  public authentication: Authentication[] = []

  public constructor(options: DidDocOptions) {
    if (options) {
      this.id = options.id
      this.publicKey = options.publicKey
      this.service = options.service
      this.authentication = options.authentication
    }
  }

  /**
   * Gets the matching public key for a given key id
   *
   * @param id fully qualified key id
   */
  public getPublicKey(id: string): PublicKey | undefined {
    return this.publicKey.find((item) => item.id === id)
  }

  /**
   * Returns all of the service endpoints matching the given type.
   *
   * @param type The type of service(s) to query.
   */
  public getServicesByType<S extends DidDocumentService = DidDocumentService>(type: string): S[] {
    return this.service.filter((service) => service.type === type) as S[]
  }

  /**
   * Returns all of the service endpoints matching the given class
   *
   * @param classType The class to query services.
   */
  public getServicesByClassType<S extends DidDocumentService = DidDocumentService>(
    classType: new (...args: never[]) => S
  ): S[] {
    return this.service.filter((service) => service instanceof classType) as S[]
  }

  /**
   * Get all DIDComm services ordered by priority descending. This means the highest
   * priority will be the first entry.
   */
  public get didCommServices(): Array<IndyAgentService | DidCommV1Service> {
    const didCommServiceTypes = [IndyAgentService.type, DidCommV1Service.type]
    const services = this.service.filter((service) => didCommServiceTypes.includes(service.type)) as Array<
      IndyAgentService | DidCommV1Service
    >

    // Sort services based on indicated priority
    return services.sort((a, b) => a.priority - b.priority)
  }
}
