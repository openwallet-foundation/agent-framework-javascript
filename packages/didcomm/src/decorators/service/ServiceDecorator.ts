import type { ResolvedDidCommService } from '../../types'

import { IsArray, IsOptional, IsString } from 'class-validator'

import { utils } from '@credo-ts/core'
import { verkeyToInstanceOfKey } from '@credo-ts/core'

export interface ServiceDecoratorOptions {
  recipientKeys: string[]
  routingKeys?: string[]
  serviceEndpoint: string
}

/**
 * Represents `~service` decorator
 *
 * Based on specification Aries RFC 0056: Service Decorator
 * @see https://github.com/hyperledger/aries-rfcs/tree/master/features/0056-service-decorator
 */
export class ServiceDecorator {
  public constructor(options: ServiceDecoratorOptions) {
    if (options) {
      this.recipientKeys = options.recipientKeys
      this.routingKeys = options.routingKeys
      this.serviceEndpoint = options.serviceEndpoint
    }
  }

  @IsArray()
  @IsString({ each: true })
  public recipientKeys!: string[]

  @IsArray()
  @IsString({ each: true })
  @IsOptional()
  public routingKeys?: string[]

  @IsString()
  public serviceEndpoint!: string

  public get resolvedDidCommService(): ResolvedDidCommService {
    return {
      id: utils.uuid(),
      recipientKeys: this.recipientKeys.map(verkeyToInstanceOfKey),
      routingKeys: this.routingKeys?.map(verkeyToInstanceOfKey) ?? [],
      serviceEndpoint: this.serviceEndpoint,
    }
  }

  public static fromResolvedDidCommService(service: ResolvedDidCommService): ServiceDecorator {
    return new ServiceDecorator({
      recipientKeys: service.recipientKeys.map((k) => k.publicKeyBase58),
      routingKeys: service.routingKeys.map((k) => k.publicKeyBase58),
      serviceEndpoint: service.serviceEndpoint,
    })
  }
}
