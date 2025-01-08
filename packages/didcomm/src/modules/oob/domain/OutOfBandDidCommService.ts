import type { ResolvedDidCommService } from '../../../types'
import type { ValidationOptions } from 'class-validator'

import { ArrayNotEmpty, buildMessage, IsOptional, isString, IsString, ValidateBy } from 'class-validator'

import { DidDocumentService, DidKey, isDid, IsUri } from '@credo-ts/core'

export class OutOfBandDidCommService extends DidDocumentService {
  public constructor(options: {
    id: string
    serviceEndpoint: string
    recipientKeys: string[]
    routingKeys?: string[]
    accept?: string[]
  }) {
    super({ ...options, type: OutOfBandDidCommService.type })

    if (options) {
      this.recipientKeys = options.recipientKeys
      this.routingKeys = options.routingKeys
      this.accept = options.accept
    }
  }

  public static type = 'did-communication'

  @IsString()
  @IsUri()
  public serviceEndpoint!: string

  @ArrayNotEmpty()
  @IsDidKeyString({ each: true })
  public recipientKeys!: string[]

  @IsDidKeyString({ each: true })
  @IsOptional()
  public routingKeys?: string[]

  @IsString({ each: true })
  @IsOptional()
  public accept?: string[]

  public get resolvedDidCommService(): ResolvedDidCommService {
    return {
      id: this.id,
      recipientKeys: this.recipientKeys.map((didKey) => DidKey.fromDid(didKey).key),
      routingKeys: this.routingKeys?.map((didKey) => DidKey.fromDid(didKey).key) ?? [],
      serviceEndpoint: this.serviceEndpoint,
    }
  }

  public static fromResolvedDidCommService(service: ResolvedDidCommService) {
    return new OutOfBandDidCommService({
      id: service.id,
      recipientKeys: service.recipientKeys.map((key) => new DidKey(key).did),
      routingKeys: service.routingKeys.map((key) => new DidKey(key).did),
      serviceEndpoint: service.serviceEndpoint,
    })
  }
}

/**
 * Checks if a given value is a did:key did string
 */
function IsDidKeyString(validationOptions?: ValidationOptions): PropertyDecorator {
  return ValidateBy(
    {
      name: 'isDidKeyString',
      validator: {
        validate: (value): boolean => isString(value) && isDid(value, 'key'),
        defaultMessage: buildMessage(
          (eachPrefix) => eachPrefix + '$property must be a did:key string',
          validationOptions
        ),
      },
    },
    validationOptions
  )
}
