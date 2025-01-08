import type { BaseMessageConstructor } from '../../BaseMessage'

import { Expose, Type } from 'class-transformer'
import { IsInstance, IsOptional, ValidateNested } from 'class-validator'

import { AckDecorator, AckValues } from './AckDecorator'

export function AckDecorated<T extends BaseMessageConstructor>(Base: T) {
  class AckDecoratorExtension extends Base {
    @Expose({ name: '~please_ack' })
    @Type(() => AckDecorator)
    @ValidateNested()
    @IsInstance(AckDecorator)
    @IsOptional()
    public pleaseAck?: AckDecorator

    public setPleaseAck(on: [AckValues.Receipt] = [AckValues.Receipt]) {
      this.pleaseAck = new AckDecorator({ on })
    }

    public getPleaseAck(): AckDecorator | undefined {
      return this.pleaseAck
    }

    public requiresAck(): boolean {
      return this.pleaseAck !== undefined
    }
  }

  return AckDecoratorExtension
}
