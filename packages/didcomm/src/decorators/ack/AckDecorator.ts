import { IsArray, IsEnum } from 'class-validator'

export enum AckValues {
  Receipt = 'RECEIPT',
  Outcome = 'OUTCOME',
}

/**
 * Represents `~please_ack` decorator
 */
export class AckDecorator {
  public constructor(options: { on: [AckValues.Receipt] }) {
    if (options) {
      this.on = options.on
    }
  }

  // pre-aip 2 the on value was not defined yet. We interpret this as
  // the value being set to on receipt
  @IsEnum(AckValues, { each: true })
  @IsArray()
  public on: AckValues[] = [AckValues.Receipt]
}
