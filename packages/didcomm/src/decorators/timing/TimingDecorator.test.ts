import { JsonTransformer } from '../../../../core'

import { TimingDecorator } from './TimingDecorator'

describe('Decorators | TimingDecorator', () => {
  it('should correctly transform Json to TimingDecorator class', () => {
    const json = {
      in_time: '2019-01-23 18:03:27.123Z',
      out_time: '2019-01-23 18:03:27.123Z',
      stale_time: '2019-01-24 18:25Z',
      expires_time: '2019-01-25 18:25Z',
      delay_milli: 12345,
      wait_until_time: '2019-01-24 00:00Z',
    }
    const decorator = JsonTransformer.fromJSON(json, TimingDecorator)

    expect(decorator.inTime).toBeInstanceOf(Date)
    expect(decorator.outTime).toBeInstanceOf(Date)
    expect(decorator.staleTime).toBeInstanceOf(Date)
    expect(decorator.expiresTime).toBeInstanceOf(Date)
    expect(decorator.delayMilli).toBe(json.delay_milli)
    expect(decorator.waitUntilTime).toBeInstanceOf(Date)
  })

  it('should correctly transform TimingDecorator class to Json', () => {
    const inTime = new Date('2019-01-23 18:03:27.123Z')
    const outTime = new Date('2019-01-23 18:03:27.123Z')
    const staleTime = new Date('2019-01-24 18:25:00.000Z')
    const expiresTime = new Date('2019-01-25 18:25:00:000Z')
    const delayMilli = 12345
    const waitUntilTime = new Date('2019-01-24 00:00:00.000Z')

    const decorator = new TimingDecorator({
      inTime,
      outTime,
      staleTime,
      expiresTime,
      delayMilli,
      waitUntilTime,
    })

    const jsonString = JsonTransformer.serialize(decorator)
    const transformed = JSON.stringify({
      in_time: '2019-01-23T18:03:27.123Z',
      out_time: '2019-01-23T18:03:27.123Z',
      stale_time: '2019-01-24T18:25:00.000Z',
      expires_time: '2019-01-25T18:25:00.000Z',
      delay_milli: 12345,
      wait_until_time: '2019-01-24T00:00:00.000Z',
    })

    expect(jsonString).toEqual(transformed)
  })
})
