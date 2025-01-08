import { JsonTransformer } from '../../../../core/src/utils/JsonTransformer'
import { Compose } from '../../../../core/src/utils/mixins'
import { BaseMessage } from '../../BaseMessage'

import { ServiceDecorated } from './ServiceDecoratorExtension'

describe('Decorators | ServiceDecoratorExtension', () => {
  class TestMessage extends Compose(BaseMessage, [ServiceDecorated]) {
    public toJSON(): Record<string, unknown> {
      return JsonTransformer.toJSON(this)
    }
  }

  const service = {
    recipientKeys: ['test', 'test'],
    routingKeys: ['test', 'test'],
    serviceEndpoint: 'https://example.com',
  }

  test('transforms ServiceDecorator class to JSON', () => {
    const message = new TestMessage()

    message.setService(service)
    expect(message.toJSON()).toEqual({ '~service': service })
  })

  test('transforms Json to ServiceDecorator class', () => {
    const transformed = JsonTransformer.fromJSON(
      { '@id': 'randomID', '@type': 'https://didcomm.org/fake-protocol/1.5/message', '~service': service },
      TestMessage
    )

    expect(transformed.service).toEqual(service)
    expect(transformed).toBeInstanceOf(TestMessage)
  })
})
