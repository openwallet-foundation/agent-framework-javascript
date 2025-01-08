import { JsonTransformer } from '../../../../core'

import { ThreadDecorator } from './ThreadDecorator'

describe('Decorators | ThreadDecorator', () => {
  it('should correctly transform Json to ThreadDecorator class', () => {
    const json = {
      thid: 'ceffce22-6471-43e4-8945-b604091981c9',
      pthid: '917a109d-eae3-42bc-9436-b02426d3ce2c',
      sender_order: 2,
      received_orders: {
        'did:sov:3ecf688c-cb3f-467b-8636-6b0c7f1d9022': 1,
      },
    }
    const decorator = JsonTransformer.fromJSON(json, ThreadDecorator)

    expect(decorator.threadId).toBe(json.thid)
    expect(decorator.parentThreadId).toBe(json.pthid)
    expect(decorator.senderOrder).toBe(json.sender_order)
    expect(decorator.receivedOrders).toEqual(json.received_orders)
  })

  it('should correctly transform ThreadDecorator class to Json', () => {
    const threadId = 'ceffce22-6471-43e4-8945-b604091981c9'
    const parentThreadId = '917a109d-eae3-42bc-9436-b02426d3ce2c'
    const senderOrder = 2
    const receivedOrders = {
      'did:sov:3ecf688c-cb3f-467b-8636-6b0c7f1d9022': 1,
    }

    const decorator = new ThreadDecorator({
      threadId,
      parentThreadId,
      senderOrder,
      receivedOrders,
    })

    const json = JsonTransformer.toJSON(decorator)
    const transformed = {
      thid: threadId,
      pthid: parentThreadId,
      sender_order: senderOrder,
      received_orders: receivedOrders,
    }

    expect(json).toEqual(transformed)
  })
})
