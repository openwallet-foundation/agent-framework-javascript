import { ClassValidationError, JsonTransformer, MessageValidator } from '../../../../core'

import { TransportDecorator, ReturnRouteTypes } from './TransportDecorator'

const validTransport = (transportJson: Record<string, unknown>) =>
  MessageValidator.validateSync(JsonTransformer.fromJSON(transportJson, TransportDecorator))
const expectValid = (transportJson: Record<string, unknown>) => expect(validTransport(transportJson)).toBeUndefined()
const expectInvalid = (transportJson: Record<string, unknown>) =>
  expect(() => validTransport(transportJson)).toThrowError(ClassValidationError)

const valid = {
  all: {
    return_route: 'all',
  },
  none: {
    return_route: 'none',
  },
  thread: {
    return_route: 'thread',
    return_route_thread: '7d5d797c-db60-489f-8787-87bbd1acdb7e',
  },
}

const invalid = {
  random: {
    return_route: 'random',
  },
  invalidThreadId: {
    return_route: 'thread',
    return_route_thread: 'invalid',
  },
  missingThreadId: {
    return_route: 'thread',
  },
}

describe('Decorators | TransportDecorator', () => {
  it('should correctly transform Json to TransportDecorator class', () => {
    const decorator = JsonTransformer.fromJSON(valid.thread, TransportDecorator)

    expect(decorator.returnRoute).toBe(valid.thread.return_route)
    expect(decorator.returnRouteThread).toBe(valid.thread.return_route_thread)
  })

  it('should correctly transform TransportDecorator class to Json', () => {
    const id = 'f6ce6225-087b-46c1-834a-3e7e24116a00'
    const decorator = new TransportDecorator({
      returnRoute: ReturnRouteTypes.thread,
      returnRouteThread: id,
    })

    const json = JsonTransformer.toJSON(decorator)
    const transformed = {
      return_route: 'thread',
      return_route_thread: id,
    }

    expect(json).toEqual(transformed)
  })

  it('should only allow correct return_route values', () => {
    expect.assertions(4)
    expectValid(valid.all)
    expectValid(valid.none)
    expectValid(valid.thread)
    expectInvalid(invalid.random)
  })

  it('should require return_route_thread when return_route is thread', async () => {
    expect.assertions(3)
    expectValid(valid.thread)
    expectInvalid(invalid.invalidThreadId)
    expectInvalid(invalid.missingThreadId)
  })
})
