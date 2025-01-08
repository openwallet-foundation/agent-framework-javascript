import type { InboundMessageContext } from '../models/InboundMessageContext'

export interface MessageHandlerMiddleware {
  (inboundMessageContext: InboundMessageContext, next: () => Promise<void>): Promise<void>
}

export class MessageHandlerMiddlewareRunner {
  public static async run(middlewares: MessageHandlerMiddleware[], inboundMessageContext: InboundMessageContext) {
    const compose = (middlewares: MessageHandlerMiddleware[]) => {
      return async function (inboundMessageContext: InboundMessageContext) {
        let index = -1
        async function dispatch(i: number): Promise<void> {
          if (i <= index) throw new Error('next() called multiple times')
          index = i
          const fn = middlewares[i]
          if (!fn) return
          await fn(inboundMessageContext, () => dispatch(i + 1))
        }
        await dispatch(0)
      }
    }

    const composed = compose(middlewares)
    await composed(inboundMessageContext)
  }
}
