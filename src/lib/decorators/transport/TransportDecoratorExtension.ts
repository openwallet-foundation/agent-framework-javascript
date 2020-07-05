import { Expose, Type } from 'class-transformer';
import { ValidateNested } from 'class-validator';
import { TransportDecorator, ReturnRouteTypes } from './TransportDecorator';
import { BaseMessageConstructor } from '../../agent/BaseMessage';

export function TransportDecorated<T extends BaseMessageConstructor>(Base: T) {
  class TransportDecoratorExtension extends Base {
    @Expose({ name: '~transport' })
    @Type(() => TransportDecorator)
    @ValidateNested()
    transport?: TransportDecorator;

    setReturnRouting(type: ReturnRouteTypes, thread?: string) {
      this.transport = new TransportDecorator({
        returnRoute: type,
        returnRouteThread: thread,
      });
    }

    hasReturnRouting(threadId?: string): boolean {
      //   transport 'none' or undefined always false
      if (!this.transport || this.transport.returnRoute === ReturnRouteTypes.none) return false;
      // transport 'all' always true
      else if (this.transport.returnRoute === ReturnRouteTypes.all) return true;
      // transport 'thread' with matching thread id is true
      else if (this.transport.returnRoute === ReturnRouteTypes.thread && this.transport.returnRouteThread === threadId)
        return true;

      // transport is thread but threadId is either missing or doesn't match. Return false
      return false;
    }
  }

  return TransportDecoratorExtension;
}
