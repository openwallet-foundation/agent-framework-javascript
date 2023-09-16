import type { DidComV1BaseMessageConstructor } from '../../didcomm/'

import { Expose, Type } from 'class-transformer'
import { IsInstance, IsOptional, ValidateNested } from 'class-validator'

import { ThreadDecorator } from './ThreadDecorator'

export function ThreadDecorated<T extends DidComV1BaseMessageConstructor>(Base: T) {
  class ThreadDecoratorExtension extends Base {
    /**
     * The ~thread decorator is generally required on any type of response, since this is what connects it with the original request.
     */
    @Expose({ name: '~thread' })
    @IsOptional()
    @Type(() => ThreadDecorator)
    @ValidateNested()
    @IsInstance(ThreadDecorator)
    public thread?: ThreadDecorator

    public get threadId(): string {
      return this.thread?.threadId ?? this.id
    }

    public get parentThreadId(): string | undefined {
      return this.thread?.parentThreadId
    }

    public setThread(options: Partial<ThreadDecorator>) {
      this.thread = new ThreadDecorator(options)
    }
  }

  return ThreadDecoratorExtension
}
