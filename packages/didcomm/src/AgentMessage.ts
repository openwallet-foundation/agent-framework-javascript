import type { PlaintextMessage } from './types'
import type { ParsedMessageType } from './util/messageType'
import type { Constructor } from '@credo-ts/core'

import { Exclude } from 'class-transformer'

import { JsonTransformer } from '@credo-ts/core'

import { BaseMessage } from './BaseMessage'
import { AckDecorated } from './decorators/ack/AckDecoratorExtension'
import { AttachmentDecorated } from './decorators/attachment/AttachmentExtension'
import { L10nDecorated } from './decorators/l10n/L10nDecoratorExtension'
import { ServiceDecorated } from './decorators/service/ServiceDecoratorExtension'
import { ThreadDecorated } from './decorators/thread/ThreadDecoratorExtension'
import { TimingDecorated } from './decorators/timing/TimingDecoratorExtension'
import { TransportDecorated } from './decorators/transport/TransportDecoratorExtension'
import { replaceNewDidCommPrefixWithLegacyDidSovOnMessage } from './util/messageType'

export type ConstructableAgentMessage = Constructor<AgentMessage> & { type: ParsedMessageType }

const Decorated = ThreadDecorated(
  L10nDecorated(TransportDecorated(TimingDecorated(AckDecorated(AttachmentDecorated(ServiceDecorated(BaseMessage))))))
)

export class AgentMessage extends Decorated {
  /**
   * Whether the protocol RFC was initially written using the legacy did:prefix instead of the
   * new https://didcomm.org message type prefix.
   *
   * @see https://github.com/hyperledger/aries-rfcs/blob/main/features/0348-transition-msg-type-to-https/README.md
   */
  @Exclude()
  public readonly allowDidSovPrefix: boolean = false

  /**
   * Whether to use Queue Transport in case the recipient of this message does not have a reliable
   * endpoint available
   *
   * @see https://github.com/decentralized-identity/didcomm-messaging/blob/main/extensions/return_route/main.md#queue-transport
   */
  @Exclude()
  public readonly allowQueueTransport: boolean = true

  public toJSON({ useDidSovPrefixWhereAllowed }: { useDidSovPrefixWhereAllowed?: boolean } = {}): PlaintextMessage {
    const json = JsonTransformer.toJSON(this)

    // If we have `useDidSovPrefixWhereAllowed` enabled, we want to replace the new https://didcomm.org prefix with the legacy did:sov prefix.
    // However, we only do this if the protocol RFC was initially written with the did:sov message type prefix
    // See https://github.com/hyperledger/aries-rfcs/blob/main/features/0348-transition-msg-type-to-https/README.md
    if (this.allowDidSovPrefix && useDidSovPrefixWhereAllowed) {
      replaceNewDidCommPrefixWithLegacyDidSovOnMessage(json)
    }

    return json as PlaintextMessage
  }

  public is<C extends typeof AgentMessage>(Class: C): this is InstanceType<C> {
    return this.type === Class.type.messageTypeUri
  }
}
