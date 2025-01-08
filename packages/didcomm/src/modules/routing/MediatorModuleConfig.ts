import { MessageForwardingStrategy } from './MessageForwardingStrategy'

/**
 * MediatorModuleConfigOptions defines the interface for the options of the MediatorModuleConfig class.
 * This can contain optional parameters that have default values in the config class itself.
 */
export interface MediatorModuleConfigOptions {
  /**
   * Whether to automatically accept and grant incoming mediation requests.
   *
   * @default false
   */
  autoAcceptMediationRequests?: boolean

  /**
   * Strategy to use when a Forward message is received.
   *
   *
   * - `MessageForwardingStrategy.QueueOnly` - simply queue encrypted message into MessagePickupRepository. It will be in charge of manually trigering MessagePickupApi.deliver() afterwards.
   * - `MessageForwardingStrategy.QueueAndLiveModeDelivery` - Queue message into MessagePickupRepository and deliver it (along any other queued message).
   * - `MessageForwardingStrategy.DirectDelivery` - Deliver message directly. Do not add into queue (it might be manually added after, e.g. in case of failure)
   *
   * @default MessageForwardingStrategy.DirectDelivery
   * @todo Update default to QueueAndLiveModeDelivery
   */
  messageForwardingStrategy?: MessageForwardingStrategy
}

export class MediatorModuleConfig {
  private options: MediatorModuleConfigOptions

  public constructor(options?: MediatorModuleConfigOptions) {
    this.options = options ?? {}
  }

  /** See {@link MediatorModuleConfigOptions.autoAcceptMediationRequests} */
  public get autoAcceptMediationRequests() {
    return this.options.autoAcceptMediationRequests ?? false
  }

  /** See {@link MediatorModuleConfigOptions.messageForwardingStrategy} */
  public get messageForwardingStrategy() {
    return this.options.messageForwardingStrategy ?? MessageForwardingStrategy.DirectDelivery
  }
}
