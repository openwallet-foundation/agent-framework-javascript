import type { AgentMessage } from './AgentMessage'
import type { EncryptedMessage, PlaintextMessage } from './types'
import type { AgentContext } from '@credo-ts/core'

import { InjectionSymbols, Key, KeyType, Logger, inject, injectable } from '@credo-ts/core'

import { DidCommModuleConfig } from './DidCommModuleConfig'
import { ForwardMessage } from './modules/routing/messages'

export interface EnvelopeKeys {
  recipientKeys: Key[]
  routingKeys: Key[]
  senderKey: Key | null
}

@injectable()
export class EnvelopeService {
  private logger: Logger

  public constructor(@inject(InjectionSymbols.Logger) logger: Logger) {
    this.logger = logger
  }

  public async packMessage(
    agentContext: AgentContext,
    payload: AgentMessage,
    keys: EnvelopeKeys
  ): Promise<EncryptedMessage> {
    const didcommConfig = agentContext.dependencyManager.resolve(DidCommModuleConfig)

    const { recipientKeys, routingKeys, senderKey } = keys
    let recipientKeysBase58 = recipientKeys.map((key) => key.publicKeyBase58)
    const routingKeysBase58 = routingKeys.map((key) => key.publicKeyBase58)
    const senderKeyBase58 = senderKey && senderKey.publicKeyBase58

    // pass whether we want to use legacy did sov prefix
    const message = payload.toJSON({ useDidSovPrefixWhereAllowed: didcommConfig.useDidSovPrefixWhereAllowed })

    this.logger.debug(`Pack outbound message ${message['@type']}`)

    let encryptedMessage = await agentContext.wallet.pack(message, recipientKeysBase58, senderKeyBase58 ?? undefined)

    // If the message has routing keys (mediator) pack for each mediator
    for (const routingKeyBase58 of routingKeysBase58) {
      const forwardMessage = new ForwardMessage({
        // Forward to first recipient key
        to: recipientKeysBase58[0],
        message: encryptedMessage,
      })
      recipientKeysBase58 = [routingKeyBase58]
      this.logger.debug('Forward message created', forwardMessage)

      const forwardJson = forwardMessage.toJSON({
        useDidSovPrefixWhereAllowed: didcommConfig.useDidSovPrefixWhereAllowed,
      })

      // Forward messages are anon packed
      encryptedMessage = await agentContext.wallet.pack(forwardJson, [routingKeyBase58], undefined)
    }

    return encryptedMessage
  }

  public async unpackMessage(
    agentContext: AgentContext,
    encryptedMessage: EncryptedMessage
  ): Promise<DecryptedMessageContext> {
    const decryptedMessage = await agentContext.wallet.unpack(encryptedMessage)
    const { recipientKey, senderKey, plaintextMessage } = decryptedMessage
    return {
      recipientKey: recipientKey ? Key.fromPublicKeyBase58(recipientKey, KeyType.Ed25519) : undefined,
      senderKey: senderKey ? Key.fromPublicKeyBase58(senderKey, KeyType.Ed25519) : undefined,
      plaintextMessage,
    }
  }
}

export interface DecryptedMessageContext {
  plaintextMessage: PlaintextMessage
  senderKey?: Key
  recipientKey?: Key
}
