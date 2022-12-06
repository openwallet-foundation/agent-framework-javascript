import type { AgentContext } from '../../../../agent/context'
import type { DecryptedMessageContext, EncryptedMessage, SignedMessage } from '../../../types'
import type { DidCommV1Message } from '../DidCommV1Message'
import type { PackMessageParams } from '../index'

import { InjectionSymbols } from '../../../../constants'
import { Key, KeyType } from '../../../../crypto'
import { AriesFrameworkError } from '../../../../error/AriesFrameworkError'
import { Logger } from '../../../../logger'
import { ForwardMessage } from '../../../../modules/routing/protocol/routing/v1'
import { inject, injectable } from '../../../../plugins'
import { DidCommMessageVersion, EnvelopeType } from '../../../types'
import { DidCommV1EnvelopeService } from '../index'

@injectable()
export class DidCommV1EnvelopeServiceImpl implements DidCommV1EnvelopeService {
  private logger: Logger

  public constructor(@inject(InjectionSymbols.Logger) logger: Logger) {
    this.logger = logger
  }

  public async packMessage(
    agentContext: AgentContext,
    payload: DidCommV1Message,
    params: PackMessageParams
  ): Promise<EncryptedMessage> {
    if (params.envelopeType === EnvelopeType.Signed) {
      throw new AriesFrameworkError('JWS messages are not supported by DIDComm V1 Indy service')
    }

    const { recipientKeys, routingKeys, senderKey } = params
    let recipientKeysBase58 = recipientKeys.map((key) => key.publicKeyBase58)
    const routingKeysBase58 = routingKeys.map((key) => key.publicKeyBase58)
    const senderKeyBase58 = senderKey && senderKey.publicKeyBase58

    // pass whether we want to use legacy did sov prefix
    const message = payload.toJSON({ useLegacyDidSovPrefix: agentContext.config.useLegacyDidSovPrefix })

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

      const forwardJson = forwardMessage.toJSON({ useLegacyDidSovPrefix: agentContext.config.useLegacyDidSovPrefix })

      // Forward messages are anon packed
      encryptedMessage = await agentContext.wallet.pack(forwardJson, [routingKeyBase58], undefined)
    }

    return encryptedMessage
  }

  public async unpackMessage(
    agentContext: AgentContext,
    encryptedMessage: EncryptedMessage | SignedMessage
  ): Promise<DecryptedMessageContext> {
    const decryptedMessage = await agentContext.wallet.unpack(encryptedMessage as EncryptedMessage)
    const { recipientKey, senderKey, plaintextMessage } = decryptedMessage
    return {
      recipientKey: recipientKey ? Key.fromPublicKeyBase58(recipientKey, KeyType.Ed25519) : undefined,
      senderKey: senderKey ? Key.fromPublicKeyBase58(senderKey, KeyType.Ed25519) : undefined,
      plaintextMessage,
      didCommVersion: DidCommMessageVersion.V1,
    }
  }
}

export { DidCommV1EnvelopeService }
