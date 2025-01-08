import type { MediationRecord } from './repository'

import { AgentContext, injectable } from '@credo-ts/core'
import { MessageHandlerRegistry } from '../../MessageHandlerRegistry'
import { MessageSender } from '../../MessageSender'
import { OutboundMessageContext } from '../../models'
import { ConnectionService } from '../connections'

import { MediatorModuleConfig } from './MediatorModuleConfig'
import { ForwardHandler, KeylistUpdateHandler } from './handlers'
import { MediationRequestHandler } from './handlers/MediationRequestHandler'
import { MediatorService } from './services/MediatorService'

@injectable()
export class MediatorApi {
  public config: MediatorModuleConfig

  private mediatorService: MediatorService
  private messageSender: MessageSender
  private agentContext: AgentContext
  private connectionService: ConnectionService

  public constructor(
    messageHandlerRegistry: MessageHandlerRegistry,
    mediationService: MediatorService,
    messageSender: MessageSender,
    agentContext: AgentContext,
    connectionService: ConnectionService,
    config: MediatorModuleConfig
  ) {
    this.mediatorService = mediationService
    this.messageSender = messageSender
    this.connectionService = connectionService
    this.agentContext = agentContext
    this.config = config
    this.registerMessageHandlers(messageHandlerRegistry)
  }

  public async grantRequestedMediation(mediationRecordId: string): Promise<MediationRecord> {
    const record = await this.mediatorService.getById(this.agentContext, mediationRecordId)
    const connectionRecord = await this.connectionService.getById(this.agentContext, record.connectionId)

    const { message, mediationRecord } = await this.mediatorService.createGrantMediationMessage(
      this.agentContext,
      record
    )
    const outboundMessageContext = new OutboundMessageContext(message, {
      agentContext: this.agentContext,
      connection: connectionRecord,
      associatedRecord: mediationRecord,
    })

    await this.messageSender.sendMessage(outboundMessageContext)

    return mediationRecord
  }

  private registerMessageHandlers(messageHandlerRegistry: MessageHandlerRegistry) {
    messageHandlerRegistry.registerMessageHandler(new KeylistUpdateHandler(this.mediatorService))
    messageHandlerRegistry.registerMessageHandler(new ForwardHandler(this.mediatorService))
    messageHandlerRegistry.registerMessageHandler(new MediationRequestHandler(this.mediatorService, this.config))
  }
}
