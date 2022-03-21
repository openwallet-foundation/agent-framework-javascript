import type { DidDoc } from '../modules/connections/models'
import type { ConnectionRecord } from '../modules/connections/repository'
import type { IndyAgentService, DidCommService } from '../modules/dids/domain/service'
import type { OutOfBandRecord } from '../modules/oob/repository'
import type { EncryptedMessage } from '../types'
import type { AgentMessage } from './AgentMessage'
import type { EnvelopeKeys } from './EnvelopeService'

import { Lifecycle, scoped } from 'tsyringe'

import { DID_COMM_TRANSPORT_QUEUE } from '../constants'
import { ConnectionRole, DidExchangeRole } from '../modules/connections/models'

@scoped(Lifecycle.ContainerScoped)
export class TransportService {
  public transportSessionTable: TransportSessionTable = {}

  public saveSession(session: TransportSession) {
    this.transportSessionTable[session.id] = session
  }

  public findSessionByConnectionId(connectionId: string) {
    return Object.values(this.transportSessionTable).find((session) => session.connection?.id === connectionId)
  }

  public findSessionByOutOfBandId(outOfBandId: string) {
    return Object.values(this.transportSessionTable).find((session) => session.outOfBand?.id === outOfBandId)
  }

  public hasInboundEndpoint(didDoc: DidDoc): boolean {
    return Boolean(didDoc.didCommServices.find((s) => s.serviceEndpoint !== DID_COMM_TRANSPORT_QUEUE))
  }

  public findSessionById(sessionId: string) {
    return this.transportSessionTable[sessionId]
  }

  public removeSession(session: TransportSession) {
    delete this.transportSessionTable[session.id]
  }

  public findDidCommServices(
    connection: ConnectionRecord,
    outOfBand?: OutOfBandRecord
  ): Array<DidCommService | IndyAgentService> {
    if (connection.theirDidDoc) {
      return connection.theirDidDoc.didCommServices
    }

    if ((connection.role === ConnectionRole.Invitee || connection.role === DidExchangeRole.Requester) && outOfBand) {
      // TODO: Resolve dids here or allow to return it as part of returned array
      return outOfBand.outOfBandMessage.services.filter((s): s is DidCommService => typeof s !== 'string')
    }

    return []
  }
}

interface TransportSessionTable {
  [sessionId: string]: TransportSession
}

export interface TransportSession {
  id: string
  type: string
  keys?: EnvelopeKeys
  inboundMessage?: AgentMessage
  connection?: ConnectionRecord
  outOfBand?: OutOfBandRecord
  send(encryptedMessage: EncryptedMessage): Promise<void>
}
