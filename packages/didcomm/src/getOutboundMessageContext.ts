import type { AgentMessage } from './AgentMessage'
import type { Routing } from './models'
import type { ConnectionRecord } from './modules/connections/repository'
import type { OutOfBandRecord } from './modules/oob'
import type { ResolvedDidCommService } from './types'
import { AgentContext, BaseRecordAny, CredoError, Key } from '@credo-ts/core'

import { utils } from '@credo-ts/core'

import { ServiceDecorator } from './decorators/service/ServiceDecorator'
import { OutboundMessageContext } from './models'
import { InvitationType, OutOfBandRepository, OutOfBandRole, OutOfBandService } from './modules/oob'
import { OutOfBandRecordMetadataKeys } from './modules/oob/repository/outOfBandRecordMetadataTypes'
import { RoutingService } from './modules/routing'
import { DidCommMessageRepository, DidCommMessageRole } from './repository'

/**
 * Maybe these methods should be moved to a service, but that would require
 * extra injection in the sender functions, and I'm not 100% sure what would
 * be the best place to host these.
 */

/**
 * Get the outbound message context for a message. Will use the connection record if available,
 * and otherwise try to create a connectionless message context.
 */
export async function getOutboundMessageContext(
  agentContext: AgentContext,
  {
    message,
    connectionRecord,
    associatedRecord,
    lastReceivedMessage,
    lastSentMessage,
  }: {
    connectionRecord?: ConnectionRecord
    associatedRecord?: BaseRecordAny
    message: AgentMessage
    lastReceivedMessage?: AgentMessage
    lastSentMessage?: AgentMessage
  }
) {
  // TODO: even if using a connection record, we should check if there's an oob record associated and this
  // is the first response to the oob invitation. If so, we should add the parentThreadId to the message
  if (connectionRecord) {
    agentContext.config.logger.debug(
      `Creating outbound message context for message ${message.id} with connection ${connectionRecord.id}`
    )
    return new OutboundMessageContext(message, {
      agentContext,
      associatedRecord,
      connection: connectionRecord,
    })
  }

  if (!lastReceivedMessage) {
    throw new CredoError(
      'No connection record and no lastReceivedMessage was supplied. For connection-less exchanges the lastReceivedMessage is required.'
    )
  }

  if (!associatedRecord) {
    throw new CredoError(
      'No associated record was supplied. This is required for connection-less exchanges to store the associated ~service decorator on the message.'
    )
  }

  // Connectionless
  return getConnectionlessOutboundMessageContext(agentContext, {
    message,
    associatedRecord,
    lastReceivedMessage,
    lastSentMessage,
  })
}

export async function getConnectionlessOutboundMessageContext(
  agentContext: AgentContext,
  {
    message,
    lastReceivedMessage,
    lastSentMessage,
    associatedRecord,
  }: {
    message: AgentMessage
    associatedRecord: BaseRecordAny
    lastReceivedMessage: AgentMessage
    lastSentMessage?: AgentMessage
  }
) {
  agentContext.config.logger.debug(
    `Creating outbound message context for message ${message.id} using connection-less exchange`
  )

  const outOfBandRecord = await getOutOfBandRecordForMessage(agentContext, message)
  // eslint-disable-next-line prefer-const
  let { recipientService, ourService } = await getServicesForMessage(agentContext, {
    lastReceivedMessage,
    lastSentMessage,
    message,
    outOfBandRecord,
  })

  // We need to set up routing for this exchange if we haven't sent any messages yet.
  if (!lastSentMessage) {
    ourService = await createOurService(agentContext, { outOfBandRecord, message })
  }

  // These errors should not happen as they will be caught by the checks above. But if there's a path missed,
  // and to make typescript happy we add these checks.
  if (!ourService) {
    throw new CredoError(`Could not determine our service for connection-less exchange for message ${message.id}.`)
  }
  if (!recipientService) {
    throw new CredoError(
      `Could not determine recipient service for connection-less exchange for message ${message.id}.`
    )
  }

  // Adds the ~service and ~thread.pthid (if oob is used) to the message and updates it in storage.
  await addExchangeDataToMessage(agentContext, { message, ourService, outOfBandRecord, associatedRecord })

  return new OutboundMessageContext(message, {
    agentContext: agentContext,
    associatedRecord,
    serviceParams: {
      service: recipientService,
      senderKey: ourService.recipientKeys[0],
      returnRoute: true,
    },
  })
}

/**
 * Retrieves the out of band record associated with the message based on the thread id of the message.
 */
async function getOutOfBandRecordForMessage(agentContext: AgentContext, message: AgentMessage) {
  agentContext.config.logger.debug(
    `Looking for out-of-band record for message ${message.id} with thread id ${message.threadId}`
  )
  const outOfBandRepository = agentContext.dependencyManager.resolve(OutOfBandRepository)

  const outOfBandRecord = await outOfBandRepository.findSingleByQuery(agentContext, {
    invitationRequestsThreadIds: [message.threadId],
  })

  return outOfBandRecord ?? undefined
}

/**
 * Returns the services to use for the message. When available it will extract the services from the
 * lastSentMessage and lastReceivedMessage. If not available it will try to extract the services from
 * the out of band record.
 *
 * If the required services and fields are not available, an error will be thrown.
 */
async function getServicesForMessage(
  agentContext: AgentContext,
  {
    lastSentMessage,
    lastReceivedMessage,
    message,
    outOfBandRecord,
  }: {
    lastSentMessage?: AgentMessage
    lastReceivedMessage: AgentMessage
    message: AgentMessage
    outOfBandRecord?: OutOfBandRecord
  }
) {
  let ourService = lastSentMessage?.service?.resolvedDidCommService
  let recipientService = lastReceivedMessage.service?.resolvedDidCommService

  const outOfBandService = agentContext.dependencyManager.resolve(OutOfBandService)

  // Check if valid
  if (outOfBandRecord?.role === OutOfBandRole.Sender) {
    // Extract ourService from the oob record if not on a previous message
    if (!ourService) {
      ourService = await outOfBandService.getResolvedServiceForOutOfBandServices(
        agentContext,
        outOfBandRecord.outOfBandInvitation.getServices()
      )
    }

    if (!recipientService) {
      throw new CredoError(
        `Could not find a service to send the message to. Please make sure the connection has a service or provide a service to send the message to.`
      )
    }

    // We have created the oob record with a message, that message should be provided here as well
    if (!lastSentMessage) {
      throw new CredoError('Must have lastSentMessage when out of band record has role Sender')
    }
  } else if (outOfBandRecord?.role === OutOfBandRole.Receiver) {
    // Extract recipientService from the oob record if not on a previous message
    if (!recipientService) {
      recipientService = await outOfBandService.getResolvedServiceForOutOfBandServices(
        agentContext,
        outOfBandRecord.outOfBandInvitation.getServices()
      )
    }

    if (lastSentMessage && !ourService) {
      throw new CredoError(
        `Could not find a service to send the message to. Please make sure the connection has a service or provide a service to send the message to.`
      )
    }
  }
  // we either miss ourService (even though a message was sent) or we miss recipientService
  // we check in separate if statements to provide a more specific error message
  else {
    if (lastSentMessage && !ourService) {
      agentContext.config.logger.error(
        `No out of band record associated and missing our service for connection-less exchange for message ${message.id}, while previous message has already been sent.`
      )
      throw new CredoError(
        `No out of band record associated and missing our service for connection-less exchange for message ${message.id}, while previous message has already been sent.`
      )
    }

    if (!recipientService) {
      agentContext.config.logger.error(
        `No out of band record associated and missing recipient service for connection-less exchange for message ${message.id}.`
      )
      throw new CredoError(
        `No out of band record associated and missing recipient service for connection-less exchange for message ${message.id}.`
      )
    }
  }

  return { ourService, recipientService }
}

/**
 * Creates a new service for us as the sender to be used in a connection-less exchange.
 *
 * Will creating routing, which takes into account mediators, and will optionally extract
 * routing configuration from the out of band record if available.
 */
async function createOurService(
  agentContext: AgentContext,
  { outOfBandRecord, message }: { outOfBandRecord?: OutOfBandRecord; message: AgentMessage }
): Promise<ResolvedDidCommService> {
  agentContext.config.logger.debug(
    `No previous sent message in thread for outbound message ${message.id}, setting up routing`
  )

  let routing: Routing | undefined = undefined

  // Extract routing from out of band record if possible
  const oobRecordRecipientRouting = outOfBandRecord?.metadata.get(OutOfBandRecordMetadataKeys.RecipientRouting)
  if (oobRecordRecipientRouting) {
    routing = {
      recipientKey: Key.fromFingerprint(oobRecordRecipientRouting.recipientKeyFingerprint),
      routingKeys: oobRecordRecipientRouting.routingKeyFingerprints.map((fingerprint) =>
        Key.fromFingerprint(fingerprint)
      ),
      endpoints: oobRecordRecipientRouting.endpoints,
      mediatorId: oobRecordRecipientRouting.mediatorId,
    }
  }

  if (!routing) {
    const routingService = agentContext.dependencyManager.resolve(RoutingService)
    routing = await routingService.getRouting(agentContext, {
      mediatorId: outOfBandRecord?.mediatorId,
    })
  }

  return {
    id: utils.uuid(),
    serviceEndpoint: routing.endpoints[0],
    recipientKeys: [routing.recipientKey],
    routingKeys: routing.routingKeys,
  }
}

async function addExchangeDataToMessage(
  agentContext: AgentContext,
  {
    message,
    ourService,
    outOfBandRecord,
    associatedRecord,
  }: {
    message: AgentMessage
    ourService: ResolvedDidCommService
    outOfBandRecord?: OutOfBandRecord
    associatedRecord: BaseRecordAny
  }
) {
  const legacyInvitationMetadata = outOfBandRecord?.metadata.get(OutOfBandRecordMetadataKeys.LegacyInvitation)

  // Set the parentThreadId on the message from the oob invitation
  // If connectionless is used, we should not add the parentThreadId
  if (outOfBandRecord && legacyInvitationMetadata?.legacyInvitationType !== InvitationType.Connectionless) {
    if (!message.thread) {
      message.setThread({
        parentThreadId: outOfBandRecord.outOfBandInvitation.id,
      })
    } else {
      message.thread.parentThreadId = outOfBandRecord.outOfBandInvitation.id
    }
  }

  // Set the service on the message and save service decorator to record (to remember our verkey)
  // TODO: we should store this in the OOB record, but that would be a breaking change for now.
  // We can change this in 0.5.0
  message.service = ServiceDecorator.fromResolvedDidCommService(ourService)

  await agentContext.dependencyManager.resolve(DidCommMessageRepository).saveOrUpdateAgentMessage(agentContext, {
    agentMessage: message,
    role: DidCommMessageRole.Sender,
    associatedRecordId: associatedRecord.id,
  })
}
