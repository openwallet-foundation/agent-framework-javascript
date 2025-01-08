import type { AgentDependencies } from '@credo-ts/core'

import { CredoError, JsonEncoder, JsonTransformer, MessageValidator } from '@credo-ts/core'
import { parseUrl } from 'query-string'

import { AgentMessage } from '../AgentMessage'
import { ConnectionInvitationMessage } from '../modules/connections/messages'
import { convertToNewInvitation } from '../modules/oob/converters'
import { OutOfBandDidCommService } from '../modules/oob/domain/OutOfBandDidCommService'
import { InvitationType, OutOfBandInvitation } from '../modules/oob/messages'

import { parseMessageType, supportsIncomingMessageType } from './messageType'

const fetchShortUrl = async (invitationUrl: string, dependencies: AgentDependencies) => {
  const abortController = new AbortController()
  const id = setTimeout(() => abortController.abort(), 15000)
  let response
  try {
    response = await dependencies.fetch(invitationUrl, {
      method: 'GET',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
      },
    })
  } catch (error) {
    throw new CredoError(`Get request failed on provided url: ${error.message}`, { cause: error })
  }
  clearTimeout(id)
  return response
}

/**
 * Parses a JSON containing an invitation message and returns an OutOfBandInvitation instance
 *
 * @param invitationJson JSON object containing message
 * @returns OutOfBandInvitation
 */
export const parseInvitationJson = (invitationJson: Record<string, unknown>): OutOfBandInvitation => {
  const messageType = invitationJson['@type'] as string

  if (!messageType) {
    throw new CredoError('Invitation is not a valid DIDComm message')
  }

  const parsedMessageType = parseMessageType(messageType)
  if (supportsIncomingMessageType(parsedMessageType, OutOfBandInvitation.type)) {
    const invitation = JsonTransformer.fromJSON(invitationJson, OutOfBandInvitation)
    MessageValidator.validateSync(invitation)
    invitation.invitationType = InvitationType.OutOfBand
    return invitation
  } else if (supportsIncomingMessageType(parsedMessageType, ConnectionInvitationMessage.type)) {
    const invitation = JsonTransformer.fromJSON(invitationJson, ConnectionInvitationMessage)
    MessageValidator.validateSync(invitation)
    const outOfBandInvitation = convertToNewInvitation(invitation)
    outOfBandInvitation.invitationType = InvitationType.Connection
    return outOfBandInvitation
  } else if (invitationJson['~service']) {
    // This is probably a legacy connectionless invitation
    return transformLegacyConnectionlessInvitationToOutOfBandInvitation(invitationJson)
  } else {
    throw new CredoError(`Invitation with '@type' ${parsedMessageType.messageTypeUri} not supported.`)
  }
}

/**
 * Parses URL containing encoded invitation and returns invitation message.
 *
 * @param invitationUrl URL containing encoded invitation
 *
 * @returns OutOfBandInvitation
 */
export const parseInvitationUrl = (invitationUrl: string): OutOfBandInvitation => {
  const parsedUrl = parseUrl(invitationUrl).query

  const encodedInvitation = parsedUrl['oob'] ?? parsedUrl['c_i'] ?? parsedUrl['d_m']

  if (typeof encodedInvitation === 'string') {
    const invitationJson = JsonEncoder.fromBase64(encodedInvitation) as Record<string, unknown>
    return parseInvitationJson(invitationJson)
  }
  throw new CredoError(
    'InvitationUrl is invalid. It needs to contain one, and only one, of the following parameters: `oob`, `c_i` or `d_m`.'
  )
}

// This currently does not follow the RFC because of issues with fetch, currently uses a janky work around
export const oobInvitationFromShortUrl = async (response: Response): Promise<OutOfBandInvitation> => {
  if (response) {
    if (response.headers.get('Content-Type')?.startsWith('application/json') && response.ok) {
      const invitationJson = (await response.json()) as Record<string, unknown>
      return parseInvitationJson(invitationJson)
    } else if (response['url']) {
      // The following if else is for here for trinsic shorten urls
      // Because the redirect targets a deep link the automatic redirect does not occur
      let responseUrl
      const location = response.headers.get('Location')
      if ((response.status === 302 || response.status === 301) && location) responseUrl = location
      else responseUrl = response['url']

      return parseInvitationUrl(responseUrl)
    }
  }
  throw new CredoError('HTTP request time out or did not receive valid response')
}

export function transformLegacyConnectionlessInvitationToOutOfBandInvitation(messageJson: Record<string, unknown>) {
  const agentMessage = JsonTransformer.fromJSON(messageJson, AgentMessage)

  // ~service is required for legacy connectionless invitations
  if (!agentMessage.service) {
    throw new CredoError('Invalid legacy connectionless invitation url. Missing ~service decorator.')
  }

  // This destructuring removes the ~service property from the message, and
  // we can can use messageWithoutService to create the out of band invitation
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { '~service': service, ...messageWithoutService } = messageJson

  // transform into out of band invitation
  const invitation = new OutOfBandInvitation({
    services: [OutOfBandDidCommService.fromResolvedDidCommService(agentMessage.service.resolvedDidCommService)],
  })

  invitation.invitationType = InvitationType.Connectionless
  invitation.addRequest(JsonTransformer.fromJSON(messageWithoutService, AgentMessage))

  return invitation
}

/**
 * Parses URL containing encoded invitation and returns invitation message. Compatible with
 * parsing short Urls
 *
 * @param invitationUrl URL containing encoded invitation
 *
 * @param dependencies Agent dependencies containing fetch
 *
 * @returns OutOfBandInvitation
 */
export const parseInvitationShortUrl = async (
  invitationUrl: string,
  dependencies: AgentDependencies
): Promise<OutOfBandInvitation> => {
  const parsedUrl = parseUrl(invitationUrl).query
  if (parsedUrl['oob'] || parsedUrl['c_i']) {
    return parseInvitationUrl(invitationUrl)
  }
  // Legacy connectionless invitation
  else if (parsedUrl['d_m']) {
    const messageJson = JsonEncoder.fromBase64(parsedUrl['d_m'] as string)
    return transformLegacyConnectionlessInvitationToOutOfBandInvitation(messageJson)
  } else {
    try {
      const outOfBandInvitation = await oobInvitationFromShortUrl(await fetchShortUrl(invitationUrl, dependencies))
      outOfBandInvitation.invitationType = InvitationType.OutOfBand
      return outOfBandInvitation
    } catch (error) {
      throw new CredoError(
        'InvitationUrl is invalid. It needs to contain one, and only one, of the following parameters: `oob`, `c_i` or `d_m`, or be valid shortened URL'
      )
    }
  }
}
