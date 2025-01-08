import type { Attachment } from '../../../decorators/attachment/Attachment'

import { Transform } from 'class-transformer'
import { ArrayNotEmpty, IsArray, IsOptional, IsString, IsUrl, ValidateIf } from 'class-validator'
import { parseUrl } from 'query-string'

import { CredoError, JsonEncoder, JsonTransformer } from '@credo-ts/core'
import { AgentMessage } from '../../../AgentMessage'
import { IsValidMessageType, parseMessageType, replaceLegacyDidSovPrefix } from '../../../util/messageType'

export interface BaseInvitationOptions {
  id?: string
  label: string
  imageUrl?: string
  appendedAttachments?: Attachment[]
}

export interface InlineInvitationOptions {
  recipientKeys: string[]
  serviceEndpoint: string
  routingKeys?: string[]
}

export interface DIDInvitationOptions {
  did: string
}

/**
 * Message to invite another agent to create a connection
 *
 * @see https://github.com/hyperledger/aries-rfcs/blob/master/features/0160-connection-protocol/README.md#0-invitation-to-connect
 */
export class ConnectionInvitationMessage extends AgentMessage {
  public readonly allowDidSovPrefix = true

  /**
   * Create new ConnectionInvitationMessage instance.
   * @param options
   */
  public constructor(options: BaseInvitationOptions & (DIDInvitationOptions | InlineInvitationOptions)) {
    super()

    if (options) {
      this.id = options.id || this.generateId()
      this.label = options.label
      this.imageUrl = options.imageUrl
      this.appendedAttachments = options.appendedAttachments

      if (isDidInvitation(options)) {
        this.did = options.did
      } else {
        this.recipientKeys = options.recipientKeys
        this.serviceEndpoint = options.serviceEndpoint
        this.routingKeys = options.routingKeys
      }

      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-ignore
      if (options.did && (options.recipientKeys || options.routingKeys || options.serviceEndpoint)) {
        throw new CredoError(
          'either the did or the recipientKeys/serviceEndpoint/routingKeys must be set, but not both'
        )
      }
    }
  }

  @IsValidMessageType(ConnectionInvitationMessage.type)
  @Transform(({ value }) => replaceLegacyDidSovPrefix(value), {
    toClassOnly: true,
  })
  public readonly type = ConnectionInvitationMessage.type.messageTypeUri
  public static readonly type = parseMessageType('https://didcomm.org/connections/1.0/invitation')

  @IsString()
  public label!: string

  @IsString()
  @ValidateIf((o: ConnectionInvitationMessage) => o.recipientKeys === undefined)
  public did?: string

  @IsString({
    each: true,
  })
  @IsArray()
  @ValidateIf((o: ConnectionInvitationMessage) => o.did === undefined)
  @ArrayNotEmpty()
  public recipientKeys?: string[]

  @IsString()
  @ValidateIf((o: ConnectionInvitationMessage) => o.did === undefined)
  public serviceEndpoint?: string

  @IsString({
    each: true,
  })
  @ValidateIf((o: ConnectionInvitationMessage) => o.did === undefined)
  @IsOptional()
  public routingKeys?: string[]

  @IsOptional()
  @IsUrl()
  public imageUrl?: string

  /**
   * Create an invitation url from this instance
   *
   * @param domain domain name to use for invitation url
   * @returns invitation url with base64 encoded invitation
   */
  public toUrl({
    domain,
    useDidSovPrefixWhereAllowed = false,
  }: {
    domain: string
    useDidSovPrefixWhereAllowed?: boolean
  }) {
    const invitationJson = this.toJSON({ useDidSovPrefixWhereAllowed })

    const encodedInvitation = JsonEncoder.toBase64URL(invitationJson)
    const invitationUrl = `${domain}?c_i=${encodedInvitation}`

    return invitationUrl
  }

  /**
   * Create a `ConnectionInvitationMessage` instance from the `c_i` or `d_m` parameter of an URL
   *
   * @param invitationUrl invitation url containing c_i or d_m parameter
   *
   * @throws Error when the url can not be decoded to JSON, or decoded message is not a valid 'ConnectionInvitationMessage'
   */
  public static fromUrl(invitationUrl: string) {
    const parsedUrl = parseUrl(invitationUrl).query
    const encodedInvitation = parsedUrl['c_i'] ?? parsedUrl['d_m']
    if (typeof encodedInvitation === 'string') {
      const invitationJson = JsonEncoder.fromBase64(encodedInvitation)
      const invitation = JsonTransformer.fromJSON(invitationJson, ConnectionInvitationMessage)

      return invitation
    } else {
      throw new CredoError('InvitationUrl is invalid. Needs to be encoded with either c_i, d_m, or oob')
    }
  }
}

/**
 * Check whether an invitation is a `DIDInvitationData` object
 *
 * @param invitation invitation object
 */
function isDidInvitation(
  invitation: InlineInvitationOptions | DIDInvitationOptions
): invitation is DIDInvitationOptions {
  return (invitation as DIDInvitationOptions).did !== undefined
}
