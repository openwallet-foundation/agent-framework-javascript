import type { PlaintextMessage } from '../../../types'

import { CredoError, JsonEncoder, JsonTransformer, IsStringOrInstance } from '@credo-ts/core'
import { Exclude, Expose, Transform, TransformationType, Type } from 'class-transformer'
import { ArrayNotEmpty, IsArray, IsInstance, IsOptional, IsUrl, ValidateNested } from 'class-validator'
import { parseUrl } from 'query-string'

import { AgentMessage } from '../../../AgentMessage'
import { Attachment, AttachmentData } from '../../../decorators/attachment/Attachment'
import { replaceLegacyDidSovPrefix, IsValidMessageType, parseMessageType } from '../../../util/messageType'
import { OutOfBandDidCommService } from '../domain/OutOfBandDidCommService'
import { outOfBandServiceToNumAlgo2Did } from '../helpers'

export interface OutOfBandInvitationOptions {
  id?: string
  label?: string
  goalCode?: string
  goal?: string
  accept?: string[]
  handshakeProtocols?: string[]
  services: Array<OutOfBandDidCommService | string>
  imageUrl?: string
  appendedAttachments?: Attachment[]
}

export class OutOfBandInvitation extends AgentMessage {
  public constructor(options: OutOfBandInvitationOptions) {
    super()

    if (options) {
      this.id = options.id ?? this.generateId()
      this.label = options.label
      this.goalCode = options.goalCode
      this.goal = options.goal
      this.accept = options.accept
      this.handshakeProtocols = options.handshakeProtocols
      this.services = options.services
      this.imageUrl = options.imageUrl
      this.appendedAttachments = options.appendedAttachments
    }
  }

  /**
   * The original type of the invitation. This is not part of the RFC, but allows to identify
   * from what the oob invitation was originally created (e.g. legacy connectionless invitation).
   */
  @Exclude()
  public invitationType?: InvitationType

  public addRequest(message: AgentMessage) {
    if (!this.requests) this.requests = []
    const requestAttachment = new Attachment({
      id: this.generateId(),
      mimeType: 'application/json',
      data: new AttachmentData({
        base64: JsonEncoder.toBase64(message.toJSON()),
      }),
    })
    this.requests.push(requestAttachment)
  }

  public getRequests(): PlaintextMessage[] | undefined {
    return this.requests?.map((request) => request.getDataAsJson())
  }

  public toUrl({ domain }: { domain: string }) {
    const invitationJson = this.toJSON()
    const encodedInvitation = JsonEncoder.toBase64URL(invitationJson)
    const invitationUrl = `${domain}?oob=${encodedInvitation}`
    return invitationUrl
  }

  public static fromUrl(invitationUrl: string) {
    const parsedUrl = parseUrl(invitationUrl).query
    const encodedInvitation = parsedUrl['oob']
    if (typeof encodedInvitation === 'string') {
      const invitationJson = JsonEncoder.fromBase64(encodedInvitation)
      const invitation = this.fromJson(invitationJson)

      return invitation
    } else {
      throw new CredoError(
        'InvitationUrl is invalid. It needs to contain one, and only one, of the following parameters; `oob`'
      )
    }
  }

  public static fromJson(json: Record<string, unknown>) {
    return JsonTransformer.fromJSON(json, OutOfBandInvitation)
  }

  public get invitationDids() {
    const dids = this.getServices().map((didOrService) => {
      if (typeof didOrService === 'string') {
        return didOrService
      }
      return outOfBandServiceToNumAlgo2Did(didOrService)
    })
    return dids
  }

  // shorthand for services without the need to deal with the String DIDs
  public getServices(): Array<OutOfBandDidCommService | string> {
    return this.services.map((service) => {
      if (service instanceof String) return service.toString()
      return service
    })
  }
  public getDidServices(): Array<string> {
    return this.getServices().filter((service): service is string => typeof service === 'string')
  }
  public getInlineServices(): Array<OutOfBandDidCommService> {
    return this.getServices().filter((service): service is OutOfBandDidCommService => typeof service !== 'string')
  }

  @Transform(({ value }) => replaceLegacyDidSovPrefix(value), {
    toClassOnly: true,
  })
  @IsValidMessageType(OutOfBandInvitation.type)
  public readonly type = OutOfBandInvitation.type.messageTypeUri
  public static readonly type = parseMessageType('https://didcomm.org/out-of-band/1.1/invitation')

  public readonly label?: string

  @Expose({ name: 'goal_code' })
  public readonly goalCode?: string

  public readonly goal?: string

  public readonly accept?: string[]
  @Transform(({ value }) => value?.map(replaceLegacyDidSovPrefix), { toClassOnly: true })
  @Expose({ name: 'handshake_protocols' })
  public handshakeProtocols?: string[]

  @Expose({ name: 'requests~attach' })
  @Type(() => Attachment)
  @IsArray()
  @ValidateNested({
    each: true,
  })
  @IsInstance(Attachment, { each: true })
  @IsOptional()
  private requests?: Attachment[]

  @IsArray()
  @ArrayNotEmpty()
  @OutOfBandServiceTransformer()
  @IsStringOrInstance(OutOfBandDidCommService, { each: true })
  // eslint-disable-next-line @typescript-eslint/ban-types
  private services!: Array<OutOfBandDidCommService | string | String>

  /**
   * Custom property. It is not part of the RFC.
   */
  @IsOptional()
  @IsUrl()
  public readonly imageUrl?: string
}

/**
 * Decorator that transforms services json to corresponding class instances
 * @note Because of ValidateNested limitation, this produces instances of String for DID services except plain js string
 */
function OutOfBandServiceTransformer() {
  return Transform(({ value, type }: { value: Array<string | { type: string }>; type: TransformationType }) => {
    if (type === TransformationType.PLAIN_TO_CLASS) {
      return value.map((service) => {
        // did
        if (typeof service === 'string') return new String(service)

        // inline didcomm service
        return JsonTransformer.fromJSON(service, OutOfBandDidCommService)
      })
    } else if (type === TransformationType.CLASS_TO_PLAIN) {
      return value.map((service) =>
        typeof service === 'string' || service instanceof String ? service.toString() : JsonTransformer.toJSON(service)
      )
    }

    // PLAIN_TO_PLAIN
    return value
  })
}

/**
 * The original invitation an out of band invitation was derived from.
 */
export enum InvitationType {
  OutOfBand = 'out-of-band/1.x',
  Connection = 'connections/1.x',
  Connectionless = 'connectionless',
}
